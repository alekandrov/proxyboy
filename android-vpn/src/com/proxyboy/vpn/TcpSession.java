package com.proxyboy.vpn;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

// Una conexión TCP de una app del dispositivo. La terminamos acá (stack TCP mínimo sobre el túnel) y la reenviamos:
// - TLS o HTTP → a Proxyboy con CONNECT <host>:<puerto>, usando el SNI o el header Host como nombre
// - Cualquier otra cosa → directo al destino original
final class TcpSession {
    private static final int MSS = 1360;
    private static final int RCV_LIMIT = 1 << 20;
    private static final byte[] EOF = new byte[0];
    private static final SecureRandom RANDOM = new SecureRandom();
    private static final Pattern HOST = Pattern.compile("(?im)^host:[ \\t]*([^\\r\\n]+)");
    private static final String[] METHODS = {"GET ", "POST ", "PUT ", "HEAD ", "DELETE ", "PATCH ", "OPTIONS ", "TRACE ", "PRI * "};

    final String key;
    private final ProxyboyVpnService vpn;
    private final byte[] clientIp, remoteIp;
    private final int clientPort, remotePort;

    // Estado TCP (protegido por "this")
    private long rcvNxt;          // próximo byte que esperamos del cliente
    private long sndUna, sndNxt;  // nuestra secuencia: primer byte sin ACK y próximo a enviar
    private int clientWindow;
    private boolean established, clientFin, finSent, finAcked, closed;
    private byte[] unacked = new byte[16384];
    private int unackedLen;
    private long lastProgress;
    private int retries;
    private int lastWindow = 65535;

    // Datos del cliente: primero se juntan para detectar el protocolo, después van a la cola hacia el upstream
    private final ByteArrayOutputStream sniff = new ByteArrayOutputStream();
    private boolean sniffing = true, sniffEof;
    private long firstDataAt;
    private final LinkedBlockingQueue<byte[]> toUpstream = new LinkedBlockingQueue<>();
    private int queued;
    private volatile Socket upstream;
    private volatile boolean viaProxy;

    TcpSession(ProxyboyVpnService vpn, String key, Packet syn) {
        this.vpn = vpn;
        this.key = key;
        this.clientIp = syn.src;
        this.remoteIp = syn.dst;
        this.clientPort = syn.srcPort;
        this.remotePort = syn.dstPort;
        long isn = RANDOM.nextInt() & 0xffffffffL;
        rcvNxt = add(syn.seq, 1);
        sndUna = isn;
        sndNxt = add(isn, 1);
        clientWindow = syn.window;
        lastProgress = System.currentTimeMillis();
    }

    void start() {
        sendSynAck();
        Thread t = new Thread(this::work, "tcp " + remotePort);
        t.setDaemon(true);
        t.start();
    }

    // ---------- Paquetes que vienen del dispositivo ----------
    synchronized void onPacket(Packet p) {
        if (closed) return;
        if (p.has(Packet.RST)) { close(false); return; }
        if (p.has(Packet.SYN)) {
            if (!established) sendSynAck(); // retransmisión del SYN
            return;
        }
        if (p.has(Packet.ACK)) onAck(p.ack, p.window);

        int len = p.payloadLen;
        boolean fin = p.has(Packet.FIN);
        if (len == 0 && !fin) return;
        int off = p.payloadOffset;
        long seq = p.seq;
        long already = (rcvNxt - seq) & 0xffffffffL;
        if (already > 0 && already < 0x80000000L) {
            // Retransmisión (total o parcial) de algo que ya recibimos
            if (already >= len) { sendAck(); return; }
            off += already;
            len -= already;
            seq = rcvNxt;
        }
        if (seq != rcvNxt) { sendAck(); return; } // fuera de orden: el cliente va a retransmitir
        if (len > 0) {
            deliver(p.buf, off, len);
            rcvNxt = add(rcvNxt, len);
        }
        if (fin && !clientFin) {
            clientFin = true;
            rcvNxt = add(rcvNxt, 1);
            if (sniffing) sniffEof = true; else toUpstream.add(EOF);
        }
        sendAck();
        notifyAll();
        maybeFinish();
    }

    private void onAck(long ack, int window) {
        long acked = (ack - sndUna) & 0xffffffffL;
        long inflight = (sndNxt - sndUna) & 0xffffffffL;
        if (acked > 0 && acked <= inflight) {
            if (!established) established = true;
            int dataAcked = (int) Math.min(acked, unackedLen);
            if (dataAcked > 0) {
                System.arraycopy(unacked, dataAcked, unacked, 0, unackedLen - dataAcked);
                unackedLen -= dataAcked;
            }
            if (finSent && acked == inflight) finAcked = true;
            sndUna = ack;
            lastProgress = System.currentTimeMillis();
            retries = 0;
        }
        clientWindow = window;
        notifyAll();
        maybeFinish();
    }

    private void deliver(byte[] b, int off, int len) {
        if (sniffing) {
            if (sniff.size() == 0) firstDataAt = System.currentTimeMillis();
            sniff.write(b, off, len);
        } else {
            byte[] c = new byte[len];
            System.arraycopy(b, off, c, 0, len);
            queued += len;
            toUpstream.add(c);
        }
    }

    private int window() {
        int pending = queued + (sniffing ? sniff.size() : 0);
        return Math.max(0, Math.min(65535, RCV_LIMIT - pending));
    }

    // ---------- Envío hacia el dispositivo ----------
    private void send(int flags, long seq, byte[] data, int off, int len, int mss) {
        int w = window();
        lastWindow = w;
        vpn.write(Packet.tcp(remoteIp, clientIp, remotePort, clientPort, seq, rcvNxt, flags, w, data, off, len, mss));
    }

    private void sendSynAck() { send(Packet.SYN | Packet.ACK, sndUna, null, 0, 0, MSS); }

    private void sendAck() { send(Packet.ACK, sndNxt, null, 0, 0, 0); }

    // Datos del upstream: respetamos la ventana del cliente y guardamos lo no confirmado para retransmitir
    private synchronized boolean sendData(byte[] b, int n) throws InterruptedException {
        while (!closed && unackedLen + n > Math.max(clientWindow, 1)) wait(200);
        if (closed) return false;
        if (unackedLen == 0) lastProgress = System.currentTimeMillis();
        if (unackedLen + n > unacked.length) {
            byte[] bigger = new byte[Math.max(unacked.length * 2, unackedLen + n)];
            System.arraycopy(unacked, 0, bigger, 0, unackedLen);
            unacked = bigger;
        }
        System.arraycopy(b, 0, unacked, unackedLen, n);
        unackedLen += n;
        send(Packet.ACK | Packet.PSH, sndNxt, b, 0, n, 0);
        sndNxt = add(sndNxt, n);
        return true;
    }

    private synchronized void sendFin() {
        if (closed || finSent) return;
        if (unackedLen == 0) lastProgress = System.currentTimeMillis();
        send(Packet.FIN | Packet.ACK, sndNxt, null, 0, 0, 0);
        sndNxt = add(sndNxt, 1);
        finSent = true;
    }

    // Llamado periódicamente: retransmite lo que el cliente no confirmó
    synchronized void tick(long now) {
        if (closed) return;
        boolean pendingSyn = !established;
        boolean pending = pendingSyn || unackedLen > 0 || (finSent && !finAcked);
        if (!pending) return;
        long rto = Math.min(400L << Math.min(retries, 4), 5000);
        if (now - lastProgress < rto) return;
        if (++retries > 10) { close(true); return; }
        lastProgress = now;
        if (pendingSyn) { sendSynAck(); return; }
        int limit = Math.min(unackedLen, Math.max(clientWindow, MSS));
        long seq = sndUna;
        for (int off = 0; off < limit; off += MSS) {
            int n = Math.min(MSS, limit - off);
            send(Packet.ACK | Packet.PSH, seq, unacked, off, n, 0);
            seq = add(seq, n);
        }
        if (finSent && !finAcked && limit == unackedLen) send(Packet.FIN | Packet.ACK, add(sndUna, unackedLen), null, 0, 0, 0);
    }

    private void maybeFinish() {
        if (clientFin && finAcked) close(false);
    }

    synchronized void close(boolean reset) {
        if (closed) return;
        closed = true;
        if (reset) send(Packet.RST | Packet.ACK, sndNxt, null, 0, 0, 0);
        vpn.removeSession(this);
        toUpstream.add(EOF);
        Socket s = upstream;
        if (s != null) try { s.close(); } catch (IOException ignored) {}
        notifyAll();
    }

    // ---------- Hilo de la conexión ----------
    private void work() {
        if (remotePort == 853) { close(true); return; } // DNS sobre TLS: que Android pase a DNS común enseguida
        AppInfo app = vpn.ownerOf(clientIp, clientPort, remoteIp, remotePort);
        try {
            byte[] first = sniffFirstBytes();
            if (first == null) return;
            String target = null;
            boolean plainHttp = false;
            if (!vpn.isDirectOnly(remoteIp, remotePort)) {
                if (first.length > 0 && (first[0] & 0xff) == 0x16) {
                    target = hostOrIp(sniHost(first));
                } else if (looksHttp(first) && !isProxyRequest(first)) {
                    target = hostOrIp(httpHost(first));
                    plainHttp = true;
                }
            }
            Socket s;
            viaProxy = target != null;
            s = viaProxy ? connectViaProxy(target, plainHttp, app) : null;
            if (s == null) {
                // Otro protocolo, o Proxyboy no lo descifra: directo al destino original
                viaProxy = false;
                s = new Socket();
                s.setTcpNoDelay(true);
                s.connect(new InetSocketAddress(InetAddress.getByAddress(remoteIp), remotePort), 10000);
            }
            upstream = s;
            synchronized (this) {
                if (closed) { s.close(); return; }
                byte[] rest = sniff.toByteArray();
                sniffing = false;
                sniff.reset();
                if (rest.length > 0) s.getOutputStream().write(rest);
                if (sniffEof) toUpstream.add(EOF);
                if (lastWindow < 16384) sendAck(); // la ventana se volvió a abrir
            }
            final Socket sock = s;
            Thread reader = new Thread(() -> pumpDown(sock), "tcp-down " + remotePort);
            reader.setDaemon(true);
            reader.start();
            pumpUp(sock);
        } catch (Exception e) {
            android.util.Log.w("ProxyboyVpn", "conexión a :" + remotePort + " falló: " + e);
            close(true);
        }
    }

    // Espera los primeros bytes del cliente para saber si es TLS (SNI) o HTTP (Host). Si no manda nada, es otro protocolo.
    private synchronized byte[] sniffFirstBytes() throws InterruptedException {
        long start = System.currentTimeMillis();
        while (!closed && !established && System.currentTimeMillis() - start < 10000) wait(200);
        if (closed || !established) { close(true); return null; }
        long waitStart = System.currentTimeMillis();
        while (!closed) {
            long now = System.currentTimeMillis();
            int size = sniff.size();
            if (size == 0) {
                if (sniffEof || now - waitStart > 700) break;
            } else {
                byte[] d = sniff.toByteArray();
                if (now - firstDataAt > 1500 || sniffEof || size >= 16384) break;
                if ((d[0] & 0xff) == 0x16) {
                    if (size >= 5 && size >= 5 + Packet.u16(d, 3)) break;
                } else if (size >= 8 || !couldBeHttp(d)) {
                    if (!looksHttp(d) || indexOf(d, "\r\n\r\n") >= 0) break;
                }
            }
            wait(50);
        }
        return closed ? null : sniff.toByteArray();
    }

    // Devuelve null si Proxyboy pide que la conexión vaya directo
    private Socket connectViaProxy(String target, boolean plainHttp, AppInfo app) throws IOException {
        Socket s = new Socket();
        s.setTcpNoDelay(true);
        s.connect(new InetSocketAddress(vpn.proxyHost, vpn.proxyPort), 5000);
        String hostPort = (target.indexOf(':') >= 0 ? "[" + target + "]" : target) + ":" + remotePort;
        StringBuilder req = new StringBuilder();
        req.append("CONNECT ").append(hostPort).append(" HTTP/1.1\r\nHost: ").append(hostPort).append("\r\n");
        if (app != null) {
            req.append("X-Proxyboy-App: ").append(app.packageName).append("\r\n");
            req.append("X-Proxyboy-App-Name: ").append(enc(app.label)).append("\r\n");
        }
        if (vpn.deviceName != null) req.append("X-Proxyboy-Device: ").append(enc(vpn.deviceName)).append("\r\n");
        // HTTP sin TLS: que Proxyboy lo inspeccione siempre (si no, quedaría como túnel opaco)
        if (plainHttp) req.append("X-Proxyboy-Intercept: 1\r\n");
        // Si Proxyboy no lo va a descifrar, que nos diga y salimos directo (como sin VPN)
        req.append("X-Proxyboy-Direct-Ok: 1\r\n");
        req.append("\r\n");
        OutputStream out = s.getOutputStream();
        out.write(req.toString().getBytes(StandardCharsets.ISO_8859_1));
        out.flush();
        InputStream in = s.getInputStream();
        ByteArrayOutputStream head = new ByteArrayOutputStream();
        s.setSoTimeout(15000);
        while (head.size() < 8192) {
            int c = in.read();
            if (c < 0) break;
            head.write(c);
            if (head.size() >= 4 && indexOf(head.toByteArray(), "\r\n\r\n") >= 0) break;
        }
        s.setSoTimeout(0);
        String status = new String(head.toByteArray(), StandardCharsets.ISO_8859_1);
        if (status.matches("(?s)HTTP/1\\.[01] 204.*") && status.toLowerCase().contains("x-proxyboy-direct: 1")) {
            s.close();
            return null;
        }
        if (!status.matches("(?s)HTTP/1\\.[01] 200.*")) {
            s.close();
            throw new IOException("Proxyboy respondió: " + status.split("\r\n")[0]);
        }
        return s;
    }

    // Cliente → upstream
    private void pumpUp(Socket s) {
        try {
            OutputStream out = s.getOutputStream();
            while (true) {
                byte[] d = toUpstream.take();
                if (d == EOF) {
                    // Hacia Proxyboy no propagamos el half-close: Node cerraría la conexión antes de responder.
                    // Se cierra cuando termina el servidor.
                    if (!closed && !viaProxy) s.shutdownOutput();
                    return;
                }
                out.write(d);
                synchronized (this) {
                    queued -= d.length;
                    if (lastWindow < 16384 && window() >= 32768 && !closed) sendAck();
                }
            }
        } catch (Exception e) {
            close(true);
        }
    }

    // Upstream → cliente
    private void pumpDown(Socket s) {
        byte[] buf = new byte[MSS];
        try {
            InputStream in = s.getInputStream();
            int n;
            while ((n = in.read(buf)) > 0) {
                if (!sendData(buf, n)) return;
            }
            sendFin();
        } catch (Exception e) {
            close(true);
        }
    }

    // ---------- Detección de protocolo ----------
    private static boolean looksHttp(byte[] d) {
        String s = new String(d, 0, Math.min(d.length, 8), StandardCharsets.ISO_8859_1);
        for (String m : METHODS) if (s.startsWith(m)) return true;
        return false;
    }

    // "GET http://host/..." : la app ya le habla a un proxy (el proxy HTTP de Android): lo dejamos pasar directo
    private static boolean isProxyRequest(byte[] d) {
        String s = new String(d, 0, Math.min(d.length, 32), StandardCharsets.ISO_8859_1);
        int sp = s.indexOf(' ');
        return sp > 0 && s.regionMatches(true, sp + 1, "http://", 0, 7);
    }

        private static boolean couldBeHttp(byte[] d) {
        String s = new String(d, StandardCharsets.ISO_8859_1);
        for (String m : METHODS) if (m.startsWith(s) || s.startsWith(m)) return true;
        return false;
    }

    private static String httpHost(byte[] d) {
        int end = indexOf(d, "\r\n\r\n");
        String head = new String(d, 0, end >= 0 ? end : d.length, StandardCharsets.ISO_8859_1);
        Matcher m = HOST.matcher(head);
        if (!m.find()) return null;
        String h = m.group(1).trim();
        if (h.startsWith("[")) { int i = h.indexOf(']'); return i > 0 ? h.substring(1, i) : null; }
        int colon = h.lastIndexOf(':');
        return colon > 0 && h.indexOf(':') == colon ? h.substring(0, colon) : h;
    }

    // server_name del ClientHello
    static String sniHost(byte[] d) {
        try {
            int p = 5;
            if ((d[p] & 0xff) != 1) return null; // ClientHello
            p += 4 + 2 + 32;
            p += 1 + (d[p] & 0xff);           // session id
            p += 2 + Packet.u16(d, p);        // cipher suites
            p += 1 + (d[p] & 0xff);           // compresión
            int extEnd = p + 2 + Packet.u16(d, p);
            p += 2;
            while (p + 4 <= extEnd && p + 4 <= d.length) {
                int type = Packet.u16(d, p);
                int len = Packet.u16(d, p + 2);
                p += 4;
                if (type == 0) {
                    int q = p + 2;
                    if ((d[q] & 0xff) == 0) {
                        int n = Packet.u16(d, q + 1);
                        return new String(d, q + 3, n, StandardCharsets.US_ASCII);
                    }
                    return null;
                }
                p += len;
            }
        } catch (RuntimeException ignored) {
            // ClientHello incompleto o raro: usamos la IP
        }
        return null;
    }

    // Nombre detectado; si no hay (o es una IP), la IP de destino
    private String hostOrIp(String name) {
        if (name != null && !name.isEmpty() && !name.matches("[0-9.]+") && name.indexOf(':') < 0) return name;
        return vpn.ipForProxy(remoteIp);
    }

    private static int indexOf(byte[] d, String needle) {
        byte[] n = needle.getBytes(StandardCharsets.ISO_8859_1);
        outer:
        for (int i = 0; i + n.length <= d.length; i++) {
            for (int j = 0; j < n.length; j++) if (d[i + j] != n[j]) continue outer;
            return i;
        }
        return -1;
    }

    private static String enc(String s) {
        try { return URLEncoder.encode(s, "UTF-8").replace("+", "%20"); } catch (Exception e) { return ""; }
    }

    private static long add(long a, long n) { return (a + n) & 0xffffffffL; }
}
