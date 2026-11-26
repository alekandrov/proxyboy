package com.proxyboy.vpn;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.concurrent.ConcurrentHashMap;

// UDP (DNS y el resto) pasa directo: un socket por flujo y las respuestas se reinyectan en el túnel.
// UDP/443 (QUIC) se descarta para que las apps usen TCP y el tráfico pase por Proxyboy.
final class UdpRelay {
    private final ProxyboyVpnService vpn;
    private final ConcurrentHashMap<String, Flow> flows = new ConcurrentHashMap<>();

    UdpRelay(ProxyboyVpnService vpn) { this.vpn = vpn; }

    void handle(Packet p) {
        if (p.dstPort == 443) return;
        String key = Packet.key(p);
        Flow f = flows.get(key);
        try {
            if (f == null) {
                f = new Flow(p);
                flows.put(key, f);
                Flow flow = f;
                Thread t = new Thread(() -> receive(key, flow), "udp " + p.dstPort);
                t.setDaemon(true);
                t.start();
            }
            f.lastUsed = System.currentTimeMillis();
            f.socket.send(new DatagramPacket(p.buf, p.payloadOffset, p.payloadLen));
        } catch (Exception e) {
            if (f != null) f.socket.close();
            flows.remove(key);
        }
    }

    private void receive(String key, Flow f) {
        byte[] buf = new byte[65535];
        int idle = f.remotePort == 53 ? 10000 : 60000;
        try {
            f.socket.setSoTimeout(5000);
            while (true) {
                DatagramPacket dp = new DatagramPacket(buf, buf.length);
                try {
                    f.socket.receive(dp);
                } catch (SocketTimeoutException e) {
                    if (System.currentTimeMillis() - f.lastUsed > idle) break;
                    continue;
                }
                f.lastUsed = System.currentTimeMillis();
                vpn.write(Packet.udp(f.remoteIp, f.clientIp, f.remotePort, f.clientPort, buf, 0, dp.getLength()));
            }
        } catch (Exception ignored) {
            // socket cerrado
        } finally {
            f.socket.close();
            flows.remove(key, f);
        }
    }

    void closeAll() {
        for (Flow f : flows.values()) f.socket.close();
        flows.clear();
    }

    private final class Flow {
        final DatagramSocket socket;
        final byte[] clientIp, remoteIp;
        final int clientPort, remotePort;
        volatile long lastUsed;

        Flow(Packet p) throws Exception {
            clientIp = p.src;
            remoteIp = p.dst;
            clientPort = p.srcPort;
            remotePort = p.dstPort;
            socket = new DatagramSocket();
            vpn.protect(socket);
            socket.connect(new InetSocketAddress(Packet.addr(remoteIp), remotePort));
        }
    }
}
