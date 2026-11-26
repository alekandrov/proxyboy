package com.proxyboy.vpn;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageManager;
import android.content.pm.ServiceInfo;
import android.net.ConnectivityManager;
import android.net.LinkProperties;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.system.OsConstants;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

// VPN local: todo el tráfico del dispositivo entra por el túnel; HTTP/HTTPS sale hacia Proxyboy, el resto directo.
// La propia app queda fuera de la VPN, así que sus sockets salen por la red real (sin loops).
public class ProxyboyVpnService extends VpnService {
    static final String ACTION_CONNECT = "com.proxyboy.vpn.CONNECT";
    static final String ACTION_STOP = "com.proxyboy.vpn.STOP";

    // Estado visible para la pantalla
    static volatile boolean running;
    static volatile String status = "Desconectado";
    static volatile String target = "";

    volatile String proxyHost;
    volatile int proxyPort;
    volatile String deviceName;

    private ParcelFileDescriptor tun;
    private FileOutputStream out;
    private Thread loop;
    private ScheduledExecutorService timer;
    private UdpRelay udp;
    private final ConcurrentHashMap<String, TcpSession> sessions = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<Integer, AppInfo> uidCache = new ConcurrentHashMap<>();
    private byte[] proxyIp;
    private final Object writeLock = new Object(); // separado del lock del servicio para no trabarse con las sesiones

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = intent != null ? intent.getAction() : null;
        if (ACTION_STOP.equals(action)) {
            stopVpn();
            stopSelf();
            return START_NOT_STICKY;
        }
        if (ACTION_CONNECT.equals(action)) {
            String host = intent.getStringExtra("host");
            int port = intent.getIntExtra("port", 9090);
            String device = intent.getStringExtra("device");
            stopVpn();
            startVpn(host, port, device);
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onRevoke() {
        // Otra VPN tomó el control o el usuario la desactivó desde Ajustes
        stopVpn();
        stopSelf();
    }

    @Override
    public void onDestroy() {
        stopVpn();
        super.onDestroy();
    }

    private synchronized void startVpn(String host, int port, String device) {
        proxyHost = host;
        proxyPort = port;
        deviceName = device != null && !device.isEmpty() ? device
                : Build.MODEL + " · Android " + Build.VERSION.RELEASE;
        target = host + ":" + port;
        foreground();
        try {
            proxyIp = InetAddress.getByName(host).getAddress();
        } catch (IOException e) {
            proxyIp = null;
        }
        try {
            Builder b = new Builder()
                    .setSession("Proxyboy")
                    .setMtu(1500)
                    .addAddress("10.215.173.1", 32)
                    .addRoute("0.0.0.0", 0)
                    .addAddress("fd70:7278:7962::1", 128)
                    .addRoute("::", 0);
            List<InetAddress> dns = underlyingDns();
            if (dns.isEmpty()) b.addDnsServer("8.8.8.8");
            for (InetAddress a : dns) b.addDnsServer(a);
            try { b.addDisallowedApplication(getPackageName()); } catch (PackageManager.NameNotFoundException ignored) {}
            if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
            b.setBlocking(true);
            b.setConfigureIntent(PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE));
            tun = b.establish();
        } catch (Exception e) {
            tun = null;
        }
        if (tun == null) {
            status = "No se pudo crear la VPN (¿falta el permiso?)";
            running = false;
            stopForeground(true);
            return;
        }
        out = new FileOutputStream(tun.getFileDescriptor());
        udp = new UdpRelay(this);
        timer = Executors.newSingleThreadScheduledExecutor();
        timer.scheduleWithFixedDelay(() -> {
            long now = System.currentTimeMillis();
            for (TcpSession s : sessions.values()) s.tick(now);
        }, 200, 200, TimeUnit.MILLISECONDS);
        FileInputStream in = new FileInputStream(tun.getFileDescriptor());
        running = true;
        status = "Conectado";
        loop = new Thread(() -> readLoop(in), "tun");
        loop.start();
        checkProxy();
    }

    private synchronized void stopVpn() {
        boolean was = running;
        running = false;
        if (timer != null) { timer.shutdownNow(); timer = null; }
        for (TcpSession s : sessions.values()) s.close(true);
        sessions.clear();
        if (udp != null) { udp.closeAll(); udp = null; }
        if (tun != null) { try { tun.close(); } catch (IOException ignored) {} tun = null; }
        if (loop != null) { loop.interrupt(); loop = null; }
        if (was) status = "Desconectado";
        stopForeground(true);
    }

    private void readLoop(FileInputStream in) {
        byte[] buf = new byte[32767];
        UdpRelay relay = udp;
        while (running) {
            int n;
            try {
                n = in.read(buf);
            } catch (IOException e) {
                break;
            }
            if (n <= 0) continue;
            Packet p = Packet.parse(buf, n);
            if (p == null) continue;
            if (p.protocol == Packet.TCP) onTcp(p);
            else if (relay != null) relay.handle(p);
        }
    }

    private void onTcp(Packet p) {
        String key = Packet.key(p);
        TcpSession s = sessions.get(key);
        if (s != null) { s.onPacket(p); return; }
        if (p.has(Packet.SYN) && !p.has(Packet.ACK)) {
            s = new TcpSession(this, key, p);
            sessions.put(key, s);
            s.start();
        } else if (!p.has(Packet.RST)) {
            // Conexión que no conocemos (ej. de antes de activar la VPN): la reseteamos
            long ack = (p.seq + p.payloadLen + (p.has(Packet.FIN) ? 1 : 0)) & 0xffffffffL;
            write(Packet.tcp(p.dst, p.src, p.dstPort, p.srcPort, p.ack, ack, Packet.RST | Packet.ACK, 0, null, 0, 0, 0));
        }
    }

    void removeSession(TcpSession s) { sessions.remove(s.key, s); }

    void write(byte[] packet) {
        FileOutputStream o = out;
        if (o == null || !running) return;
        synchronized (writeLock) {
            try { o.write(packet); } catch (IOException ignored) {}
        }
    }

    // Conexiones que no tiene sentido mandar a Proxyboy
    boolean isDirectOnly(byte[] ip, int port) {
        if (port == 22) return true; // SSH
        return proxyIp != null && port == proxyPort && java.util.Arrays.equals(ip, proxyIp);
    }

    // Una IP de destino tal como la tiene que usar Proxyboy desde la compu
    String ipForProxy(byte[] ip) {
        // 10.0.2.2 en el emulador es la compu misma
        if (proxyIp != null && java.util.Arrays.equals(ip, proxyIp) && !Packet.addr(ip).isLoopbackAddress()) return "127.0.0.1";
        String s = Packet.addr(ip).getHostAddress();
        int pct = s.indexOf('%');
        return pct > 0 ? s.substring(0, pct) : s;
    }

    AppInfo ownerOf(byte[] srcIp, int srcPort, byte[] dstIp, int dstPort) {
        if (Build.VERSION.SDK_INT < 29) return null;
        int uid;
        try {
            ConnectivityManager cm = getSystemService(ConnectivityManager.class);
            uid = cm.getConnectionOwnerUid(OsConstants.IPPROTO_TCP,
                    new InetSocketAddress(Packet.addr(srcIp), srcPort), new InetSocketAddress(Packet.addr(dstIp), dstPort));
        } catch (Exception e) {
            return null;
        }
        if (uid < 0) return null;
        AppInfo cached = uidCache.get(uid);
        if (cached != null) return cached;
        AppInfo info;
        PackageManager pm = getPackageManager();
        String[] pkgs = pm.getPackagesForUid(uid);
        if (pkgs == null || pkgs.length == 0) {
            info = new AppInfo("uid." + uid, uid == 0 ? "root" : uid < 10000 ? "Sistema Android" : "UID " + uid);
        } else {
            String pkg = pkgs[0];
            String label = pkg;
            try {
                ApplicationInfo ai = pm.getApplicationInfo(pkg, 0);
                label = String.valueOf(pm.getApplicationLabel(ai));
            } catch (PackageManager.NameNotFoundException ignored) {}
            if (pkgs.length > 1) label = uid < 10000 ? "Sistema Android" : label;
            info = new AppInfo(pkg, label);
        }
        uidCache.put(uid, info);
        return info;
    }

    // DNS de la red real (no de otra VPN)
    private List<InetAddress> underlyingDns() {
        List<InetAddress> list = new ArrayList<>();
        ConnectivityManager cm = getSystemService(ConnectivityManager.class);
        for (Network n : cm.getAllNetworks()) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(n);
            if (caps == null || caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    || !caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) continue;
            LinkProperties lp = cm.getLinkProperties(n);
            if (lp == null) continue;
            for (InetAddress a : lp.getDnsServers()) if (!list.contains(a)) list.add(a);
        }
        // IPv4 primero: es lo que siempre funciona en el emulador
        list.sort((a, b) -> Boolean.compare(!(a instanceof Inet4Address), !(b instanceof Inet4Address)));
        return list;
    }

    // Verifica que Proxyboy responda, para avisar en la pantalla si no
    private void checkProxy() {
        String host = proxyHost;
        int port = proxyPort;
        Thread t = new Thread(() -> {
            try (Socket s = new Socket()) {
                s.connect(new InetSocketAddress(host, port), 3000);
                if (running) status = "Conectado";
            } catch (IOException e) {
                if (running) status = "Conectado, pero Proxyboy no responde en " + host + ":" + port;
            }
        });
        t.setDaemon(true);
        t.start();
    }

    private void foreground() {
        try {
            NotificationManager nm = getSystemService(NotificationManager.class);
            Notification.Builder nb;
            if (Build.VERSION.SDK_INT >= 26) {
                nm.createNotificationChannel(new NotificationChannel("vpn", "VPN", NotificationManager.IMPORTANCE_LOW));
                nb = new Notification.Builder(this, "vpn");
            } else {
                nb = new Notification.Builder(this);
            }
            Notification n = nb.setSmallIcon(getApplicationInfo().icon)
                    .setContentTitle("Proxyboy VPN")
                    .setContentText("Enviando el tráfico a " + target)
                    .setOngoing(true)
                    .setContentIntent(PendingIntent.getActivity(this, 0, new Intent(this, MainActivity.class), PendingIntent.FLAG_IMMUTABLE))
                    .build();
            if (Build.VERSION.SDK_INT >= 34) startForeground(1, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
            else startForeground(1, n);
        } catch (Exception ignored) {
            // Sin notificación la VPN funciona igual
        }
    }
}
