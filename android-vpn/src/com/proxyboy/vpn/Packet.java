package com.proxyboy.vpn;

import java.net.InetAddress;

// Parseo y armado de paquetes IPv4/IPv6 con TCP o UDP (lo mínimo para hacer de stack TCP en espacio de usuario)
final class Packet {
    static final int TCP = 6;
    static final int UDP = 17;

    static final int FIN = 0x01, SYN = 0x02, RST = 0x04, PSH = 0x08, ACK = 0x10;

    byte[] buf;
    int version;
    int protocol;
    byte[] src;
    byte[] dst;
    int l4Offset; // inicio del header TCP/UDP
    int end;      // fin del paquete IP (sin padding)
    int srcPort, dstPort;
    // TCP
    long seq, ack;
    int flags;
    int window;
    int payloadOffset, payloadLen;

    // Devuelve null si no es TCP/UDP o está fragmentado
    static Packet parse(byte[] b, int len) {
        if (len < 20) return null;
        Packet p = new Packet();
        p.buf = b;
        p.version = (b[0] >> 4) & 0xf;
        int next;
        int off;
        if (p.version == 4) {
            int ihl = (b[0] & 0xf) * 4;
            int total = u16(b, 2);
            if (ihl < 20 || total > len || total < ihl) return null;
            int frag = u16(b, 6);
            if ((frag & 0x3fff) != 0) return null; // fragmentos: no los manejamos
            next = b[9] & 0xff;
            p.src = copy(b, 12, 4);
            p.dst = copy(b, 16, 4);
            off = ihl;
            p.end = total;
        } else if (p.version == 6) {
            if (len < 40) return null;
            int total = 40 + u16(b, 4);
            if (total > len) return null;
            next = b[6] & 0xff;
            p.src = copy(b, 8, 16);
            p.dst = copy(b, 24, 16);
            off = 40;
            // Headers de extensión comunes
            while (next == 0 || next == 43 || next == 60) {
                if (off + 8 > total) return null;
                next = b[off] & 0xff;
                off += ((b[off + 1] & 0xff) + 1) * 8;
            }
            if (next == 44) return null; // fragmento
            p.end = total;
        } else {
            return null;
        }
        p.protocol = next;
        p.l4Offset = off;
        if (next == TCP) {
            if (off + 20 > p.end) return null;
            p.srcPort = u16(b, off);
            p.dstPort = u16(b, off + 2);
            p.seq = u32(b, off + 4);
            p.ack = u32(b, off + 8);
            int dataOff = ((b[off + 12] >> 4) & 0xf) * 4;
            if (dataOff < 20 || off + dataOff > p.end) return null;
            p.flags = b[off + 13] & 0x3f;
            p.window = u16(b, off + 14);
            p.payloadOffset = off + dataOff;
            p.payloadLen = p.end - p.payloadOffset;
        } else if (next == UDP) {
            if (off + 8 > p.end) return null;
            p.srcPort = u16(b, off);
            p.dstPort = u16(b, off + 2);
            p.payloadOffset = off + 8;
            p.payloadLen = Math.min(u16(b, off + 4) - 8, p.end - p.payloadOffset);
            if (p.payloadLen < 0) return null;
        } else {
            return null;
        }
        return p;
    }

    boolean has(int f) { return (flags & f) != 0; }

    // ---------- Armado ----------
    private static int ipId = 1;

    static byte[] tcp(byte[] src, byte[] dst, int sport, int dport, long seq, long ack, int flags, int window,
                      byte[] data, int off, int len, int mss) {
        int optLen = mss > 0 ? 4 : 0;
        int l4 = 20 + optLen + len;
        int ipLen = src.length == 4 ? 20 : 40;
        byte[] b = new byte[ipLen + l4];
        writeIp(b, src, dst, TCP, l4);
        int o = ipLen;
        put16(b, o, sport);
        put16(b, o + 2, dport);
        put32(b, o + 4, seq);
        put32(b, o + 8, ack);
        b[o + 12] = (byte) (((20 + optLen) / 4) << 4);
        b[o + 13] = (byte) flags;
        put16(b, o + 14, window);
        if (mss > 0) {
            b[o + 20] = 2;
            b[o + 21] = 4;
            put16(b, o + 22, mss);
        }
        if (len > 0) System.arraycopy(data, off, b, o + 20 + optLen, len);
        int sum = checksum(pseudo(src, dst, TCP, l4), b, o, l4);
        put16(b, o + 16, sum);
        return b;
    }

    static byte[] udp(byte[] src, byte[] dst, int sport, int dport, byte[] data, int off, int len) {
        int l4 = 8 + len;
        int ipLen = src.length == 4 ? 20 : 40;
        byte[] b = new byte[ipLen + l4];
        writeIp(b, src, dst, UDP, l4);
        int o = ipLen;
        put16(b, o, sport);
        put16(b, o + 2, dport);
        put16(b, o + 4, l4);
        System.arraycopy(data, off, b, o + 8, len);
        int sum = checksum(pseudo(src, dst, UDP, l4), b, o, l4);
        put16(b, o + 6, sum == 0 ? 0xffff : sum);
        return b;
    }

    private static synchronized int nextId() { ipId = (ipId + 1) & 0xffff; return ipId; }

    private static void writeIp(byte[] b, byte[] src, byte[] dst, int proto, int l4) {
        if (src.length == 4) {
            b[0] = 0x45;
            put16(b, 2, 20 + l4);
            put16(b, 4, nextId());
            put16(b, 6, 0x4000); // DF
            b[8] = 64;
            b[9] = (byte) proto;
            System.arraycopy(src, 0, b, 12, 4);
            System.arraycopy(dst, 0, b, 16, 4);
            put16(b, 10, checksum(0, b, 0, 20));
        } else {
            b[0] = 0x60;
            put16(b, 4, l4);
            b[6] = (byte) proto;
            b[7] = 64;
            System.arraycopy(src, 0, b, 8, 16);
            System.arraycopy(dst, 0, b, 24, 16);
        }
    }

    private static long pseudo(byte[] src, byte[] dst, int proto, int l4) {
        long sum = 0;
        for (int i = 0; i < src.length; i += 2) sum += u16(src, i) + u16(dst, i);
        sum += proto + (l4 & 0xffff) + ((l4 >>> 16) & 0xffff);
        return sum;
    }

    private static int checksum(long sum, byte[] b, int off, int len) {
        int i = off;
        int end = off + len;
        for (; i + 1 < end; i += 2) sum += ((b[i] & 0xff) << 8) | (b[i + 1] & 0xff);
        if (i < end) sum += (b[i] & 0xff) << 8;
        while ((sum >> 16) != 0) sum = (sum & 0xffff) + (sum >> 16);
        return (int) (~sum & 0xffff);
    }

    // ---------- Utilidades ----------
    static int u16(byte[] b, int o) { return ((b[o] & 0xff) << 8) | (b[o + 1] & 0xff); }

    static long u32(byte[] b, int o) {
        return ((long) (b[o] & 0xff) << 24) | ((b[o + 1] & 0xff) << 16) | ((b[o + 2] & 0xff) << 8) | (b[o + 3] & 0xff);
    }

    static void put16(byte[] b, int o, int v) { b[o] = (byte) (v >> 8); b[o + 1] = (byte) v; }

    static void put32(byte[] b, int o, long v) {
        b[o] = (byte) (v >> 24); b[o + 1] = (byte) (v >> 16); b[o + 2] = (byte) (v >> 8); b[o + 3] = (byte) v;
    }

    static byte[] copy(byte[] b, int o, int n) { byte[] r = new byte[n]; System.arraycopy(b, o, r, 0, n); return r; }

    static InetAddress addr(byte[] a) {
        try { return InetAddress.getByAddress(a); } catch (Exception e) { return null; }
    }

    static String key(Packet p) {
        StringBuilder sb = new StringBuilder();
        for (byte x : p.src) sb.append(x & 0xff).append('.');
        sb.append(p.srcPort).append('>');
        for (byte x : p.dst) sb.append(x & 0xff).append('.');
        return sb.append(p.dstPort).toString();
    }
}
