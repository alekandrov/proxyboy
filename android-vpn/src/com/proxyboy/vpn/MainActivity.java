package com.proxyboy.vpn;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

// Pantalla principal. Proxyboy (desde la compu) la abre con:
//   am start -n com.proxyboy.vpn/.MainActivity --es host 10.0.2.2 --ei port 9090 --es device "Pixel 9" --ez connect true
public class MainActivity extends Activity {
    private static final int BG = 0xFF0E1116, CARD = 0xFF171B22, BORDER = 0xFF2A303A, TEXT = 0xFFE8ECF1, MUTED = 0xFF8B95A3;
    private static final int GREEN = 0xFF2FB56A, ACCENT = 0xFF6C7BFF;

    private SharedPreferences prefs;
    private EditText hostField, portField;
    private TextView statusView, targetView;
    private Toggle toggle;
    private String pendingDevice;
    private final Handler handler = new Handler(Looper.getMainLooper());
    private final Runnable refresher = new Runnable() {
        @Override public void run() { refresh(); handler.postDelayed(this, 500); }
    };

    @Override
    protected void onCreate(Bundle saved) {
        super.onCreate(saved);
        prefs = getSharedPreferences("proxyboy", MODE_PRIVATE);
        setContentView(buildUi());
        handleIntent(getIntent());
    }

    @Override
    protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        handleIntent(intent);
    }

    @Override protected void onResume() { super.onResume(); handler.post(refresher); }

    @Override protected void onPause() { super.onPause(); handler.removeCallbacks(refresher); }

    private void handleIntent(Intent i) {
        if (i == null) return;
        if (i.hasExtra("host")) hostField.setText(i.getStringExtra("host"));
        if (i.hasExtra("port")) portField.setText(String.valueOf(i.getIntExtra("port", 9090)));
        if (i.hasExtra("device")) pendingDevice = i.getStringExtra("device");
        if (i.getBooleanExtra("connect", false)) connect();
        else if (i.getBooleanExtra("disconnect", false)) disconnect();
        i.removeExtra("connect");
        i.removeExtra("disconnect");
    }

    private void connect() {
        Intent consent = VpnService.prepare(this);
        if (consent != null) startActivityForResult(consent, 1);
        else onActivityResult(1, RESULT_OK, null);
    }

    @Override
    protected void onActivityResult(int request, int result, Intent data) {
        if (request != 1) return;
        if (result != RESULT_OK) { ProxyboyVpnService.status = "Permiso de VPN rechazado"; refresh(); return; }
        String host = hostField.getText().toString().trim();
        int port;
        try { port = Integer.parseInt(portField.getText().toString().trim()); } catch (NumberFormatException e) { port = 9090; }
        if (host.isEmpty()) host = isEmulator() ? "10.0.2.2" : "127.0.0.1";
        SharedPreferences.Editor ed = prefs.edit().putString("host", host).putInt("port", port);
        if (pendingDevice != null) ed.putString("device", pendingDevice);
        ed.apply();
        Intent svc = new Intent(this, ProxyboyVpnService.class).setAction(ProxyboyVpnService.ACTION_CONNECT)
                .putExtra("host", host).putExtra("port", port).putExtra("device", prefs.getString("device", null));
        startService(svc);
        ProxyboyVpnService.status = "Conectando…";
        refresh();
    }

    private void disconnect() {
        startService(new Intent(this, ProxyboyVpnService.class).setAction(ProxyboyVpnService.ACTION_STOP));
    }

    private void refresh() {
        boolean on = ProxyboyVpnService.running;
        toggle.setOn(on);
        String st = ProxyboyVpnService.status;
        boolean warn = st.contains("no responde") || st.contains("No se pudo") || st.contains("rechazado");
        statusView.setText("● " + st);
        statusView.setTextColor(warn ? 0xFFFFB454 : on ? GREEN : MUTED);
        targetView.setText(on ? "→ Proxyboy en " + ProxyboyVpnService.target : "Tocá el botón para empezar a capturar");
        hostField.setEnabled(!on);
        portField.setEnabled(!on);
    }

    private static boolean isEmulator() {
        return Build.FINGERPRINT.contains("generic") || Build.MODEL.startsWith("sdk_") || Build.HARDWARE.contains("ranchu")
                || Build.HARDWARE.contains("goldfish");
    }

    // ---------- UI ----------
    private View buildUi() {
        ScrollView scroll = new ScrollView(this);
        scroll.setBackgroundColor(BG);
        scroll.setFitsSystemWindows(true);
        LinearLayout col = new LinearLayout(this);
        col.setOrientation(LinearLayout.VERTICAL);
        col.setGravity(Gravity.CENTER_HORIZONTAL);
        col.setPadding(dp(20), dp(28), dp(20), dp(28));
        scroll.addView(col);

        TextView title = text("Proxyboy VPN", 30, TEXT, true);
        col.addView(title);
        TextView sub = text("Captura el tráfico del dispositivo y lo manda a Proxyboy", 15, MUTED, false);
        sub.setGravity(Gravity.CENTER);
        sub.setPadding(0, dp(6), 0, dp(24));
        col.addView(sub);

        toggle = new Toggle(this);
        toggle.setOnClickListener(v -> { if (ProxyboyVpnService.running) disconnect(); else connect(); });
        col.addView(toggle, new LinearLayout.LayoutParams(dp(210), dp(210)));

        statusView = text("", 18, MUTED, true);
        statusView.setGravity(Gravity.CENTER);
        statusView.setPadding(0, dp(18), 0, dp(2));
        col.addView(statusView);
        targetView = text("", 14, ACCENT, false);
        targetView.setGravity(Gravity.CENTER);
        targetView.setPadding(0, 0, 0, dp(22));
        col.addView(targetView);

        LinearLayout proxyCard = card();
        proxyCard.addView(text("Proxyboy", 17, TEXT, true));
        TextView hint = text("Emulador: 10.0.2.2 · Teléfono por USB: 127.0.0.1 (adb reverse) · Wi-Fi: la IP de tu compu", 13, MUTED, false);
        hint.setPadding(0, dp(4), 0, dp(10));
        proxyCard.addView(hint);
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        hostField = field(prefs.getString("host", isEmulator() ? "10.0.2.2" : "127.0.0.1"), InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
        portField = field(String.valueOf(prefs.getInt("port", 9090)), InputType.TYPE_CLASS_NUMBER);
        row.addView(hostField, new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 3));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1.2f);
        lp.leftMargin = dp(10);
        row.addView(portField, lp);
        proxyCard.addView(row);
        col.addView(proxyCard, cardParams());

        LinearLayout info = card();
        info.addView(text("¿Por qué una VPN?", 17, TEXT, true));
        TextView why = text("Flutter, React Native y otras apps ignoran el proxy de Android. La VPN toma todo el tráfico del sistema: "
                + "HTTP y HTTPS van a Proxyboy (con el nombre de la app que lo hizo) y el resto sale directo. "
                + "Para ver HTTPS descifrado, la app tiene que confiar en el certificado de Proxyboy.", 14, MUTED, false);
        why.setPadding(0, dp(6), 0, 0);
        why.setLineSpacing(0, 1.25f);
        info.addView(why);
        col.addView(info, cardParams());
        return scroll;
    }

    private TextView text(String s, int sp, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(s);
        t.setTextSize(TypedValue.COMPLEX_UNIT_SP, sp);
        t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT_BOLD);
        return t;
    }

    private EditText field(String value, int type) {
        EditText e = new EditText(this);
        e.setText(value);
        e.setInputType(type);
        e.setSingleLine(true);
        e.setTextColor(TEXT);
        e.setTypeface(Typeface.MONOSPACE);
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        e.setPadding(dp(12), dp(10), dp(12), dp(10));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(BG);
        bg.setCornerRadius(dp(10));
        bg.setStroke(dp(1), BORDER);
        e.setBackground(bg);
        return e;
    }

    private LinearLayout card() {
        LinearLayout c = new LinearLayout(this);
        c.setOrientation(LinearLayout.VERTICAL);
        c.setPadding(dp(18), dp(16), dp(18), dp(18));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(CARD);
        bg.setCornerRadius(dp(16));
        bg.setStroke(dp(1), BORDER);
        c.setBackground(bg);
        return c;
    }

    private LinearLayout.LayoutParams cardParams() {
        LinearLayout.LayoutParams p = new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        p.topMargin = dp(14);
        return p;
    }

    private int dp(float v) { return Math.round(v * getResources().getDisplayMetrics().density); }

    // Botón circular grande: verde con "ACTIVA" cuando la VPN está encendida
    private final class Toggle extends View {
        private final Paint fill = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint ring = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint label = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Paint icon = new Paint(Paint.ANTI_ALIAS_FLAG);
        private boolean on;

        Toggle(Context c) {
            super(c);
            ring.setStyle(Paint.Style.STROKE);
            ring.setStrokeWidth(dp(5));
            label.setColor(Color.WHITE);
            label.setTextAlign(Paint.Align.CENTER);
            label.setTypeface(Typeface.create(Typeface.DEFAULT, Typeface.BOLD));
            label.setLetterSpacing(0.12f);
            icon.setColor(Color.WHITE);
            icon.setStyle(Paint.Style.STROKE);
            icon.setStrokeCap(Paint.Cap.ROUND);
            icon.setStrokeWidth(dp(7));
            setClickable(true);
        }

        void setOn(boolean v) { if (v != on) { on = v; invalidate(); } }

        @Override
        protected void onDraw(Canvas c) {
            float w = getWidth(), h = getHeight(), cx = w / 2, cy = h / 2, r = Math.min(w, h) / 2 - dp(6);
            fill.setColor(on ? GREEN : 0xFF262C36);
            ring.setColor(on ? 0xFF7FDCA4 : 0xFF3A4250);
            c.drawCircle(cx, cy, r, fill);
            c.drawCircle(cx, cy, r, ring);
            label.setTextSize(dp(17));
            if (on) {
                // tilde
                android.graphics.Path p = new android.graphics.Path();
                p.moveTo(cx - r * 0.22f, cy - r * 0.12f);
                p.lineTo(cx - r * 0.04f, cy + r * 0.06f);
                p.lineTo(cx + r * 0.26f, cy - r * 0.28f);
                c.drawPath(p, icon);
                c.drawText("ACTIVA", cx, cy + r * 0.42f, label);
            } else {
                // símbolo de encendido
                c.drawArc(cx - r * 0.24f, cy - r * 0.36f, cx + r * 0.24f, cy + r * 0.12f, -60, 300, false, icon);
                c.drawLine(cx, cy - r * 0.44f, cx, cy - r * 0.14f, icon);
                c.drawText("CONECTAR", cx, cy + r * 0.42f, label);
            }
        }
    }
}
