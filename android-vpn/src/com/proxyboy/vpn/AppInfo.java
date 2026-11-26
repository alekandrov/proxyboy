package com.proxyboy.vpn;

// App dueña de una conexión (por UID)
final class AppInfo {
    final String packageName;
    final String label;

    AppInfo(String packageName, String label) {
        this.packageName = packageName;
        this.label = label;
    }
}
