package org.reteget.core.tls;

import java.util.Locale;

/**
 * Server identity check against the certificate's subjectAltName (RFC 9525).
 *
 * DNS names match case-insensitively, with a wildcard allowed only as the whole
 * left-most label and matching exactly one label. IP literals match iPAddress
 * entries only. The subject CN is never consulted.
 */
public final class HostnameChecker {

    private HostnameChecker() {}

    public static boolean matches(String host, X509Cert cert) {
        if (host == null || host.isEmpty() || cert == null) return false;
        String h = host.toLowerCase(Locale.US);
        if (h.startsWith("[") && h.endsWith("]")) {
            h = h.substring(1, h.length() - 1);
        }
        if (h.endsWith(".")) {
            h = h.substring(0, h.length() - 1);
        }
        if (isIpLiteral(h)) {
            byte[] addr;
            try {
                // A literal, so no name lookup happens.
                addr = java.net.InetAddress.getByName(h).getAddress();
            } catch (Exception e) {
                return false;
            }
            for (byte[] ip : cert.ipAddresses) {
                if (java.util.Arrays.equals(ip, addr)) return true;
            }
            return false;
        }
        for (String name : cert.dnsNames) {
            if (dnsMatches(h, name.toLowerCase(Locale.US))) return true;
        }
        return false;
    }

    static boolean dnsMatches(String host, String pattern) {
        if (pattern.endsWith(".")) pattern = pattern.substring(0, pattern.length() - 1);
        if (pattern.isEmpty()) return false;
        if (!pattern.startsWith("*.")) {
            return pattern.indexOf('*') < 0 && host.equals(pattern);
        }
        String suffix = pattern.substring(1); // ".example.com"
        if (suffix.indexOf('*') >= 0 || suffix.indexOf('.', 1) < 0) {
            return false; // no further wildcards, and never "*.com"
        }
        if (!host.endsWith(suffix)) return false;
        String label = host.substring(0, host.length() - suffix.length());
        return !label.isEmpty() && label.indexOf('.') < 0;
    }

    static boolean isIpLiteral(String h) {
        if (h.indexOf(':') >= 0) return true;
        if (h.isEmpty()) return false;
        int dots = 0;
        for (int i = 0; i < h.length(); i++) {
            char c = h.charAt(i);
            if (c == '.') dots++;
            else if (c < '0' || c > '9') return false;
        }
        return dots == 3;
    }
}
