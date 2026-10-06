package org.reteget.core.ssh;

import java.io.ByteArrayOutputStream;

/** Base64 (RFC 4648) for fingerprints and key files; android.util.Base64 is not on the JVM and java.util.Base64 is API 26. */
final class SshBase64 {

    private SshBase64() {}

    private static final char[] ALPHABET =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    static String encode(byte[] in, boolean padding) {
        StringBuilder sb = new StringBuilder((in.length + 2) / 3 * 4);
        for (int i = 0; i < in.length; i += 3) {
            int b0 = in[i] & 0xff;
            int b1 = i + 1 < in.length ? in[i + 1] & 0xff : 0;
            int b2 = i + 2 < in.length ? in[i + 2] & 0xff : 0;
            sb.append(ALPHABET[b0 >> 2]);
            sb.append(ALPHABET[((b0 & 3) << 4) | (b1 >> 4)]);
            if (i + 1 < in.length) sb.append(ALPHABET[((b1 & 0xf) << 2) | (b2 >> 6)]);
            else if (padding) sb.append('=');
            if (i + 2 < in.length) sb.append(ALPHABET[b2 & 0x3f]);
            else if (padding) sb.append('=');
        }
        return sb.toString();
    }

    /** Decodes, skipping white space and padding; null when another character appears. */
    static byte[] decode(String s) {
        ByteArrayOutputStream out = new ByteArrayOutputStream(s.length() * 3 / 4);
        int acc = 0;
        int bits = 0;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            int v;
            if (c >= 'A' && c <= 'Z') v = c - 'A';
            else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
            else if (c >= '0' && c <= '9') v = c - '0' + 52;
            else if (c == '+') v = 62;
            else if (c == '/') v = 63;
            else if (c == '=' || c == '\n' || c == '\r' || c == ' ' || c == '\t') continue;
            else return null;
            acc = (acc << 6) | v;
            bits += 6;
            if (bits >= 8) {
                bits -= 8;
                out.write((acc >> bits) & 0xff);
            }
        }
        return out.toByteArray();
    }
}
