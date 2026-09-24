package org.reteget.core.tls;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF (RFC 5869) over HMAC-SHA256 and the TLS 1.3 helpers built on it
 * (RFC 8446 section 7.1: HKDF-Expand-Label and Derive-Secret).
 */
public final class Hkdf {

    public static final int HASH_LEN = 32;
    private static final String HMAC = "HmacSHA256";

    private Hkdf() {}

    public static byte[] hmac(byte[] key, byte[] data) throws Exception {
        Mac mac = Mac.getInstance(HMAC);
        // A zero-length HMAC key is legal; SecretKeySpec rejects it, so pad to one block of zeros,
        // which HMAC treats identically (keys are zero-padded to the block size).
        mac.init(new SecretKeySpec(key.length == 0 ? new byte[64] : key, HMAC));
        return mac.doFinal(data);
    }

    public static byte[] extract(byte[] salt, byte[] ikm) throws Exception {
        return hmac(salt == null || salt.length == 0 ? new byte[HASH_LEN] : salt, ikm);
    }

    public static byte[] expand(byte[] prk, byte[] info, int length) throws Exception {
        if (length < 0 || length > 255 * HASH_LEN) {
            throw new IllegalArgumentException("HKDF output length out of range");
        }
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(prk, HMAC));
        byte[] out = new byte[length];
        byte[] t = new byte[0];
        int pos = 0;
        for (int i = 1; pos < length; i++) {
            mac.update(t);
            mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();
            int n = Math.min(t.length, length - pos);
            System.arraycopy(t, 0, out, pos, n);
            pos += n;
        }
        return out;
    }

    /** HkdfLabel = uint16 length || opaque label<7..255> ("tls13 " + label) || opaque context<0..255>. */
    public static byte[] expandLabel(byte[] secret, String label, byte[] context, int length) throws Exception {
        byte[] full = ascii("tls13 " + label);
        if (full.length > 255 || context.length > 255) {
            throw new IllegalArgumentException("HKDF label or context too long");
        }
        byte[] info = new byte[2 + 1 + full.length + 1 + context.length];
        int p = 0;
        info[p++] = (byte) (length >>> 8);
        info[p++] = (byte) length;
        info[p++] = (byte) full.length;
        System.arraycopy(full, 0, info, p, full.length);
        p += full.length;
        info[p++] = (byte) context.length;
        System.arraycopy(context, 0, info, p, context.length);
        return expand(secret, info, length);
    }

    /** Derive-Secret(secret, label, messages) with the transcript hash already computed. */
    public static byte[] deriveSecret(byte[] secret, String label, byte[] transcriptHash) throws Exception {
        return expandLabel(secret, label, transcriptHash, HASH_LEN);
    }

    static byte[] ascii(String s) {
        byte[] b = new byte[s.length()];
        for (int i = 0; i < b.length; i++) {
            char c = s.charAt(i);
            if (c > 0x7e) {
                throw new IllegalArgumentException("non-ASCII label");
            }
            b[i] = (byte) c;
        }
        return b;
    }
}
