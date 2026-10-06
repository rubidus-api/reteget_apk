package org.reteget.core.ssh;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * HMAC-SHA-256 (RFC 2104) built on the platform's SHA-256.
 *
 * On Android 2.3 "HmacSHA256" comes from a pure-Java provider and is about fifty times slower
 * than the SHA-256 message digest, which is native there; every SSH packet is authenticated, so
 * that difference decides the download speed.
 */
final class HmacSha256 {

    static final int LENGTH = 32;
    private static final int BLOCK = 64;

    private final MessageDigest inner;
    private final MessageDigest outer;
    private final byte[] ipad = new byte[BLOCK];
    private final byte[] opad = new byte[BLOCK];

    HmacSha256(byte[] key) {
        try {
            inner = MessageDigest.getInstance("SHA-256");
            outer = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        byte[] k = key.length > BLOCK ? inner.digest(key) : key;
        for (int i = 0; i < BLOCK; i++) {
            byte b = i < k.length ? k[i] : 0;
            ipad[i] = (byte) (b ^ 0x36);
            opad[i] = (byte) (b ^ 0x5c);
        }
        inner.update(ipad);
    }

    void update(byte[] data) {
        inner.update(data, 0, data.length);
    }

    void update(byte[] data, int off, int len) {
        inner.update(data, off, len);
    }

    /** The MAC of everything updated since the last call; the instance is ready for the next message. */
    byte[] doFinal() {
        byte[] h = inner.digest();
        inner.update(ipad);
        outer.update(opad);
        return outer.digest(h);
    }
}
