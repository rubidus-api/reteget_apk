package org.reteget.core.tls;

import java.security.MessageDigest;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES-GCM with a 12-byte nonce and a 16-byte tag (NIST SP 800-38D).
 *
 * Only the AES block encryption comes from the platform ("AES/ECB/NoPadding",
 * present since API 1); CTR, GHASH and tag handling are implemented here because
 * "AES/GCM/NoPadding" is missing on the Android releases this engine targets.
 * Decryption checks the tag before any plaintext is produced.
 */
public final class AesGcm {

    public static final int TAG_LEN = 16;
    public static final int NONCE_LEN = 12;

    private final Cipher aesEcb;
    private final long h0;
    private final long h1;

    public AesGcm(byte[] key) throws Exception {
        if (key.length != 16 && key.length != 32) {
            throw new IllegalArgumentException("AES key must be 16 or 32 bytes");
        }
        aesEcb = Cipher.getInstance("AES/ECB/NoPadding");
        aesEcb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        byte[] h = aesEcb.doFinal(new byte[16]);
        h0 = getLong(h, 0);
        h1 = getLong(h, 8);
    }

    /** Returns ciphertext || tag. */
    public byte[] encrypt(byte[] nonce, byte[] plaintext, byte[] aad) throws Exception {
        return encrypt(nonce, plaintext, 0, plaintext.length, aad);
    }

    public byte[] encrypt(byte[] nonce, byte[] in, int off, int len, byte[] aad) throws Exception {
        checkNonce(nonce);
        byte[] out = new byte[len + TAG_LEN];
        byte[] j0 = j0(nonce);
        ctr(j0, in, off, len, out, 0);
        byte[] tag = tag(j0, aad, out, 0, len);
        System.arraycopy(tag, 0, out, len, TAG_LEN);
        return out;
    }

    /** Takes ciphertext || tag; throws SecurityException when the tag does not match. */
    public byte[] decrypt(byte[] nonce, byte[] ciphertextWithTag, byte[] aad) throws Exception {
        return decrypt(nonce, ciphertextWithTag, 0, ciphertextWithTag.length, aad);
    }

    public byte[] decrypt(byte[] nonce, byte[] in, int off, int len, byte[] aad) throws Exception {
        checkNonce(nonce);
        if (len < TAG_LEN) {
            throw new SecurityException("GCM payload shorter than tag");
        }
        int cipherLen = len - TAG_LEN;
        byte[] j0 = j0(nonce);
        byte[] expected = tag(j0, aad, in, off, cipherLen);
        byte[] received = new byte[TAG_LEN];
        System.arraycopy(in, off + cipherLen, received, 0, TAG_LEN);
        if (!MessageDigest.isEqual(expected, received)) {
            throw new SecurityException("GCM tag mismatch");
        }
        byte[] plain = new byte[cipherLen];
        ctr(j0, in, off, cipherLen, plain, 0);
        return plain;
    }

    private static void checkNonce(byte[] nonce) {
        if (nonce == null || nonce.length != NONCE_LEN) {
            throw new IllegalArgumentException("GCM nonce must be 12 bytes");
        }
    }

    private static byte[] j0(byte[] nonce) {
        byte[] j0 = new byte[16];
        System.arraycopy(nonce, 0, j0, 0, NONCE_LEN);
        j0[15] = 1;
        return j0;
    }

    private void ctr(byte[] j0, byte[] in, int inOff, int len, byte[] out, int outOff) throws Exception {
        byte[] counter = j0.clone();
        byte[] mask = new byte[16];
        for (int pos = 0; pos < len; pos += 16) {
            inc32(counter);
            aesEcb.doFinal(counter, 0, 16, mask, 0);
            int n = Math.min(16, len - pos);
            for (int j = 0; j < n; j++) {
                out[outOff + pos + j] = (byte) (in[inOff + pos + j] ^ mask[j]);
            }
        }
    }

    private byte[] tag(byte[] j0, byte[] aad, byte[] c, int cOff, int cLen) throws Exception {
        long[] s = new long[2];
        int aadLen = aad == null ? 0 : aad.length;
        if (aadLen > 0) {
            ghash(s, aad, 0, aadLen);
        }
        ghash(s, c, cOff, cLen);
        s[0] ^= ((long) aadLen) * 8L;
        s[1] ^= ((long) cLen) * 8L;
        gmult(s);
        byte[] mask = aesEcb.doFinal(j0);
        byte[] t = new byte[16];
        putLong(s[0], t, 0);
        putLong(s[1], t, 8);
        for (int i = 0; i < 16; i++) {
            t[i] ^= mask[i];
        }
        return t;
    }

    private void ghash(long[] s, byte[] data, int off, int len) {
        byte[] block = new byte[16];
        for (int pos = 0; pos < len; pos += 16) {
            int n = Math.min(16, len - pos);
            if (n == 16) {
                s[0] ^= getLong(data, off + pos);
                s[1] ^= getLong(data, off + pos + 8);
            } else {
                java.util.Arrays.fill(block, (byte) 0);
                System.arraycopy(data, off + pos, block, 0, n);
                s[0] ^= getLong(block, 0);
                s[1] ^= getLong(block, 8);
            }
            gmult(s);
        }
    }

    /** s = s * H in GF(2^128), bit-reflected as in SP 800-38D; no data-dependent branches. */
    private void gmult(long[] s) {
        long z0 = 0, z1 = 0;
        long v0 = h0, v1 = h1;
        long x0 = s[0], x1 = s[1];
        for (int i = 0; i < 128; i++) {
            long bit = (i < 64) ? (x0 >>> (63 - i)) & 1 : (x1 >>> (127 - i)) & 1;
            long m = -bit;
            z0 ^= v0 & m;
            z1 ^= v1 & m;
            long lsb = -(v1 & 1);
            v1 = (v1 >>> 1) | (v0 << 63);
            v0 = (v0 >>> 1) ^ (0xe100000000000000L & lsb);
        }
        s[0] = z0;
        s[1] = z1;
    }

    private static void inc32(byte[] block) {
        for (int i = 15; i >= 12; i--) {
            if (++block[i] != 0) {
                break;
            }
        }
    }

    static long getLong(byte[] b, int off) {
        long v = 0;
        for (int i = 0; i < 8; i++) {
            v = (v << 8) | (b[off + i] & 0xffL);
        }
        return v;
    }

    static void putLong(long v, byte[] b, int off) {
        for (int i = 7; i >= 0; i--) {
            b[off + i] = (byte) v;
            v >>>= 8;
        }
    }
}
