package org.reteget.core.ssh;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Ed25519 signatures (RFC 8032): verification for SSH host keys, and key derivation and signing
 * for public-key user authentication.
 *
 * A port of TweetNaCl's crypto_sign (public domain), the same shape as the in-tree X25519:
 * field elements of GF(2^255 - 19) are 16 limbs of 16 bits held in longs. Scalar multiplication
 * is a fixed 256-step double-and-add with masked swaps, so it has no secret-dependent branches
 * or table lookups; Java gives no stronger timing guarantee than that. Only SHA-512 comes from
 * the platform.
 *
 * Verification is stricter than TweetNaCl's: S must be below the group order (no malleable
 * signatures) and a public key of small order is refused.
 */
public final class Ed25519 {

    public static final int PUBLIC_KEY_LEN = 32;
    public static final int SEED_LEN = 32;
    public static final int SIGNATURE_LEN = 64;

    private Ed25519() {}

    private static final long[] GF0 = new long[16];
    private static final long[] GF1 = { 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    private static final long[] D = { 0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070,
            0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee, 0x5203 };
    private static final long[] D2 = { 0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0,
            0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc, 0x2406 };
    private static final long[] BX = { 0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c,
            0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3, 0x2169 };
    private static final long[] BY = { 0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
            0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666 };
    private static final long[] SQRT_M1 = { 0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43,
            0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480, 0x2b83 };
    /** The group order L, little-endian bytes. */
    private static final int[] L = { 0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2,
            0xde, 0xf9, 0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10 };

    /** The public key for a 32-byte seed (the private key as OpenSSH and RFC 8032 store it). */
    public static byte[] publicKey(byte[] seed) {
        if (seed.length != SEED_LEN) throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        byte[] d = sha512(seed);
        clamp(d);
        long[][] p = point();
        scalarBase(p, d);
        java.util.Arrays.fill(d, (byte) 0);
        return pack(p);
    }

    /** The 64-byte signature R || S of {@code message}. */
    public static byte[] sign(byte[] seed, byte[] message) {
        if (seed.length != SEED_LEN) throw new IllegalArgumentException("Ed25519 seed must be 32 bytes");
        byte[] d = sha512(seed);
        clamp(d);
        long[][] p = point();
        scalarBase(p, d);
        byte[] pk = pack(p);

        MessageDigest md = sha512();
        md.update(d, 32, 32);
        byte[] r = md.digest(message);
        reduce(r);
        scalarBase(p, r);
        byte[] sig = new byte[SIGNATURE_LEN];
        System.arraycopy(pack(p), 0, sig, 0, 32);

        md.update(sig, 0, 32);
        md.update(pk);
        byte[] h = md.digest(message);
        reduce(h);

        long[] x = new long[64];
        for (int i = 0; i < 32; i++) x[i] = r[i] & 0xff;
        for (int i = 0; i < 32; i++) {
            for (int j = 0; j < 32; j++) {
                x[i + j] += (long) (h[i] & 0xff) * (d[j] & 0xff);
            }
        }
        byte[] s = new byte[32];
        modL(s, x);
        System.arraycopy(s, 0, sig, 32, 32);
        java.util.Arrays.fill(d, (byte) 0);
        java.util.Arrays.fill(r, (byte) 0);
        java.util.Arrays.fill(x, 0L);
        return sig;
    }

    /** True when {@code signature} is a valid Ed25519 signature of {@code message} by {@code publicKey}. */
    public static boolean verify(byte[] publicKey, byte[] message, byte[] signature) {
        if (publicKey == null || signature == null || message == null) return false;
        if (publicKey.length != PUBLIC_KEY_LEN || signature.length != SIGNATURE_LEN) return false;
        if (!scalarBelowL(signature, 32)) return false;

        long[][] q = point();
        if (!unpackNeg(q, publicKey)) return false;
        if (isSmallOrder(q)) return false;

        MessageDigest md = sha512();
        md.update(signature, 0, 32);
        md.update(publicKey);
        byte[] h = md.digest(message);
        reduce(h);

        long[][] p = point();
        scalarMult(p, q, h);
        byte[] s = new byte[32];
        System.arraycopy(signature, 32, s, 0, 32);
        scalarBase(q, s);
        add(p, q);
        byte[] t = pack(p);
        int diff = 0;
        for (int i = 0; i < 32; i++) diff |= t[i] ^ signature[i];
        return diff == 0;
    }

    // --- scalars mod L ---

    private static void clamp(byte[] d) {
        d[0] &= (byte) 248;
        d[31] &= 127;
        d[31] |= 64;
    }

    /** True when the 32 little-endian bytes at {@code off} are a number below L. */
    private static boolean scalarBelowL(byte[] b, int off) {
        for (int i = 31; i >= 0; i--) {
            int v = b[off + i] & 0xff;
            if (v < L[i]) return true;
            if (v > L[i]) return false;
        }
        return false;
    }

    private static void modL(byte[] r, long[] x) {
        long carry;
        for (int i = 63; i >= 32; i--) {
            carry = 0;
            int j;
            for (j = i - 32; j < i - 12; j++) {
                x[j] += carry - 16 * x[i] * L[j - (i - 32)];
                carry = (x[j] + 128) >> 8;
                x[j] -= carry << 8;
            }
            x[j] += carry;
            x[i] = 0;
        }
        carry = 0;
        for (int j = 0; j < 32; j++) {
            x[j] += carry - (x[31] >> 4) * L[j];
            carry = x[j] >> 8;
            x[j] &= 255;
        }
        for (int j = 0; j < 32; j++) x[j] -= carry * L[j];
        for (int i = 0; i < 32; i++) {
            x[i + 1] += x[i] >> 8;
            r[i] = (byte) (x[i] & 255);
        }
    }

    /** Reduces a 64-byte little-endian number mod L in place (the result is in the first 32 bytes). */
    private static void reduce(byte[] r) {
        long[] x = new long[64];
        for (int i = 0; i < 64; i++) x[i] = r[i] & 0xff;
        java.util.Arrays.fill(r, (byte) 0);
        modL(r, x);
    }

    // --- points (extended coordinates X, Y, Z, T) ---

    private static long[][] point() {
        return new long[][] { new long[16], new long[16], new long[16], new long[16] };
    }

    private static void add(long[][] p, long[][] q) {
        long[] a = new long[16], b = new long[16], c = new long[16], d = new long[16], t = new long[16];
        long[] e = new long[16], f = new long[16], g = new long[16], h = new long[16];
        sub(a, p[1], p[0]);
        sub(t, q[1], q[0]);
        mul(a, a, t);
        add(b, p[0], p[1]);
        add(t, q[0], q[1]);
        mul(b, b, t);
        mul(c, p[3], q[3]);
        mul(c, c, D2);
        mul(d, p[2], q[2]);
        add(d, d, d);
        sub(e, b, a);
        sub(f, d, c);
        add(g, d, c);
        add(h, b, a);
        mul(p[0], e, f);
        mul(p[1], h, g);
        mul(p[2], g, f);
        mul(p[3], e, h);
    }

    private static void cswap(long[][] p, long[][] q, int bit) {
        for (int i = 0; i < 4; i++) sel(p[i], q[i], bit);
    }

    private static byte[] pack(long[][] p) {
        long[] tx = new long[16], ty = new long[16], zi = new long[16];
        invert(zi, p[2]);
        mul(tx, p[0], zi);
        mul(ty, p[1], zi);
        byte[] r = pack25519(ty);
        r[31] ^= (byte) (parity(tx) << 7);
        return r;
    }

    /** p = s * q; q is overwritten. */
    private static void scalarMult(long[][] p, long[][] q, byte[] s) {
        set(p[0], GF0);
        set(p[1], GF1);
        set(p[2], GF1);
        set(p[3], GF0);
        for (int i = 255; i >= 0; i--) {
            int b = (s[i >>> 3] >>> (i & 7)) & 1;
            cswap(p, q, b);
            add(q, p);
            add(p, p);
            cswap(p, q, b);
        }
    }

    private static void scalarBase(long[][] p, byte[] s) {
        long[][] q = point();
        set(q[0], BX);
        set(q[1], BY);
        set(q[2], GF1);
        mul(q[3], BX, BY);
        scalarMult(p, q, s);
    }

    /** Decodes a public key into r as the negated point; false when it is not on the curve. */
    private static boolean unpackNeg(long[][] r, byte[] p) {
        long[] t = new long[16], chk = new long[16], num = new long[16], den = new long[16];
        long[] den2 = new long[16], den4 = new long[16], den6 = new long[16];
        set(r[2], GF1);
        unpack25519(r[1], p);
        mul(num, r[1], r[1]);
        mul(den, num, D);
        sub(num, num, r[2]);
        add(den, r[2], den);

        mul(den2, den, den);
        mul(den4, den2, den2);
        mul(den6, den4, den2);
        mul(t, den6, num);
        mul(t, t, den);

        pow2523(t, t);
        mul(t, t, num);
        mul(t, t, den);
        mul(t, t, den);
        mul(r[0], t, den);

        mul(chk, r[0], r[0]);
        mul(chk, chk, den);
        if (neq(chk, num)) mul(r[0], r[0], SQRT_M1);

        mul(chk, r[0], r[0]);
        mul(chk, chk, den);
        if (neq(chk, num)) return false;

        if (parity(r[0]) == ((p[31] & 0xff) >>> 7)) sub(r[0], GF0, r[0]);
        mul(r[3], r[0], r[1]);
        return true;
    }

    /** True when 8 * q is the neutral element. */
    private static boolean isSmallOrder(long[][] q) {
        long[][] t = point();
        for (int i = 0; i < 4; i++) set(t[i], q[i]);
        add(t, t);
        add(t, t);
        add(t, t);
        byte[] enc = pack(t);
        int acc = (enc[0] & 0xff) ^ 1;
        for (int i = 1; i < 32; i++) acc |= enc[i] & 0xff;
        return acc == 0;
    }

    // --- field arithmetic mod 2^255 - 19 ---

    private static void set(long[] r, long[] a) {
        System.arraycopy(a, 0, r, 0, 16);
    }

    private static void carry(long[] o) {
        for (int i = 0; i < 16; i++) {
            o[i] += 1L << 16;
            long c = o[i] >> 16;
            if (i < 15) {
                o[i + 1] += c - 1;
            } else {
                o[0] += 38 * (c - 1);
            }
            o[i] -= c << 16;
        }
    }

    /** Swaps p and q when bit == 1, using a mask instead of a branch. */
    private static void sel(long[] p, long[] q, int bit) {
        long mask = -(long) bit;
        for (int i = 0; i < 16; i++) {
            long t = mask & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static byte[] pack25519(long[] n) {
        long[] t = n.clone();
        long[] m = new long[16];
        carry(t);
        carry(t);
        carry(t);
        for (int j = 0; j < 2; j++) {
            m[0] = t[0] - 0xffed;
            for (int i = 1; i < 15; i++) {
                m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
                m[i - 1] &= 0xffff;
            }
            m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
            int borrow = (int) ((m[15] >> 16) & 1);
            m[14] &= 0xffff;
            sel(t, m, 1 - borrow);
        }
        byte[] o = new byte[32];
        for (int i = 0; i < 16; i++) {
            o[2 * i] = (byte) t[i];
            o[2 * i + 1] = (byte) (t[i] >> 8);
        }
        return o;
    }

    private static boolean neq(long[] a, long[] b) {
        byte[] c = pack25519(a);
        byte[] d = pack25519(b);
        int diff = 0;
        for (int i = 0; i < 32; i++) diff |= c[i] ^ d[i];
        return diff != 0;
    }

    private static int parity(long[] a) {
        return pack25519(a)[0] & 1;
    }

    private static void unpack25519(long[] o, byte[] n) {
        for (int i = 0; i < 16; i++) {
            o[i] = (n[2 * i] & 0xff) + ((long) (n[2 * i + 1] & 0xff) << 8);
        }
        o[15] &= 0x7fff;
    }

    private static void add(long[] o, long[] a, long[] b) {
        for (int i = 0; i < 16; i++) o[i] = a[i] + b[i];
    }

    private static void sub(long[] o, long[] a, long[] b) {
        for (int i = 0; i < 16; i++) o[i] = a[i] - b[i];
    }

    private static void mul(long[] o, long[] a, long[] b) {
        long[] t = new long[31];
        for (int i = 0; i < 16; i++) {
            for (int j = 0; j < 16; j++) {
                t[i + j] += a[i] * b[j];
            }
        }
        for (int i = 0; i < 15; i++) {
            t[i] += 38 * t[i + 16]; // 2^256 = 38 mod p
        }
        System.arraycopy(t, 0, o, 0, 16);
        carry(o);
        carry(o);
    }

    private static void invert(long[] o, long[] i) {
        long[] c = i.clone();
        for (int a = 253; a >= 0; a--) {
            mul(c, c, c);
            if (a != 2 && a != 4) mul(c, c, i);
        }
        System.arraycopy(c, 0, o, 0, 16);
    }

    private static void pow2523(long[] o, long[] i) {
        long[] c = i.clone();
        for (int a = 250; a >= 0; a--) {
            mul(c, c, c);
            if (a != 1) mul(c, c, i);
        }
        System.arraycopy(c, 0, o, 0, 16);
    }

    private static MessageDigest sha512() {
        try {
            return MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] sha512(byte[] in) {
        return sha512().digest(in);
    }
}
