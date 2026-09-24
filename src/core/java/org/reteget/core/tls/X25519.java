package org.reteget.core.tls;

/**
 * X25519 Diffie-Hellman (RFC 7748).
 *
 * Field elements of GF(2^255 - 19) are 16 limbs of 16 bits held in longs, so every
 * product fits a signed 64-bit accumulator. The Montgomery ladder runs a fixed 255
 * steps with masked conditional swaps and no secret-dependent branches or lookups.
 */
public final class X25519 {

    public static final int KEY_LEN = 32;

    private static final long[] A24 = { 0xdb41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    private static final byte[] BASE = new byte[32];
    static {
        BASE[0] = 9;
    }

    private X25519() {}

    public static byte[] publicKey(byte[] privateKey) {
        return scalarMult(privateKey, BASE);
    }

    /**
     * Returns the 32-byte shared value. Callers must reject an all-zero result
     * (RFC 8446 section 7.4.2) with {@link #isAllZero}.
     */
    public static byte[] scalarMult(byte[] scalar, byte[] uCoordinate) {
        if (scalar.length != KEY_LEN || uCoordinate.length != KEY_LEN) {
            throw new IllegalArgumentException("X25519 inputs must be 32 bytes");
        }
        byte[] z = scalar.clone();
        z[31] = (byte) ((z[31] & 127) | 64);
        z[0] &= (byte) 248;

        long[] x = unpack(uCoordinate);
        long[] a = new long[16], b = x.clone(), c = new long[16], d = new long[16];
        long[] e = new long[16], f = new long[16];
        a[0] = 1;
        d[0] = 1;
        for (int i = 254; i >= 0; i--) {
            int r = (z[i >>> 3] >>> (i & 7)) & 1;
            swap(a, b, r);
            swap(c, d, r);
            add(e, a, c);
            sub(a, a, c);
            add(c, b, d);
            sub(b, b, d);
            mul(d, e, e);
            mul(f, a, a);
            mul(a, c, a);
            mul(c, b, e);
            add(e, a, c);
            sub(a, a, c);
            mul(b, a, a);
            sub(c, d, f);
            mul(a, c, A24);
            add(a, a, d);
            mul(c, c, a);
            mul(a, d, f);
            mul(d, b, x);
            mul(b, e, e);
            swap(a, b, r);
            swap(c, d, r);
        }
        invert(c, c);
        mul(a, a, c);
        java.util.Arrays.fill(z, (byte) 0);
        return pack(a);
    }

    public static boolean isAllZero(byte[] v) {
        int acc = 0;
        for (int i = 0; i < v.length; i++) {
            acc |= v[i];
        }
        return acc == 0;
    }

    private static long[] unpack(byte[] n) {
        long[] o = new long[16];
        for (int i = 0; i < 16; i++) {
            o[i] = (n[2 * i] & 0xff) + ((long) (n[2 * i + 1] & 0xff) << 8);
        }
        o[15] &= 0x7fff; // RFC 7748: mask the most significant bit of u
        return o;
    }

    private static byte[] pack(long[] n) {
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
            swap(t, m, 1 - borrow);
        }
        byte[] o = new byte[32];
        for (int i = 0; i < 16; i++) {
            o[2 * i] = (byte) t[i];
            o[2 * i + 1] = (byte) (t[i] >> 8);
        }
        return o;
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
    private static void swap(long[] p, long[] q, int bit) {
        long mask = -(long) bit;
        for (int i = 0; i < 16; i++) {
            long t = mask & (p[i] ^ q[i]);
            p[i] ^= t;
            q[i] ^= t;
        }
    }

    private static void add(long[] o, long[] a, long[] b) {
        for (int i = 0; i < 16; i++) {
            o[i] = a[i] + b[i];
        }
    }

    private static void sub(long[] o, long[] a, long[] b) {
        for (int i = 0; i < 16; i++) {
            o[i] = a[i] - b[i];
        }
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

    /** o = i^(p-2) by the fixed addition chain for p - 2 = 2^255 - 21. */
    private static void invert(long[] o, long[] i) {
        long[] c = i.clone();
        for (int a = 253; a >= 0; a--) {
            mul(c, c, c);
            if (a != 2 && a != 4) {
                mul(c, c, i);
            }
        }
        System.arraycopy(c, 0, o, 0, 16);
    }
}
