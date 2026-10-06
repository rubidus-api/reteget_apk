package org.reteget.core.ssh;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * bcrypt_pbkdf, the key derivation OpenSSH uses for passphrase-protected private key files
 * (OpenBSD's bcrypt_pbkdf.c: PBKDF2 with SHA-512 around a bcrypt core), and the Blowfish it
 * needs.
 *
 * <p>Blowfish's initial state is the first 1042 words of the fractional part of pi in
 * hexadecimal. Instead of carrying that table (8 KB of constants that a typing slip would
 * silently break), it is computed once on first use with Machin's formula; the tests compare
 * the resulting cipher with the JDK's Blowfish.
 */
final class BcryptPbkdf {

    private BcryptPbkdf() {}

    private static final int WORDS = 18 + 4 * 256;
    private static int[] piWords;

    /** The first 1042 32-bit words of pi's fractional part. */
    private static synchronized int[] piWords() {
        if (piWords != null) return piWords;
        int bits = WORDS * 32;
        int guard = 64;
        BigInteger one = BigInteger.ONE.shiftLeft(bits + guard);
        // pi = 16 arctan(1/5) - 4 arctan(1/239)
        BigInteger pi = arctanInverse(5, one).shiftLeft(4).subtract(arctanInverse(239, one).shiftLeft(2));
        BigInteger frac = pi.subtract(BigInteger.valueOf(3).shiftLeft(bits + guard)).shiftRight(guard);
        byte[] b = frac.toByteArray();
        byte[] fixed = new byte[WORDS * 4];
        int n = Math.min(b.length, fixed.length);
        System.arraycopy(b, b.length - n, fixed, fixed.length - n, n);
        int[] w = new int[WORDS];
        for (int i = 0; i < WORDS; i++) {
            w[i] = ((fixed[4 * i] & 0xff) << 24) | ((fixed[4 * i + 1] & 0xff) << 16)
                    | ((fixed[4 * i + 2] & 0xff) << 8) | (fixed[4 * i + 3] & 0xff);
        }
        piWords = w;
        return w;
    }

    /** arctan(1/x) scaled by {@code one}. */
    private static BigInteger arctanInverse(int x, BigInteger one) {
        BigInteger xSquared = BigInteger.valueOf((long) x * x);
        BigInteger term = one.divide(BigInteger.valueOf(x));
        BigInteger sum = term;
        for (int k = 1; term.signum() != 0; k++) {
            term = term.divide(xSquared);
            BigInteger part = term.divide(BigInteger.valueOf(2L * k + 1));
            sum = (k & 1) == 1 ? sum.subtract(part) : sum.add(part);
        }
        return sum;
    }

    /** Blowfish with the "expensive key setup" operations bcrypt is built from. */
    static final class Blowfish {
        final int[] p = new int[18];
        final int[] s = new int[4 * 256];
        private int l, r;

        Blowfish() {
            int[] pi = piWords();
            System.arraycopy(pi, 0, p, 0, 18);
            System.arraycopy(pi, 18, s, 0, 4 * 256);
        }

        /** The standard key schedule (for the comparison with other implementations). */
        Blowfish(byte[] key) {
            this();
            expand0(key);
        }

        private void encipher() {
            int xl = l, xr = r;
            xl ^= p[0];
            for (int i = 1; i <= 16; i += 2) {
                xr ^= f(xl) ^ p[i];
                xl ^= f(xr) ^ p[i + 1];
            }
            l = xr ^ p[17];
            r = xl;
        }

        private int f(int x) {
            return ((s[x >>> 24] + s[256 + ((x >>> 16) & 0xff)]) ^ s[512 + ((x >>> 8) & 0xff)]) + s[768 + (x & 0xff)];
        }

        /** Encrypts {@code blocks} 64-bit blocks held as pairs of words, in place. */
        void encrypt(int[] data, int blocks) {
            for (int i = 0; i < blocks; i++) {
                l = data[2 * i];
                r = data[2 * i + 1];
                encipher();
                data[2 * i] = l;
                data[2 * i + 1] = r;
            }
        }

        private static int word(byte[] d, int[] pos) {
            int w = 0;
            for (int i = 0; i < 4; i++) {
                w = (w << 8) | (d[pos[0]] & 0xff);
                pos[0] = (pos[0] + 1) % d.length;
            }
            return w;
        }

        void expand0(byte[] key) {
            int[] pos = { 0 };
            for (int i = 0; i < 18; i++) p[i] ^= word(key, pos);
            l = 0;
            r = 0;
            for (int i = 0; i < 18; i += 2) {
                encipher();
                p[i] = l;
                p[i + 1] = r;
            }
            for (int i = 0; i < 4 * 256; i += 2) {
                encipher();
                s[i] = l;
                s[i + 1] = r;
            }
        }

        void expand(byte[] data, byte[] key) {
            int[] pos = { 0 };
            for (int i = 0; i < 18; i++) p[i] ^= word(key, pos);
            pos[0] = 0;
            l = 0;
            r = 0;
            for (int i = 0; i < 18; i += 2) {
                l ^= word(data, pos);
                r ^= word(data, pos);
                encipher();
                p[i] = l;
                p[i + 1] = r;
            }
            for (int i = 0; i < 4 * 256; i += 2) {
                l ^= word(data, pos);
                r ^= word(data, pos);
                encipher();
                s[i] = l;
                s[i + 1] = r;
            }
        }
    }

    private static final byte[] MAGIC = SshBuf.utf8("OxychromaticBlowfishSwatDynamite");

    private static byte[] bcryptHash(byte[] sha2pass, byte[] sha2salt) {
        Blowfish b = new Blowfish();
        b.expand(sha2salt, sha2pass);
        for (int i = 0; i < 64; i++) {
            b.expand0(sha2salt);
            b.expand0(sha2pass);
        }
        int[] c = new int[8];
        int[] pos = { 0 };
        for (int i = 0; i < 8; i++) c[i] = Blowfish.word(MAGIC, pos);
        for (int i = 0; i < 64; i++) b.encrypt(c, 4);
        byte[] out = new byte[32];
        for (int i = 0; i < 8; i++) { // each word little-endian
            out[4 * i + 3] = (byte) (c[i] >>> 24);
            out[4 * i + 2] = (byte) (c[i] >>> 16);
            out[4 * i + 1] = (byte) (c[i] >>> 8);
            out[4 * i] = (byte) c[i];
        }
        return out;
    }

    /** Derives {@code keyLen} bytes from a passphrase and salt with the given number of rounds. */
    static byte[] derive(byte[] passphrase, byte[] salt, int rounds, int keyLen) {
        if (rounds < 1 || passphrase.length == 0 || salt.length == 0 || keyLen <= 0 || keyLen > 1024) {
            throw new IllegalArgumentException("invalid bcrypt_pbkdf parameters");
        }
        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-512");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
        byte[] key = new byte[keyLen];
        int stride = (keyLen + 32 - 1) / 32;
        int amt = (keyLen + stride - 1) / stride;
        byte[] sha2pass = sha.digest(passphrase);
        int remaining = keyLen;
        for (int count = 1; remaining > 0; count++) {
            sha.update(salt);
            sha.update(new byte[] { (byte) (count >>> 24), (byte) (count >>> 16), (byte) (count >>> 8), (byte) count });
            byte[] sha2salt = sha.digest();
            byte[] tmp = bcryptHash(sha2pass, sha2salt);
            byte[] out = tmp.clone();
            for (int i = 1; i < rounds; i++) {
                sha2salt = sha.digest(tmp);
                tmp = bcryptHash(sha2pass, sha2salt);
                for (int j = 0; j < 32; j++) out[j] ^= tmp[j];
            }
            amt = Math.min(amt, remaining);
            int i;
            for (i = 0; i < amt; i++) {
                int dest = i * stride + (count - 1);
                if (dest >= keyLen) break;
                key[dest] = out[i];
            }
            remaining -= i;
        }
        return key;
    }
}
