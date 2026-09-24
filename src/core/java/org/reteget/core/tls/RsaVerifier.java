package org.reteget.core.tls;

import java.math.BigInteger;
import java.security.MessageDigest;

/**
 * RSA signature verification (RFC 8017): RSASSA-PSS and RSASSA-PKCS1-v1_5.
 *
 * Only public-key operations exist here, so BigInteger is appropriate. PSS is
 * implemented directly because "SHA256withRSA/PSS" is absent before Android 6.
 */
public final class RsaVerifier {

    public static final int MIN_BITS = 2048;
    public static final int MAX_BITS = 8192;

    private RsaVerifier() {}

    private static BigInteger checkedPublicOp(BigInteger n, BigInteger e, byte[] sig, int minBits) {
        int bits = n.bitLength();
        if (bits < minBits || bits > MAX_BITS) {
            throw new IllegalArgumentException("RSA modulus size " + bits + " not supported");
        }
        if (e.signum() <= 0 || !e.testBit(0) || e.compareTo(BigInteger.valueOf(3)) < 0) {
            throw new IllegalArgumentException("RSA public exponent invalid");
        }
        if (sig.length != (bits + 7) / 8) {
            return null;
        }
        BigInteger s = new BigInteger(1, sig);
        if (s.compareTo(n) >= 0) {
            return null;
        }
        return s.modPow(e, n);
    }

    /** EMSA-PSS-VERIFY with MGF1 over the same hash and the given salt length. */
    public static boolean verifyPss(BigInteger n, BigInteger e, String hashAlg, int saltLen,
                                    byte[] message, byte[] sig) throws Exception {
        return verifyPss(n, e, hashAlg, saltLen, message, sig, MIN_BITS);
    }

    static boolean verifyPss(BigInteger n, BigInteger e, String hashAlg, int saltLen,
                             byte[] message, byte[] sig, int minBits) throws Exception {
        BigInteger m = checkedPublicOp(n, e, sig, minBits);
        if (m == null) return false;
        int emBits = n.bitLength() - 1;
        int emLen = (emBits + 7) / 8;
        byte[] em = toFixed(m, emLen);
        if (em == null) return false;

        MessageDigest md = MessageDigest.getInstance(hashAlg);
        int hLen = md.getDigestLength();
        byte[] mHash = md.digest(message);
        if (emLen < hLen + saltLen + 2) return false;
        if ((em[emLen - 1] & 0xff) != 0xbc) return false;

        int dbLen = emLen - hLen - 1;
        byte[] db = new byte[dbLen];
        System.arraycopy(em, 0, db, 0, dbLen);
        byte[] h = new byte[hLen];
        System.arraycopy(em, dbLen, h, 0, hLen);

        int unusedBits = 8 * emLen - emBits;
        int topMask = (0xff << (8 - unusedBits)) & 0xff;
        if ((db[0] & topMask) != 0) return false;

        byte[] mask = mgf1(hashAlg, h, dbLen);
        for (int i = 0; i < dbLen; i++) {
            db[i] ^= mask[i];
        }
        db[0] &= (byte) (0xff >>> unusedBits);

        int psLen = emLen - hLen - saltLen - 2;
        for (int i = 0; i < psLen; i++) {
            if (db[i] != 0) return false;
        }
        if (db[psLen] != 0x01) return false;

        md.reset();
        md.update(new byte[8]);
        md.update(mHash);
        md.update(db, dbLen - saltLen, saltLen);
        byte[] h2 = md.digest();
        return MessageDigest.isEqual(h, h2);
    }

    /** EMSA-PKCS1-v1_5 with an exact comparison of the whole encoded block. */
    public static boolean verifyPkcs1(BigInteger n, BigInteger e, String hashAlg,
                                      byte[] message, byte[] sig) throws Exception {
        return verifyPkcs1(n, e, hashAlg, message, sig, MIN_BITS);
    }

    static boolean verifyPkcs1(BigInteger n, BigInteger e, String hashAlg,
                               byte[] message, byte[] sig, int minBits) throws Exception {
        BigInteger m = checkedPublicOp(n, e, sig, minBits);
        if (m == null) return false;
        int k = (n.bitLength() + 7) / 8;
        byte[] em = toFixed(m, k);
        if (em == null) return false;

        byte[] prefix = digestInfoPrefix(hashAlg);
        byte[] hash = MessageDigest.getInstance(hashAlg).digest(message);
        int tLen = prefix.length + hash.length;
        if (k < tLen + 11) return false;
        byte[] expected = new byte[k];
        expected[0] = 0x00;
        expected[1] = 0x01;
        for (int i = 2; i < k - tLen - 1; i++) {
            expected[i] = (byte) 0xff;
        }
        expected[k - tLen - 1] = 0x00;
        System.arraycopy(prefix, 0, expected, k - tLen, prefix.length);
        System.arraycopy(hash, 0, expected, k - hash.length, hash.length);
        return MessageDigest.isEqual(expected, em);
    }

    static byte[] mgf1(String hashAlg, byte[] seed, int len) throws Exception {
        MessageDigest md = MessageDigest.getInstance(hashAlg);
        byte[] out = new byte[len];
        int pos = 0;
        for (int counter = 0; pos < len; counter++) {
            md.reset();
            md.update(seed);
            md.update(new byte[] { (byte) (counter >>> 24), (byte) (counter >>> 16),
                    (byte) (counter >>> 8), (byte) counter });
            byte[] block = md.digest();
            int n = Math.min(block.length, len - pos);
            System.arraycopy(block, 0, out, pos, n);
            pos += n;
        }
        return out;
    }

    private static byte[] toFixed(BigInteger v, int len) {
        byte[] raw = v.toByteArray();
        int start = 0;
        while (start < raw.length - 1 && raw[start] == 0) start++;
        int n = raw.length - start;
        if (n > len) return null;
        byte[] out = new byte[len];
        System.arraycopy(raw, start, out, len - n, n);
        return out;
    }

    private static byte[] digestInfoPrefix(String hashAlg) {
        if ("SHA-256".equals(hashAlg)) {
            return hex("3031300d060960864801650304020105000420");
        } else if ("SHA-384".equals(hashAlg)) {
            return hex("3041300d060960864801650304020205000430");
        } else if ("SHA-512".equals(hashAlg)) {
            return hex("3051300d060960864801650304020305000440");
        }
        throw new IllegalArgumentException("unsupported PKCS#1 hash " + hashAlg);
    }

    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) {
            b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        }
        return b;
    }
}
