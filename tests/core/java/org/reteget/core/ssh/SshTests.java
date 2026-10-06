package org.reteget.core.ssh;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/** The in-tree SSH client: primitives first, then the protocol against a JDK-crypto test server. */
public final class SshTests {

    public static int passed = 0;
    public static int failed = 0;

    private SshTests() {}

    public static void run() {
        System.out.println("\n[SSH / SFTP]");
        testEd25519Vectors();
        testEd25519AgainstJdk();
        testEd25519Rejections();
        testAesCtr();
        testWireTypes();
    }

    static void check(String msg, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("  PASS: " + msg);
        } else {
            failed++;
            System.err.println("  FAIL: " + msg);
        }
    }

    static void checkEq(String msg, Object expected, Object actual) {
        boolean ok = expected == null ? actual == null : expected.equals(actual);
        if (ok) {
            passed++;
            System.out.println("  PASS: " + msg);
        } else {
            failed++;
            System.err.println("  FAIL: " + msg + " (expected [" + expected + "], got [" + actual + "])");
        }
    }

    static byte[] hex(String s) {
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    // --- Ed25519 ---

    private static void vector(String name, String seed, String pk, String msg, String sig) {
        checkEq("Ed25519 " + name + ": public key", pk, hex(Ed25519.publicKey(hex(seed))));
        checkEq("Ed25519 " + name + ": signature", sig, hex(Ed25519.sign(hex(seed), hex(msg))));
        check("Ed25519 " + name + ": verifies", Ed25519.verify(hex(pk), hex(msg), hex(sig)));
    }

    private static void testEd25519Vectors() {
        // RFC 8032 section 7.1
        vector("RFC 8032 test 1", "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                        + "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b");
        vector("RFC 8032 test 2", "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
                        + "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00");
        vector("RFC 8032 test 3", "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac"
                        + "18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a");
    }

    /** The JDK's Ed25519 (JDK 15+) signs for our verifier and verifies our signatures. */
    private static void testEd25519AgainstJdk() {
        try {
            KeyPairGenerator g = KeyPairGenerator.getInstance("Ed25519");
            Random rnd = new Random(1);
            boolean oursVerifyJdk = true, jdkVerifiesOurs = true;
            for (int i = 0; i < 6; i++) {
                KeyPair kp = g.generateKeyPair();
                byte[] spki = kp.getPublic().getEncoded();
                byte[] pk = Arrays.copyOfRange(spki, spki.length - 32, spki.length);
                byte[] msg = new byte[i * 37];
                rnd.nextBytes(msg);
                Signature s = Signature.getInstance("Ed25519");
                s.initSign(kp.getPrivate());
                s.update(msg);
                oursVerifyJdk &= Ed25519.verify(pk, msg, s.sign());

                byte[] seed = new byte[32];
                rnd.nextBytes(seed);
                byte[] ourPk = Ed25519.publicKey(seed);
                byte[] prefix = hex("302a300506032b6570032100");
                byte[] enc = new byte[prefix.length + 32];
                System.arraycopy(prefix, 0, enc, 0, prefix.length);
                System.arraycopy(ourPk, 0, enc, prefix.length, 32);
                PublicKey jp = KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(enc));
                Signature v = Signature.getInstance("Ed25519");
                v.initVerify(jp);
                v.update(msg);
                jdkVerifiesOurs &= v.verify(Ed25519.sign(seed, msg));
            }
            check("Ed25519: verifies signatures made by the JDK", oursVerifyJdk);
            check("Ed25519: the JDK verifies our signatures", jdkVerifiesOurs);
        } catch (java.security.NoSuchAlgorithmException e) {
            System.out.println("  SKIP: this JDK has no Ed25519 (needs 15+)");
        } catch (Exception e) {
            check("Ed25519 against the JDK: " + e, false);
        }
    }

    private static void testEd25519Rejections() {
        byte[] seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
        byte[] pk = Ed25519.publicKey(seed);
        byte[] msg = "host key check".getBytes();
        byte[] sig = Ed25519.sign(seed, msg);
        check("Ed25519: good signature", Ed25519.verify(pk, msg, sig));
        byte[] bad = sig.clone();
        bad[5] ^= 1;
        check("Ed25519: altered R refused", !Ed25519.verify(pk, msg, bad));
        bad = sig.clone();
        bad[40] ^= 1;
        check("Ed25519: altered S refused", !Ed25519.verify(pk, msg, bad));
        check("Ed25519: other message refused", !Ed25519.verify(pk, "host key chec".getBytes(), sig));
        byte[] otherPk = Ed25519.publicKey(hex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb"));
        check("Ed25519: other key refused", !Ed25519.verify(otherPk, msg, sig));

        // S + L is the same scalar mod L: a malleable copy must not verify.
        BigInteger l = new BigInteger("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed", 16);
        byte[] sLe = Arrays.copyOfRange(sig, 32, 64);
        byte[] sBe = new byte[32];
        for (int i = 0; i < 32; i++) sBe[i] = sLe[31 - i];
        byte[] sum = new BigInteger(1, sBe).add(l).toByteArray();
        byte[] mall = sig.clone();
        for (int i = 0; i < 32; i++) mall[32 + i] = i < sum.length ? sum[sum.length - 1 - i] : 0;
        check("Ed25519: S >= L refused", !Ed25519.verify(pk, msg, mall));

        byte[] neutral = new byte[32];
        neutral[0] = 1; // the point (0, 1), order 1
        check("Ed25519: small-order public key refused", !Ed25519.verify(neutral, msg, new byte[64]));
        byte[] order2 = hex("ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"); // (0, -1)
        check("Ed25519: order-2 public key refused", !Ed25519.verify(order2, msg, new byte[64]));
        byte[] offCurve = hex("0200000000000000000000000000000000000000000000000000000000000000");
        check("Ed25519: point off the curve refused", !Ed25519.verify(offCurve, msg, sig));
        check("Ed25519: wrong lengths refused", !Ed25519.verify(new byte[31], msg, sig) && !Ed25519.verify(pk, msg, new byte[63]));
    }

    // --- AES-CTR ---

    private static void testAesCtr() {
        try {
            // NIST SP 800-38A F.5.1 CTR-AES128.Encrypt
            byte[] key = hex("2b7e151628aed2a6abf7158809cf4f3c");
            byte[] iv = hex("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            byte[] pt = hex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
                    + "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710");
            byte[] out = new byte[pt.length];
            new AesCtr(key, iv).process(pt, 0, pt.length, out, 0);
            checkEq("AES-CTR: SP 800-38A F.5.1", "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"
                    + "5ae4df3edbd5d35e5b4f09020db03eab1e031dda2fbe03d1792170a0f3009cee", hex(out));

            // In odd-sized pieces, with a counter that carries across bytes, against the JDK.
            Random rnd = new Random(7);
            byte[] k256 = new byte[32];
            rnd.nextBytes(k256);
            byte[] iv2 = hex("00000000000000000000000000fffffe");
            byte[] data = new byte[1000];
            rnd.nextBytes(data);
            Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k256, "AES"), new IvParameterSpec(iv2));
            byte[] expect = c.doFinal(data);
            AesCtr ours = new AesCtr(k256, iv2);
            byte[] got = new byte[data.length];
            int pos = 0;
            int step = 1;
            while (pos < data.length) {
                int n = Math.min(step, data.length - pos);
                ours.process(data, pos, n, got, pos);
                pos += n;
                step = step * 3 % 41 + 1;
            }
            check("AES-256-CTR: streamed in pieces equals the JDK", Arrays.equals(expect, got));
        } catch (Exception e) {
            check("AES-CTR: " + e, false);
        }
    }

    // --- wire types ---

    private static void testWireTypes() {
        try {
            // RFC 4251 section 5 mpint examples
            checkEq("mpint 0", "00000000", hex(new SshBuf.Writer().mpint(BigInteger.ZERO).bytes()));
            checkEq("mpint 9a378f9b2e332a7", "0000000809a378f9b2e332a7",
                    hex(new SshBuf.Writer().mpint(new BigInteger("9a378f9b2e332a7", 16)).bytes()));
            checkEq("mpint 80", "000000020080", hex(new SshBuf.Writer().mpint(BigInteger.valueOf(0x80)).bytes()));
            checkEq("mpint from unsigned bytes with leading zeros", "000000020080",
                    hex(new SshBuf.Writer().mpint(new byte[] { 0, 0, (byte) 0x80 }).bytes()));
            byte[] msg = new SshBuf.Writer().u8(20).bool(true).u32(0xfffffffeL).u64(0x0102030405060708L)
                    .string("zlib,none").nameList(new String[] { "a", "b" }).mpint(BigInteger.valueOf(255)).bytes();
            SshBuf.Reader r = new SshBuf.Reader(msg);
            check("wire round trip", r.u8() == 20 && r.bool() && r.u32() == 0xfffffffeL && r.u64() == 0x0102030405060708L
                    && Arrays.equals(new String[] { "zlib", "none" }, r.nameList()) && r.nameList().length == 2
                    && r.mpint().intValue() == 255 && r.remaining() == 0);
            checkEq("empty name-list", 0, new SshBuf.Reader(new byte[4]).nameList().length);
            boolean threw = false;
            try {
                new SshBuf.Reader(hex("0000000a0102")).string();
            } catch (SshException e) {
                threw = true;
            }
            check("string longer than the message is refused", threw);
            threw = false;
            try {
                new SshBuf.Reader(hex("ffffffff")).string();
            } catch (SshException e) {
                threw = true;
            }
            check("huge string length is refused", threw);
            threw = false;
            try {
                new SshBuf.Reader(hex("0000000180")).mpint();
            } catch (SshException e) {
                threw = true;
            }
            check("negative mpint is refused", threw);
        } catch (Exception e) {
            check("wire types: " + e, false);
        }
    }
}
