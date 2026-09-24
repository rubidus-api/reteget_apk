package org.reteget.core.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Tests for the in-tree TLS engines: known-answer vectors from RFC 5869, RFC 7748 and
 * RFC 8448, cross-checks against the desktop JDK's own implementations, a byte-exact
 * replay of the RFC 8448 handshake through Tls13Socket, and loopback interoperability
 * with the JDK's TLS server (an independent implementation).
 */
public final class TlsTests {

    public static int passed;
    public static int failed;

    // RFC 8448 section 3, "Simple 1-RTT Handshake" (IETF Trust; test data).
    // client: create an ephemeral x25519 key pair: / private key
    static final String CLIENT_PRIV = "49af42ba7f7994852d713ef2784bcbcaa7911de26adc5642cb634540e7ea5005";
    // client: create an ephemeral x25519 key pair: / public key
    static final String CLIENT_PUB = "99381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c";
    // client: construct a ClientHello handshake message: / ClientHello
    static final String CLIENT_HELLO = "010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece700000613011303130201"
            + "0000910000000b0009000006736572766572ff01000100000a00140012001d0017001800190100010101020103010400"
            + "230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529aaf2c002b00"
            + "03020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00020101001c"
            + "00024001";
    // client: send handshake record: / complete record
    static final String CH_RECORD = "16030100c4010000c00303cb34ecb1e78163ba1c38c6dacb196a6dffa21a8d9912ec18a2ef6283024dece70000061301"
            + "13031302010000910000000b0009000006736572766572ff01000100000a00140012001d001700180019010001010102"
            + "0103010400230000003300260024001d002099381de560e4bd43d23d8e435a7dbafeb3c06e51c13cae4d5413691e529a"
            + "af2c002b0003020304000d0020001e040305030603020308040805080604010501060102010402050206020202002d00"
            + "020101001c00024001";
    // server: extract secret "early": / secret
    static final String EARLY_SECRET = "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a";
    // server: create an ephemeral x25519 key pair: / private key
    static final String SERVER_PRIV = "b1580eeadf6dd589b8ef4f2d5652578cc810e9980191ec8d058308cea216a21e";
    // server: create an ephemeral x25519 key pair: / public key
    static final String SERVER_PUB = "c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f";
    // server: construct a ServerHello handshake message: / ServerHello
    static final String SERVER_HELLO = "020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e2692800130100002e00330024"
            + "001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";
    // server: extract secret "handshake": / IKM
    static final String SHARED = "8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d";
    // server: extract secret "handshake": / secret
    static final String HS_SECRET = "1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac";
    // server: derive secret "tls13 c hs traffic": / expanded
    static final String C_HS = "b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21";
    // server: derive secret "tls13 s hs traffic": / expanded
    static final String S_HS = "b67b7d690cc16c4e75e54213cb2d37b4e9c912bcded9105d42befd59d391ad38";
    // server: extract secret "master": / secret
    static final String MASTER = "18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919";
    // server: send handshake record: / complete record
    static final String SH_RECORD = "160303005a020000560303a6af06a4121860dc5e6e60249cd34c95930c8ac5cb1434dac155772ed3e269280013010000"
            + "2e00330024001d0020c9828876112095fe66762bdbf7c672e156d6cc253b833df1dd69b1b04e751f0f002b00020304";
    // server: derive write traffic keys for handshake data: / key expanded
    static final String S_HS_KEY = "3fce516009c21727d0f2e4e86ee403bc";
    // server: derive write traffic keys for handshake data: / iv expanded
    static final String S_HS_IV = "5d313eb2671276ee13000b30";
    // server: construct an EncryptedExtensions handshake message: / EncryptedExtensions
    static final String EE = "080000240022000a00140012001d00170018001901000101010201030104001c0002400100000000";
    // server: construct a Certificate handshake message: / Certificate
    static final String CERT = "0b0001b9000001b50001b0308201ac30820115a003020102020102300d06092a864886f70d01010b0500300e310c300a"
            + "06035504031303727361301e170d3136303733303031323335395a170d3236303733303031323335395a300e310c300a"
            + "0603550403130372736130819f300d06092a864886f70d010101050003818d0030818902818100b4bb498f8279303d98"
            + "0836399b36c6988c0c68de55e1bdb826d3901a2461eafd2de49a91d015abbc9a95137ace6c1af19eaa6af98c7ced4312"
            + "0998e187a80ee0ccb0524b1b018c3e0b63264d449a6d38e22a5fda430846748030530ef0461c8ca9d9efbfae8ea6d1d0"
            + "3e2bd193eff0ab9a8002c47428a6d35a8d88d79f7f1e3f0203010001a31a301830090603551d1304023000300b060355"
            + "1d0f0404030205a0300d06092a864886f70d01010b05000381810085aad2a0e5b9276b908c65f73a7267170618a54c5f"
            + "8a7b337d2df7a594365417f2eae8f8a58c8f8172f9319cf36b7fd6c55b80f21a03015156726096fd335e5e67f2dbf102"
            + "702e608ccae6bec1fc63a42a99be5c3eb7107c3c54e9b9eb2bd5203b1c3b84e0a8b2f759409ba3eac9d91d402dcc0cc8"
            + "f8961229ac9187b42b4de10000";
    // server: construct a CertificateVerify handshake message: / CertificateVerify
    static final String CV = "0f000084080400805a747c5d88fa9bd2e55ab085a61015b7211f824cd484145ab3ff52f1fda8477b0b7abc90db78e2d3"
            + "3a5c141a078653fa6bef780c5ea248eeaaa785c4f394cab6d30bbe8d4859ee511f602957b15411ac027671459e46445c"
            + "9ea58c181e818e95b8c3fb0bf3278409d3be152a3da5043e063dda65cdf5aea20d53dfacd42f74f3";
    // server: calculate finished "tls13 finished": / finished
    static final String S_FIN_VERIFY = "9b9b141d906337fbd2cbdce71df4deda4ab42c309572cb7fffee5454b78f0718";
    // server: send handshake record: / complete record
    static final String S_FLIGHT_RECORD = "17030302a2d1ff334a56f5bff6594a07cc87b580233f500f45e489e7f33af35edf7869fcf40aa40aa2b8ea73f848a7ca"
            + "07612ef9f945cb960b4068905123ea78b111b429ba9191cd05d2a389280f526134aadc7fc78c4b729df828b5ecf7b13b"
            + "d9aefb0e57f271585b8ea9bb355c7c79020716cfb9b1183ef3ab20e37d57a6b9d7477609aee6e122a4cf51427325250c"
            + "7d0e509289444c9b3a648f1d71035d2ed65b0e3cdd0cbae8bf2d0b227812cbb360987255cc744110c453baa4fcd61092"
            + "8d809810e4b7ed1a8fd991f06aa6248204797e36a6a73b70a2559c09ead686945ba246ab66e5edd8044b4c6de3fcf2a8"
            + "9441ac66272fd8fb330ef8190579b3684596c960bd596eea520a56a8d650f563aad27409960dca63d3e688611ea5e22f"
            + "4415cf9538d51a200c27034272968a264ed6540c84838d89f72c24461aad6d26f59ecaba9acbbb317b66d902f4f292a3"
            + "6ac1b639c637ce343117b659622245317b49eeda0c6258f100d7d961ffb138647e92ea330faeea6dfa31c7a84dc3bd7e"
            + "1b7a6c7178af36879018e3f252107f243d243dc7339d5684c8b0378bf30244da8c87c843f5e56eb4c5e8280a2b48052c"
            + "f93b16499a66db7cca71e4599426f7d461e66f99882bd89fc50800becca62d6c74116dbd2972fda1fa80f85df881edbe"
            + "5a37668936b335583b599186dc5c6918a396fa48a181d6b6fa4f9d62d513afbb992f2b992f67f8afe67f76913fa388cb"
            + "5630c8ca01e0c65d11c66a1e2ac4c85977b7c7a6999bbf10dc35ae69f5515614636c0b9b68c19ed2e31c0b3b66763038"
            + "ebba42f3b38edc0399f3a9f23faa63978c317fc9fa66a73f60f0504de93b5b845e275592c12335ee340bbc4fddd50278"
            + "4016e4b3be7ef04dda49f4b440a30cb5d2af939828fd4ae3794e44f94df5a631ede42c1719bfdabf0253fe5175be898e"
            + "750edc53370d2b";
    // server: derive secret "tls13 c ap traffic": / expanded
    static final String C_AP = "9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5";
    // server: derive secret "tls13 s ap traffic": / expanded
    static final String S_AP = "a11af9f05531f856ad47116b45a950328204b4f44bfb6b3a4b4f1f3fcb631643";
    // server: derive write traffic keys for application data: / key expanded
    static final String S_AP_KEY = "9f02283b6c9c07efc26bb9f2ac92e356";
    // server: derive write traffic keys for application data: / iv expanded
    static final String S_AP_IV = "cf782b88dd83549aadf1e984";
    // server: derive read traffic keys for handshake data: / key expanded
    static final String C_HS_KEY = "dbfaa693d1762c5b666af5d950258d01";
    // server: derive read traffic keys for handshake data: / iv expanded
    static final String C_HS_IV = "5bd3c71b836e0b76bb73265f";
    // client: calculate finished "tls13 finished": / finished
    static final String C_FIN_VERIFY = "a8ec436d677634ae525ac1fcebe11a039ec17694fac6e98527b642f2edd5ce61";
    // client: send handshake record: / complete record
    static final String C_FIN_RECORD = "170303003575ec4dc238cce60b298044a71e219c56cc77b0517fe9b93c7a4bfc44d87f38f80338ac98fc46deb384bd1c"
            + "aeacab6867d726c40546";
    // client: derive write traffic keys for application data: / key expanded
    static final String C_AP_KEY = "17422dda596ed5d9acd890e3c63f5051";
    // client: derive write traffic keys for application data: / iv expanded
    static final String C_AP_IV = "5b78923dee08579033e523d9";
    // server: send handshake record: / complete record
    static final String NST_RECORD = "17030300de3a6b8f90414a97d6959c3487680de5134a2b240e6cffac116e95d41d6af8f6b580dcf3d11d63c758db289a"
            + "015940252f55713e061dc13e078891a38efbcf5753ad8ef170ad3c7353d16d9da773b9ca7f2b9fa1b6c0d4a3d03f75e0"
            + "9c30ba1e62972ac46f75f7b981be63439b2999ce13064615139891d5e4c5b406f16e3fc181a77ca475840025db2f0a77"
            + "f81b5ab05b94c01346755f69232c86519d86cbeeac87aac347d143f9605d64f650db4d023e70e952ca49fe5137121c74"
            + "bc2697687e248746d6df353005f3bce18696129c8153556b3b6c6779b37bf15985684f";
    // client: send application_data record: / payload
    static final String C_APP_PAYLOAD = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
            + "3031";
    // client: send application_data record: / complete record
    static final String C_APP_RECORD = "1703030043a23f7054b62c94d0affafe8228ba55cbefacea42f914aa66bcab3f2b9819a8a5b46b395bd54a9a20441e2b"
            + "62974e1f5a6292a2977014bd1e3deae63aeebb21694915e4";
    // server: send application_data record: / payload
    static final String S_APP_PAYLOAD = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f"
            + "3031";
    // server: send application_data record: / complete record
    static final String S_APP_RECORD = "17030300432e937e11ef4ac740e538ad36005fc4a46932fc3225d05f82aa1b36e30efaf97d90e6dffc602dcb501a59a8"
            + "fcc49c4bf2e5f0a21c0047c2abf332540dd032e167c2955d";
    // client: send alert record: / complete record
    static final String C_ALERT_RECORD = "1703030013c9872760655666b74d7ff1153efd6db6d0b0e3";
    // server: send alert record: / complete record
    static final String S_ALERT_RECORD = "1703030013b58fd67166ebf599d24720cfbe7efa7a8864a9";

    private TlsTests() {}

    public static void run() {
        System.out.println("\n[TLS engine]");
        String[] names = {
            "hkdf", "x25519", "keySchedule", "gcmCrossCheck", "ecdsaCrossCheck", "rsaCrossCheck",
            "p256Ecdh", "hostname", "serverHelloChecks", "rfc8448Replay", "rfc8448Tampering",
            "rfc8448SplitRecords", "rfc8448PlaintextAlertRefused", "loopbackInterop", "pathValidation", "tls12UnderAttack"
        };
        for (String n : names) {
            try {
                TlsTests.class.getDeclaredMethod(n).invoke(null);
            } catch (java.lang.reflect.InvocationTargetException e) {
                fail(n + " threw " + e.getCause());
                e.getCause().printStackTrace();
            } catch (Exception e) {
                fail(n + " could not run: " + e);
            }
        }
    }

    // ------------------------------------------------------------------ assertions

    static void check(String name, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("  PASS: " + name);
        } else {
            fail(name);
        }
    }

    static void fail(String name) {
        failed++;
        System.err.println("  FAIL: " + name);
    }

    static void eqHex(String name, String expected, byte[] actual) {
        String got = hex(actual);
        if (expected.equals(got)) {
            check(name, true);
        } else {
            fail(name + "\n      expected " + expected + "\n      got      " + got);
        }
    }

    static void expectAlert(String name, int alert, Runnable0 r) {
        try {
            r.run();
            fail(name + " (no failure)");
        } catch (TlsException e) {
            if (e.alert == alert) {
                check(name, true);
            } else {
                fail(name + " (alert " + e.alert + ": " + e.getMessage() + ")");
            }
        } catch (Exception e) {
            fail(name + " (" + e + ")");
        }
    }

    interface Runnable0 {
        void run() throws Exception;
    }

    static byte[] h(String s) {
        return RsaVerifier.hex(s);
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            sb.append(String.format("%02x", x & 0xff));
        }
        return sb.toString();
    }

    static byte[] cat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            o.write(p, 0, p.length);
        }
        return o.toByteArray();
    }

    // ------------------------------------------------------------------ primitives

    static void hkdf() throws Exception {
        byte[] ikm = new byte[22];
        Arrays.fill(ikm, (byte) 0x0b);
        byte[] prk = Hkdf.extract(h("000102030405060708090a0b0c"), ikm);
        eqHex("HKDF RFC 5869 A.1 PRK", "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", prk);
        eqHex("HKDF RFC 5869 A.1 OKM",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
                Hkdf.expand(prk, h("f0f1f2f3f4f5f6f7f8f9"), 42));
        // RFC 8448: HKDF-Expand-Label("derived") info bytes and output.
        eqHex("HKDF-Expand-Label derived (RFC 8448)",
                "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba",
                Hkdf.deriveSecret(h(EARLY_SECRET), "derived", Tls13Socket.sha256(new byte[0])));
    }

    static void x25519() throws Exception {
        eqHex("X25519 RFC 7748 5.2 vector 1", "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
                X25519.scalarMult(h("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4"),
                        h("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")));
        eqHex("X25519 RFC 7748 5.2 vector 2", "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957",
                X25519.scalarMult(h("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d"),
                        h("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493")));
        byte[] a = h("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        byte[] b = h("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
        eqHex("X25519 RFC 7748 6.1 Alice public", "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
                X25519.publicKey(a));
        eqHex("X25519 RFC 7748 6.1 Bob public", "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
                X25519.publicKey(b));
        eqHex("X25519 RFC 7748 6.1 shared", "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
                X25519.scalarMult(a, X25519.publicKey(b)));
        byte[] k = new byte[32];
        byte[] u = new byte[32];
        k[0] = 9;
        u[0] = 9;
        for (int i = 1; i <= 1000; i++) {
            byte[] next = X25519.scalarMult(k, u);
            u = k;
            k = next;
            if (i == 1) {
                eqHex("X25519 RFC 7748 iterated x1",
                        "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079", k);
            }
        }
        eqHex("X25519 RFC 7748 iterated x1000", "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51", k);
        eqHex("X25519 RFC 8448 client public", CLIENT_PUB, X25519.publicKey(h(CLIENT_PRIV)));
        eqHex("X25519 RFC 8448 shared secret", SHARED, X25519.scalarMult(h(CLIENT_PRIV), h(SERVER_PUB)));
        check("X25519 low-order point gives all-zero output",
                X25519.isAllZero(X25519.scalarMult(h(CLIENT_PRIV), new byte[32])));
    }

    static void keySchedule() throws Exception {
        byte[] zeros = new byte[32];
        byte[] emptyHash = Tls13Socket.sha256(new byte[0]);
        byte[] early = Hkdf.extract(zeros, zeros);
        eqHex("key schedule early secret", EARLY_SECRET, early);
        byte[] hs = Hkdf.extract(Hkdf.deriveSecret(early, "derived", emptyHash), h(SHARED));
        eqHex("key schedule handshake secret", HS_SECRET, hs);
        byte[] th = Tls13Socket.sha256(cat(h(CLIENT_HELLO), h(SERVER_HELLO)));
        eqHex("key schedule c hs traffic", C_HS, Hkdf.deriveSecret(hs, "c hs traffic", th));
        eqHex("key schedule s hs traffic", S_HS, Hkdf.deriveSecret(hs, "s hs traffic", th));
        byte[] master = Hkdf.extract(Hkdf.deriveSecret(hs, "derived", emptyHash), zeros);
        eqHex("key schedule master secret", MASTER, master);
        eqHex("traffic key (server handshake)", S_HS_KEY, Hkdf.expandLabel(h(S_HS), "key", new byte[0], 16));
        eqHex("traffic iv (server handshake)", S_HS_IV, new Tls13Socket.Protection(h(S_HS)).iv);
        eqHex("traffic iv (client handshake)", C_HS_IV, new Tls13Socket.Protection(h(C_HS)).iv);
        eqHex("traffic key (client application)", C_AP_KEY, Hkdf.expandLabel(h(C_AP), "key", new byte[0], 16));
        eqHex("traffic iv (server application)", S_AP_IV, new Tls13Socket.Protection(h(S_AP)).iv);
        byte[] thFull = Tls13Socket.sha256(cat(h(CLIENT_HELLO), h(SERVER_HELLO), h(EE), h(CERT), h(CV)));
        eqHex("server Finished verify_data",
                S_FIN_VERIFY, Hkdf.hmac(Hkdf.expandLabel(h(S_HS), "finished", new byte[0], 32), thFull));
    }

    static void gcmCrossCheck() throws Exception {
        Random rnd = new Random(1);
        boolean ok = true;
        for (int keyLen = 16; keyLen <= 32; keyLen += 16) {
            for (int len = 0; len <= 70; len++) {
                byte[] key = new byte[keyLen], nonce = new byte[12], pt = new byte[len], aad = new byte[len % 23];
                rnd.nextBytes(key);
                rnd.nextBytes(nonce);
                rnd.nextBytes(pt);
                rnd.nextBytes(aad);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, nonce));
                c.updateAAD(aad);
                byte[] jdk = c.doFinal(pt);
                AesGcm g = new AesGcm(key);
                byte[] ours = g.encrypt(nonce, pt, aad);
                ok &= Arrays.equals(jdk, ours);
                ok &= Arrays.equals(pt, g.decrypt(nonce, jdk, aad));
            }
        }
        check("AES-GCM matches the JDK for AES-128/256, lengths 0..70", ok);
        AesGcm g = new AesGcm(new byte[16]);
        byte[] sealed = g.encrypt(new byte[12], new byte[20], new byte[3]);
        sealed[25] ^= 1;
        boolean rejected = false;
        try {
            g.decrypt(new byte[12], sealed, new byte[3]);
        } catch (SecurityException e) {
            rejected = true;
        }
        check("AES-GCM rejects a modified tag", rejected);
    }

    static void ecdsaCrossCheck() throws Exception {
        String[][] curves = { { "secp256r1", "SHA256withECDSA" }, { "secp384r1", "SHA384withECDSA" } };
        int[] schemes = { SignatureSchemes.ECDSA_SECP256R1_SHA256, SignatureSchemes.ECDSA_SECP384R1_SHA384 };
        for (int i = 0; i < 2; i++) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec(curves[i][0]));
            KeyPair kp = kpg.generateKeyPair();
            boolean ok = true;
            for (int j = 0; j < 5; j++) {
                byte[] msg = ("message " + j).getBytes("UTF-8");
                Signature s = Signature.getInstance(curves[i][1]);
                s.initSign(kp.getPrivate());
                s.update(msg);
                byte[] sig = s.sign();
                ok &= SignatureSchemes.verify(schemes[i], kp.getPublic(), msg, sig, true);
                msg[0] ^= 1;
                ok &= !SignatureSchemes.verify(schemes[i], kp.getPublic(), msg, sig, true);
            }
            check("ECDSA " + curves[i][0] + " verifies JDK signatures and rejects altered messages", ok);
            byte[] msg = new byte[] { 1 };
            Signature s = Signature.getInstance(curves[i][1]);
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            check("TLS 1.3 ECDSA scheme is bound to its curve",
                    !SignatureSchemes.verify(schemes[1 - i], kp.getPublic(), msg, sig, true));
        }
        check("EC point off the curve is rejected", !EcCurve.P256.isOnCurve(
                new EcCurve.Point(BigInteger.ONE, BigInteger.ONE)));
    }

    static void rsaCrossCheck() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        byte[] msg = "reteget TLS 1.3".getBytes("UTF-8");
        String[] hashes = { "SHA-256", "SHA-384", "SHA-512" };
        int[] pss = { SignatureSchemes.RSA_PSS_RSAE_SHA256, SignatureSchemes.RSA_PSS_RSAE_SHA384,
            SignatureSchemes.RSA_PSS_RSAE_SHA512 };
        int[] pkcs = { SignatureSchemes.RSA_PKCS1_SHA256, SignatureSchemes.RSA_PKCS1_SHA384,
            SignatureSchemes.RSA_PKCS1_SHA512 };
        for (int i = 0; i < 3; i++) {
            Signature s = Signature.getInstance("RSASSA-PSS");
            int hl = MessageDigest.getInstance(hashes[i]).getDigestLength();
            s.setParameter(new PSSParameterSpec(hashes[i], "MGF1", new MGF1ParameterSpec(hashes[i]), hl, 1));
            s.initSign(kp.getPrivate());
            s.update(msg);
            byte[] sig = s.sign();
            check("RSA-PSS " + hashes[i] + " verifies a JDK signature",
                    SignatureSchemes.verify(pss[i], kp.getPublic(), msg, sig, true));
            sig[10] ^= 1;
            check("RSA-PSS " + hashes[i] + " rejects a modified signature",
                    !SignatureSchemes.verify(pss[i], kp.getPublic(), msg, sig, true));

            Signature p = Signature.getInstance(hashes[i].replace("-", "") + "withRSA");
            p.initSign(kp.getPrivate());
            p.update(msg);
            byte[] psig = p.sign();
            check("RSA PKCS#1 " + hashes[i] + " verifies a JDK signature (TLS 1.2)",
                    SignatureSchemes.verify(pkcs[i], kp.getPublic(), msg, psig, false));
            check("RSA PKCS#1 " + hashes[i] + " is refused for TLS 1.3 handshakes",
                    !SignatureSchemes.verify(pkcs[i], kp.getPublic(), msg, psig, true));
        }
        KeyPairGenerator small = KeyPairGenerator.getInstance("RSA");
        small.initialize(1024);
        KeyPair weak = small.generateKeyPair();
        boolean refused = false;
        try {
            SignatureSchemes.verify(SignatureSchemes.RSA_PSS_RSAE_SHA256, weak.getPublic(), msg, new byte[128], true);
        } catch (IllegalArgumentException e) {
            refused = true;
        }
        check("RSA keys under 2048 bits are refused", refused);
    }

    static void p256Ecdh() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair peer = kpg.generateKeyPair();
        BigInteger k = EcCurve.P256.randomScalar();
        EcCurve.Point ours = EcCurve.P256.multiplyBase(k);
        ECPublicKey pp = (ECPublicKey) peer.getPublic();
        byte[] shared = EcCurve.P256.ecdh(k, new EcCurve.Point(pp.getW().getAffineX(), pp.getW().getAffineY()));

        java.security.spec.ECPoint w = new java.security.spec.ECPoint(ours.x, ours.y);
        java.security.PublicKey ourPub = java.security.KeyFactory.getInstance("EC")
                .generatePublic(new java.security.spec.ECPublicKeySpec(w, pp.getParams()));
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(peer.getPrivate());
        ka.doPhase(ourPub, true);
        check("P-256 ECDH matches the JDK", Arrays.equals(shared, ka.generateSecret()));
        byte[] enc = EcCurve.P256.encodePoint(ours);
        check("P-256 point encode/decode round trip", EcCurve.P256.decodePoint(enc).x.equals(ours.x));
        enc[40] ^= 1;
        boolean rejected = false;
        try {
            EcCurve.P256.decodePoint(enc);
        } catch (IllegalArgumentException e) {
            rejected = true;
        }
        check("P-256 decode rejects a point off the curve", rejected);
    }

    static void hostname() {
        check("host exact match", HostnameChecker.dnsMatches("github.com", "github.com"));
        check("host wildcard one label", HostnameChecker.dnsMatches("objects.github.com", "*.github.com"));
        check("host wildcard not two labels", !HostnameChecker.dnsMatches("a.b.github.com", "*.github.com"));
        check("host wildcard not bare domain", !HostnameChecker.dnsMatches("github.com", "*.github.com"));
        check("host wildcard not public suffix", !HostnameChecker.dnsMatches("example.com", "*.com"));
        check("host partial wildcard refused", !HostnameChecker.dnsMatches("foo.github.com", "f*.github.com"));
        check("host mismatch", !HostnameChecker.dnsMatches("evil.com", "github.com"));
        check("ip literal detection", HostnameChecker.isIpLiteral("127.0.0.1") && !HostnameChecker.isIpLiteral("a.b.c.d"));
    }

    // ------------------------------------------------------------------ ServerHello rules

    static byte[] serverHello(byte[] random, byte[] sessionId, int suite, byte[] exts) {
        TlsWriter b = new TlsWriter().u16(0x0303).raw(random).vec8(sessionId).u16(suite).u8(0);
        if (exts != null) {
            b.vec16(exts);
        }
        return TlsWriter.handshake(Tls13Socket.HT_SERVER_HELLO, b.toByteArray());
    }

    static void serverHelloChecks() throws Exception {
        final Tls13Socket.ClientHelloInfo offered = Tls13Socket.ClientHelloInfo.parse(h(CLIENT_HELLO));
        final byte[] random = new byte[32];
        byte[] sentinel = random.clone();
        System.arraycopy(Tls13Socket.DOWNGRADE_TLS12, 0, sentinel, 24, 8);
        final byte[] downgraded = serverHello(sentinel, new byte[0], 0xc02f, new byte[0]);
        expectAlert("TLS 1.2 ServerHello with DOWNGRD sentinel is refused", TlsException.ILLEGAL_PARAMETER,
                new Runnable0() {
                    public void run() throws Exception {
                        Tls13Socket.ServerHelloInfo.parse(downgraded, offered);
                    }
                });
        boolean versionException = false;
        try {
            Tls13Socket.ServerHelloInfo.parse(serverHello(random, new byte[0], 0xc02f, new byte[0]), offered);
        } catch (TlsVersionException e) {
            versionException = true;
        }
        check("plain TLS 1.2 ServerHello raises TlsVersionException (fallback allowed)", versionException);

        final byte[] ks = new TlsWriter().extension(51, new TlsWriter().u16(0x1d).vec16(new byte[32]).toByteArray())
                .extension(43, new byte[] { 3, 4 }).toByteArray();
        expectAlert("ServerHello with wrong session id echo", TlsException.ILLEGAL_PARAMETER, new Runnable0() {
            public void run() throws Exception {
                Tls13Socket.ServerHelloInfo.parse(serverHello(random, new byte[] { 1 }, 0x1301, ks), offered);
            }
        });
        expectAlert("ServerHello with unoffered cipher suite", TlsException.ILLEGAL_PARAMETER, new Runnable0() {
            public void run() throws Exception {
                Tls13Socket.ServerHelloInfo.parse(serverHello(random, new byte[0], 0x1302, ks), offered);
            }
        });
        final byte[] dup = cat(ks, new TlsWriter().extension(43, new byte[] { 3, 4 }).toByteArray());
        expectAlert("ServerHello with duplicate extension", TlsException.ILLEGAL_PARAMETER, new Runnable0() {
            public void run() throws Exception {
                Tls13Socket.ServerHelloInfo.parse(serverHello(random, new byte[0], 0x1301, dup), offered);
            }
        });
        Tls13Socket.ServerHelloInfo hrr = Tls13Socket.ServerHelloInfo.parse(serverHello(Tls13Socket.HRR_RANDOM,
                new byte[0], 0x1301, new TlsWriter().extension(43, new byte[] { 3, 4 })
                        .extension(51, new byte[] { 0, 0x17 }).toByteArray()), offered);
        check("HelloRetryRequest is recognised with its selected group",
                hrr.helloRetry && hrr.keyShareGroup == Tls13Socket.GROUP_SECP256R1);
    }

    // ------------------------------------------------------------------ RFC 8448 replay

    static Tls13Socket replaySocket(byte[] serverBytes, ByteArrayOutputStream clientOut) {
        Tls13Socket t = new Tls13Socket(null, new ByteArrayInputStream(serverBytes), clientOut, "server",
                CertificatePolicy.insecure());
        t.rsaMinBits = 1024; // the RFC 8448 server certificate is RSA-1024
        t.clientHelloOverride = h(CLIENT_HELLO);
        t.x25519PrivateOverride = h(CLIENT_PRIV);
        return t;
    }

    static void rfc8448Replay() throws Exception {
        byte[] server = cat(h(SH_RECORD), h(S_FLIGHT_RECORD), h(NST_RECORD), h(S_APP_RECORD), h(S_ALERT_RECORD));
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Tls13Socket t = replaySocket(server, out);
        t.handshake();
        eqHex("RFC 8448 client flight (ClientHello + Finished) is byte-exact",
                CH_RECORD + C_FIN_RECORD, out.toByteArray());
        out.reset();
        t.getOutputStream().write(h(C_APP_PAYLOAD));
        eqHex("RFC 8448 client application record is byte-exact", C_APP_RECORD, out.toByteArray());
        ByteArrayOutputStream got = new ByteArrayOutputStream();
        InputStream in = t.getInputStream();
        byte[] buf = new byte[7];
        int n;
        while ((n = in.read(buf)) > 0) {
            got.write(buf, 0, n);
        }
        eqHex("RFC 8448 server application data decrypted (after NewSessionTicket)", S_APP_PAYLOAD, got.toByteArray());
        check("server close_notify gives end of stream", n == -1);
        out.reset();
        t.close();
        eqHex("RFC 8448 client close_notify record is byte-exact", C_ALERT_RECORD, out.toByteArray());
    }

    /** Re-encrypts server handshake messages under the RFC 8448 server handshake key. */
    static byte[] sealHandshake(byte[][] records) throws Exception {
        Tls13Socket.Protection p = new Tls13Socket.Protection(h(S_HS));
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] plain : records) {
            byte[] inner = cat(plain, new byte[] { 22 });
            int len = inner.length + 16;
            byte[] header = { 23, 3, 3, (byte) (len >>> 8), (byte) len };
            byte[] ct = p.aead.encrypt(p.nonce(), inner, header);
            p.seq++;
            o.write(header);
            o.write(ct);
        }
        return o.toByteArray();
    }

    static void replayExpect(String name, int alert, final byte[] flight) {
        expectAlert(name, alert, new Runnable0() {
            public void run() throws Exception {
                replaySocket(cat(h(SH_RECORD), flight), new ByteArrayOutputStream()).handshake();
            }
        });
    }

    static void rfc8448Tampering() throws Exception {
        byte[] flight = h(S_FLIGHT_RECORD);
        flight[40] ^= 1;
        replayExpect("tampered encrypted record -> bad_record_mac", TlsException.BAD_RECORD_MAC, flight);

        byte[] cv = h(CV);
        cv[20] ^= 1;
        replayExpect("altered CertificateVerify -> decrypt_error", TlsException.DECRYPT_ERROR,
                sealHandshake(new byte[][] { cat(h(EE), h(CERT), cv, finishedMsg()) }));

        byte[] fin = finishedMsg();
        fin[10] ^= 1;
        replayExpect("altered server Finished -> decrypt_error", TlsException.DECRYPT_ERROR,
                sealHandshake(new byte[][] { cat(h(EE), h(CERT), h(CV), fin) }));

        byte[] ee = TlsWriter.handshake(8, new TlsWriter().vec16(
                new TlsWriter().extension(0x1234, new byte[0]).toByteArray()).toByteArray());
        replayExpect("unrequested EncryptedExtensions entry -> unsupported_extension",
                TlsException.UNSUPPORTED_EXTENSION,
                sealHandshake(new byte[][] { cat(ee, h(CERT), h(CV), finishedMsg()) }));

        byte[] certReq = TlsWriter.handshake(13, new TlsWriter().vec8(new byte[0]).vec16(new byte[0]).toByteArray());
        replayExpect("CertificateRequest -> handshake_failure (client auth unsupported)",
                TlsException.HANDSHAKE_FAILURE, sealHandshake(new byte[][] { cat(h(EE), certReq) }));

        replayExpect("Finished before Certificate -> unexpected_message", TlsException.UNEXPECTED_MESSAGE,
                sealHandshake(new byte[][] { cat(h(EE), finishedMsg()) }));

        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Tls13Socket wrongKey = new Tls13Socket(null, new ByteArrayInputStream(cat(h(SH_RECORD), h(S_FLIGHT_RECORD))),
                out, "server", CertificatePolicy.insecure());
        wrongKey.rsaMinBits = 1024;
        wrongKey.clientHelloOverride = h(CLIENT_HELLO);
        byte[] other = h(CLIENT_PRIV);
        other[5] ^= 1;
        wrongKey.x25519PrivateOverride = other;
        final Tls13Socket wk = wrongKey;
        expectAlert("wrong key share secret -> bad_record_mac", TlsException.BAD_RECORD_MAC, new Runnable0() {
            public void run() throws Exception {
                wk.handshake();
            }
        });
    }

    static void rfc8448PlaintextAlertRefused() throws Exception {
        // An unauthenticated close_notify after the handshake must not end the stream cleanly.
        byte[] server = cat(h(SH_RECORD), h(S_FLIGHT_RECORD), new byte[] { 21, 3, 3, 0, 2, 1, 0 });
        final Tls13Socket t = replaySocket(server, new ByteArrayOutputStream());
        t.handshake();
        expectAlert("plaintext close_notify after handshake -> unexpected_message (no silent truncation)",
                TlsException.UNEXPECTED_MESSAGE, new Runnable0() {
                    public void run() throws Exception {
                        t.getInputStream().read(new byte[16]);
                    }
                });
    }

    static byte[] finishedMsg() {
        return TlsWriter.handshake(20, h(S_FIN_VERIFY));
    }

    static void rfc8448SplitRecords() throws Exception {
        byte[] all = cat(h(EE), h(CERT), h(CV), finishedMsg());
        byte[] a = Arrays.copyOfRange(all, 0, 17);
        byte[] b = Arrays.copyOfRange(all, 17, 300);
        byte[] c = Arrays.copyOfRange(all, 300, all.length);
        byte[] flight = cat(sealHandshake(new byte[][] { a, b, c }));
        // The byte-exact client flight still results because only record framing changed.
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        Tls13Socket t = replaySocket(cat(h(SH_RECORD), new byte[] { 20, 3, 3, 0, 1, 1 }, flight), out);
        t.handshake();
        eqHex("handshake split over 3 records plus compat CCS gives the same client flight",
                CH_RECORD + C_FIN_RECORD, out.toByteArray());
    }

    // ------------------------------------------------------------------ loopback interop (JDK server)

    static File fixtureDir() {
        File d = new File("build/test/tls-fixtures");
        d.mkdirs();
        return d;
    }

    /** Creates a self-signed PKCS#12 key store with keytool; returns null when keytool is missing. */
    static File keystore(String name, String keyArgs, String san) throws Exception {
        File ks = new File(fixtureDir(), name + ".p12");
        if (ks.exists()) {
            ks.delete();
        }
        String keytool = System.getProperty("java.home") + File.separator + "bin" + File.separator + "keytool";
        java.util.List<String> cmd = new java.util.ArrayList<String>(Arrays.asList(keytool, "-genkeypair",
                "-alias", "server", "-dname", "CN=reteget test", "-validity", "2", "-storetype", "PKCS12",
                "-keystore", ks.getPath(), "-storepass", "changeit", "-keypass", "changeit", "-ext", "SAN=" + san));
        cmd.addAll(Arrays.asList(keyArgs.split(" ")));
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        InputStream pin = p.getInputStream();
        while (pin.read() >= 0) {
            // drain
        }
        return p.waitFor() == 0 ? ks : null;
    }

    static KeyStore load(File f) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        FileInputStream in = new FileInputStream(f);
        try {
            ks.load(in, "changeit".toCharArray());
        } finally {
            in.close();
        }
        return ks;
    }

    static X509TrustManager trustManagerFor(File f) throws Exception {
        KeyStore trust = KeyStore.getInstance("PKCS12");
        trust.load(null, null);
        trust.setCertificateEntry("anchor", load(f).getCertificate("server"));
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("PKIX");
        tmf.init(trust);
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) return (X509TrustManager) tm;
        }
        throw new IllegalStateException("no X509TrustManager");
    }

    static final class Server implements Runnable {
        final SSLServerSocket ss;
        final byte[] body;
        volatile Throwable error;
        final Thread thread;

        Server(File keystore, String[] protocols, String[] groups, byte[] body) throws Exception {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(load(keystore), "changeit".toCharArray());
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            ss = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 5,
                    java.net.InetAddress.getByName("127.0.0.1"));
            ss.setEnabledProtocols(protocols);
            if (groups != null) {
                SSLParameters params = ss.getSSLParameters();
                SSLParameters.class.getMethod("setNamedGroups", String[].class)
                        .invoke(params, new Object[] { groups });
                ss.setSSLParameters(params);
            }
            this.body = body;
            thread = new Thread(this);
            thread.setDaemon(true);
            thread.start();
        }

        int port() {
            return ss.getLocalPort();
        }

        public void run() {
            // Up to two connections: a refused TLS 1.3 attempt is followed by a TLS 1.2 retry.
            try {
                for (int attempt = 0; attempt < 2; attempt++) {
                    SSLSocket s = (SSLSocket) ss.accept();
                    try {
                        serve(s);
                        error = null;
                        return;
                    } catch (Throwable t) {
                        error = t;
                        s.close();
                    }
                }
            } catch (Throwable t) {
                error = t;
            } finally {
                try { ss.close(); } catch (IOException ignored) {}
            }
        }

        private void serve(SSLSocket s) throws IOException {
            s.setSoTimeout(20000);
            InputStream in = s.getInputStream();
            int state = 0;
            while (state < 4) {
                int c = in.read();
                if (c < 0) throw new IOException("client closed before the request ended");
                state = (c == (state % 2 == 0 ? '\r' : '\n')) ? state + 1 : (c == '\r' ? 1 : 0);
            }
            OutputStream out = s.getOutputStream();
            out.write(("HTTP/1.1 200 OK\r\nContent-Length: " + body.length + "\r\n\r\n").getBytes("US-ASCII"));
            out.write(body);
            out.flush();
            s.close();
        }
    }

    static byte[] testBody(int n) {
        byte[] b = new byte[n];
        new Random(n).nextBytes(b);
        return b;
    }

    /** Sends GET over the connection and returns the response body after the header. */
    static byte[] fetch(TlsConnection c) throws Exception {
        c.getOutputStream().write("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n".getBytes("US-ASCII"));
        c.getOutputStream().flush();
        ByteArrayOutputStream all = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        InputStream in = c.getInputStream();
        while ((n = in.read(buf)) > 0) {
            all.write(buf, 0, n);
        }
        byte[] r = all.toByteArray();
        for (int i = 0; i + 3 < r.length; i++) {
            if (r[i] == '\r' && r[i + 1] == '\n' && r[i + 2] == '\r' && r[i + 3] == '\n') {
                return Arrays.copyOfRange(r, i + 4, r.length);
            }
        }
        return new byte[0];
    }

    static void interop(String name, File ks, String[] protocols, String[] groups, int bodyLen,
                        String expectProtocol, String expectInSummary) throws Exception {
        byte[] body = testBody(bodyLen);
        Server srv = new Server(ks, protocols, groups, body);
        TlsConnection c = TlsClient.connect("localhost", srv.port(), 20000, trustManagerFor(ks));
        byte[] got = fetch(c);
        c.close();
        srv.thread.join(20000);
        check(name + " [" + c.getSummary() + "]", Arrays.equals(body, got)
                && expectProtocol.equals(c.getProtocol()) && c.getSummary().contains(expectInSummary)
                && srv.error == null);
        if (srv.error != null) {
            System.err.println("      server error: " + srv.error);
        }
    }

    static void loopbackInterop() throws Exception {
        File rsa = keystore("rsa", "-keyalg RSA -keysize 2048", "dns:localhost,ip:127.0.0.1");
        File ec = keystore("ec", "-keyalg EC -groupname secp256r1", "dns:localhost");
        File ec384 = keystore("ec384", "-keyalg EC -groupname secp384r1", "dns:localhost");
        File wrongName = keystore("wrongname", "-keyalg EC -groupname secp256r1", "dns:other.test");
        if (rsa == null || ec == null || ec384 == null || wrongName == null) {
            fail("keytool unavailable; loopback interop not run");
            return;
        }
        String[] tls13 = { "TLSv1.3" };
        interop("JDK TLS 1.3 server, RSA certificate (RSA-PSS), 300 KB body", rsa, tls13, null, 300000,
                "TLSv1.3", "rsa_pss_rsae_sha256");
        interop("JDK TLS 1.3 server, ECDSA P-256 certificate", ec, tls13, null, 50000,
                "TLSv1.3", "ecdsa_secp256r1_sha256");
        interop("JDK TLS 1.3 server, ECDSA P-384 certificate", ec384, tls13, null, 1000,
                "TLSv1.3", "ecdsa_secp384r1_sha384");
        interop("JDK TLS 1.3 server that only accepts secp256r1 (HelloRetryRequest)", ec, tls13,
                new String[] { "secp256r1" }, 1000, "TLSv1.3", "secp256r1");
        interop("JDK TLS 1.2-only server -> fallback to the TLS 1.2 engine", rsa, new String[] { "TLSv1.2" },
                null, 20000, "TLSv1.2", "TLS 1.2");

        // KeyUpdate: a direct Tls13Socket so the counter is visible.
        byte[] body = testBody(400000);
        Server srv = new Server(ec, tls13, null, body);
        Tls13Socket t = Tls13Socket.connect("localhost", srv.port(), 20000,
                CertificatePolicy.trusting(trustManagerFor(ec)));
        byte[] got = fetch(t);
        t.close();
        srv.thread.join(20000);
        check("KeyUpdate from the server is followed (" + t.keyUpdatesReceived + " received)",
                Arrays.equals(body, got) && t.keyUpdatesReceived > 0);

        final File wn = wrongName;
        final Server s1 = new Server(wrongName, tls13, null, new byte[1]);
        expectAlert("certificate for another host name is rejected", TlsException.BAD_CERTIFICATE, new Runnable0() {
            public void run() throws Exception {
                TlsClient.connect("localhost", s1.port(), 20000, trustManagerFor(wn));
            }
        });
        final File ecf = ec;
        final File rsaf = rsa;
        final Server s2 = new Server(ecf, tls13, null, new byte[1]);
        expectAlert("certificate from an untrusted issuer is rejected", TlsException.BAD_CERTIFICATE, new Runnable0() {
            public void run() throws Exception {
                TlsClient.connect("localhost", s2.port(), 20000, trustManagerFor(rsaf));
            }
        });
    }

    // ------------------------------------------------------------------ own path validation

    static String keytool() {
        return System.getProperty("java.home") + File.separator + "bin" + File.separator + "keytool";
    }

    static boolean run(String... cmd) throws Exception {
        Process p = new ProcessBuilder(cmd).redirectErrorStream(true).start();
        InputStream pin = p.getInputStream();
        while (pin.read() >= 0) {
            // drain
        }
        return p.waitFor() == 0;
    }

    /** root (P-384 CA) -> intermediate (P-256 CA, pathlen 0) -> leaf (RSA, localhost), in one PKCS#12 store. */
    static File chainStore() throws Exception {
        File d = fixtureDir();
        File ks = new File(d, "chain.p12");
        File csr = new File(d, "req.csr");
        File crt = new File(d, "signed.crt");
        ks.delete();
        String kt = keytool();
        String[] common = { "-storetype", "PKCS12", "-keystore", ks.getPath(), "-storepass", "changeit", "-keypass", "changeit" };
        boolean ok = run(cat(new String[] { kt, "-genkeypair", "-alias", "root", "-keyalg", "EC", "-groupname", "secp384r1",
                "-dname", "CN=reteget test root", "-validity", "3", "-ext", "bc:c", "-ext", "ku:c=keyCertSign,cRLSign" }, common));
        ok &= run(cat(new String[] { kt, "-genkeypair", "-alias", "mid", "-keyalg", "EC", "-groupname", "secp256r1",
                "-dname", "CN=reteget test intermediate", "-validity", "3" }, common));
        ok &= run(cat(new String[] { kt, "-certreq", "-alias", "mid", "-file", csr.getPath() }, common));
        ok &= run(cat(new String[] { kt, "-gencert", "-alias", "root", "-infile", csr.getPath(), "-outfile", crt.getPath(),
                "-validity", "2", "-ext", "bc:c=ca:true,pathlen:0", "-ext", "ku:c=keyCertSign" }, common));
        ok &= run(cat(new String[] { kt, "-importcert", "-alias", "mid", "-file", crt.getPath(), "-noprompt" }, common));
        ok &= run(cat(new String[] { kt, "-genkeypair", "-alias", "server", "-keyalg", "RSA", "-keysize", "2048",
                "-dname", "CN=localhost", "-validity", "3" }, common));
        ok &= run(cat(new String[] { kt, "-certreq", "-alias", "server", "-file", csr.getPath() }, common));
        ok &= run(cat(new String[] { kt, "-gencert", "-alias", "mid", "-infile", csr.getPath(), "-outfile", crt.getPath(),
                "-validity", "1", "-ext", "SAN=dns:localhost", "-ext", "eku=serverAuth", "-ext", "ku=digitalSignature,keyEncipherment" }, common));
        ok &= run(cat(new String[] { kt, "-importcert", "-alias", "server", "-file", crt.getPath(), "-noprompt" }, common));
        // The TLS server gets a store holding only the leaf key and its chain.
        File serverOnly = new File(d, "chain-server.p12");
        serverOnly.delete();
        ok &= run(kt, "-importkeystore", "-srckeystore", ks.getPath(), "-srcstoretype", "PKCS12",
                "-srcstorepass", "changeit", "-srcalias", "server", "-destkeystore", serverOnly.getPath(),
                "-deststoretype", "PKCS12", "-deststorepass", "changeit", "-destkeypass", "changeit", "-noprompt");
        return ok ? ks : null;
    }

    static String[] cat(String[] a, String[] b) {
        String[] out = Arrays.copyOf(a, a.length + b.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static X509Cert own(java.security.cert.Certificate c) throws Exception {
        return X509Cert.parse(c.getEncoded());
    }

    /** A trust manager whose own check always fails, so CertificatePolicy must use PathValidator. */
    static X509TrustManager rootsOnly(final X509Certificate root) {
        return new X509TrustManager() {
            public void checkClientTrusted(X509Certificate[] c, String a) throws java.security.cert.CertificateException {
                throw new java.security.cert.CertificateException("client");
            }

            public void checkServerTrusted(X509Certificate[] c, String a) throws java.security.cert.CertificateException {
                throw new java.security.cert.CertificateException("platform check disabled for this test");
            }

            public X509Certificate[] getAcceptedIssuers() {
                return new X509Certificate[] { root };
            }
        };
    }

    static void pathValidation() throws Exception {
        File f = chainStore();
        if (f == null) {
            fail("keytool could not build the test chain");
            return;
        }
        KeyStore ks = load(f);
        java.security.cert.Certificate[] chain = ks.getCertificateChain("server");
        X509Cert leaf = own(chain[0]);
        X509Cert mid = own(chain[1]);
        X509Cert root = own(ks.getCertificate("root"));
        check("test chain is leaf <- intermediate <- root", chain.length >= 2
                && Arrays.equals(leaf.issuer, mid.subject) && Arrays.equals(mid.issuer, root.subject));
        check("X509Cert parses SAN, EKU and CA flags",
                leaf.dnsNames.contains("localhost") && leaf.extKeyUsage != null && !leaf.isCa
                        && mid.isCa && mid.pathLen == 0 && root.isCa);
        long now = System.currentTimeMillis();
        java.util.List<X509Cert> anchors = Arrays.asList(root);
        check("own path validation accepts a valid ECDSA/RSA chain",
                PathValidator.validate(new X509Cert[] { leaf, mid }, anchors, now) == null);
        check("presented order does not matter (extra copy of the root is ignored)",
                PathValidator.validate(new X509Cert[] { leaf, root, mid }, anchors, now) == null);
        check("missing intermediate is rejected",
                PathValidator.validate(new X509Cert[] { leaf }, anchors, now) != null);
        check("no trusted root is rejected",
                PathValidator.validate(new X509Cert[] { leaf, mid }, new java.util.ArrayList<X509Cert>(), now) != null);
        String expired = PathValidator.validate(new X509Cert[] { leaf, mid }, anchors, now + 10L * 86400000L);
        check("expired chain is rejected (" + expired + ")", expired != null && expired.contains("expired"));
        String early = PathValidator.validate(new X509Cert[] { leaf, mid }, anchors, now - 10L * 86400000L);
        check("not-yet-valid chain is rejected", early != null && early.contains("not yet valid"));
        check("a leaf cannot act as an issuer",
                PathValidator.validate(new X509Cert[] { mid, leaf }, Arrays.asList(leaf), now) != null);
        check("host name check uses the parsed SAN",
                HostnameChecker.matches("localhost", leaf) && !HostnameChecker.matches("evil.test", leaf));

        // End to end: TLS 1.3 to a JDK server, platform check forced to fail, own validator decides.
        File serverStore = new File(fixtureDir(), "chain-server.p12");
        Server srv = new Server(serverStore, new String[] { "TLSv1.3" }, null, testBody(3000));
        Tls13Socket t = Tls13Socket.connect("localhost", srv.port(), 20000,
                CertificatePolicy.trusting(rootsOnly((X509Certificate) ks.getCertificate("root"))));
        byte[] got = fetch(t);
        t.close();
        srv.thread.join(20000);
        check("TLS 1.3 connection validated only by PathValidator [" + t.getSummary() + "]",
                Arrays.equals(testBody(3000), got));
        final Server srv2 = new Server(serverStore, new String[] { "TLSv1.3" }, null, new byte[1]);
        final X509Certificate otherRoot = (X509Certificate) load(keystore("ec", "-keyalg EC -groupname secp256r1",
                "dns:localhost")).getCertificate("server");
        expectAlert("PathValidator rejects a chain to an unknown root", TlsException.BAD_CERTIFICATE, new Runnable0() {
            public void run() throws Exception {
                Tls13Socket.connect("localhost", srv2.port(), 20000, CertificatePolicy.trusting(rootsOnly(otherRoot)));
            }
        });
    }

    // ------------------------------------------------------------------ TLS 1.2 under attack

    /**
     * A TCP proxy in front of a JDK TLS 1.2 server that edits the first handshake message of
     * the given type in the server-to-client direction.
     */
    static final class Mitm implements Runnable {
        final java.net.ServerSocket listen;
        final int target;
        final int messageType;
        final boolean downgradeRandom;
        final Thread thread;

        Mitm(int target, int messageType, boolean downgradeRandom) throws IOException {
            this.listen = new java.net.ServerSocket(0, 5, java.net.InetAddress.getByName("127.0.0.1"));
            this.target = target;
            this.messageType = messageType;
            this.downgradeRandom = downgradeRandom;
            thread = new Thread(this);
            thread.setDaemon(true);
            thread.start();
        }

        public void run() {
            try {
                final java.net.Socket c = listen.accept();
                final java.net.Socket s = new java.net.Socket("127.0.0.1", target);
                Thread up = new Thread(new Runnable() {
                    public void run() {
                        try {
                            InputStream i = c.getInputStream();
                            OutputStream o = s.getOutputStream();
                            byte[] b = new byte[4096];
                            int n;
                            while ((n = i.read(b)) > 0) o.write(b, 0, n);
                        } catch (IOException ignored) {
                            // connection ends
                        }
                    }
                });
                up.setDaemon(true);
                up.start();
                java.io.DataInputStream i = new java.io.DataInputStream(s.getInputStream());
                OutputStream o = c.getOutputStream();
                boolean edited = false;
                while (true) {
                    byte[] h = new byte[5];
                    i.readFully(h);
                    byte[] p = new byte[((h[3] & 0xff) << 8) | (h[4] & 0xff)];
                    i.readFully(p);
                    if (!edited && h[0] == 22) {
                        int off = 0;
                        while (off + 4 <= p.length) {
                            int len = ((p[off + 1] & 0xff) << 16) | ((p[off + 2] & 0xff) << 8) | (p[off + 3] & 0xff);
                            if ((p[off] & 0xff) == messageType && off + 4 + len <= p.length) {
                                if (downgradeRandom) {
                                    System.arraycopy(Tls13Socket.DOWNGRADE_TLS12, 0, p, off + 4 + 2 + 24, 8);
                                } else {
                                    p[off + 4 + len - 1] ^= 1; // last byte of the signature
                                }
                                edited = true;
                                break;
                            }
                            off += 4 + len;
                        }
                    }
                    o.write(h);
                    o.write(p);
                }
            } catch (IOException ignored) {
                // connection ends
            }
        }
    }

    static void tls12UnderAttack() throws Exception {
        File ec = keystore("ec12", "-keyalg EC -groupname secp256r1", "dns:localhost");
        final X509TrustManager tm = trustManagerFor(ec);
        interop("JDK TLS 1.2-only server, ECDSA certificate", ec, new String[] { "TLSv1.2" }, null, 5000,
                "TLSv1.2", "ecdsa_secp256r1_sha256");

        final Server s1 = new Server(ec, new String[] { "TLSv1.2" }, null, new byte[1]);
        final Mitm m1 = new Mitm(s1.port(), Tls12Socket.HT_SERVER_KEY_EXCHANGE, false);
        expectAlert("TLS 1.2: altered ServerKeyExchange signature -> decrypt_error", TlsException.DECRYPT_ERROR,
                new Runnable0() {
                    public void run() throws Exception {
                        Tls12Socket.connect("localhost", m1.listen.getLocalPort(), 20000, CertificatePolicy.trusting(tm));
                    }
                });
        final Server s2 = new Server(ec, new String[] { "TLSv1.2" }, null, new byte[1]);
        final Mitm m2 = new Mitm(s2.port(), Tls12Socket.HT_SERVER_HELLO, true);
        expectAlert("TLS 1.2: DOWNGRD sentinel in ServerHello -> illegal_parameter", TlsException.ILLEGAL_PARAMETER,
                new Runnable0() {
                    public void run() throws Exception {
                        Tls12Socket.connect("localhost", m2.listen.getLocalPort(), 20000, CertificatePolicy.trusting(tm));
                    }
                });
    }
}
