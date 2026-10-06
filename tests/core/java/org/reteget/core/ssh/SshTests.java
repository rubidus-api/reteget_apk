package org.reteget.core.ssh;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
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
        testDhGroup();
        if (!jdkHasEd25519()) {
            System.out.println("  SKIP: protocol tests need the JDK's Ed25519 and X25519 (JDK 15+)");
            return;
        }
        testAlgorithmMatrix();
        testRekey();
        testAuthentication();
        testHostKeyDecision();
        testStrictKex();
        testSftpBehaviour();
        testVersionExchange();
        testTampering();
        testBlowfish();
        testKeyFilesOwn();
        testKeyFilesFromSshKeygen();
        testPublicKeyAuthentication();
    }

    // --- key files ---

    private static void testBlowfish() {
        try {
            Random rnd = new Random(5);
            boolean same = true;
            for (int i = 0; i < 5; i++) {
                byte[] key = new byte[8 + i * 6];
                rnd.nextBytes(key);
                byte[] block = new byte[16];
                rnd.nextBytes(block);
                Cipher c = Cipher.getInstance("Blowfish/ECB/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "Blowfish"));
                byte[] expect = c.doFinal(block);
                int[] w = new int[4];
                for (int k = 0; k < 4; k++) {
                    w[k] = ((block[4 * k] & 0xff) << 24) | ((block[4 * k + 1] & 0xff) << 16) | ((block[4 * k + 2] & 0xff) << 8) | (block[4 * k + 3] & 0xff);
                }
                new BcryptPbkdf.Blowfish(key).encrypt(w, 2);
                byte[] got = new byte[16];
                for (int k = 0; k < 4; k++) {
                    got[4 * k] = (byte) (w[k] >>> 24);
                    got[4 * k + 1] = (byte) (w[k] >>> 16);
                    got[4 * k + 2] = (byte) (w[k] >>> 8);
                    got[4 * k + 3] = (byte) w[k];
                }
                same &= Arrays.equals(expect, got);
            }
            check("Blowfish (pi digits computed, not tabled) equals the JDK's", same);
            checkEq("Blowfish P[0] is the first word of pi's fraction", 0x243f6a88, new BcryptPbkdf.Blowfish().p[0]);
        } catch (Exception e) {
            check("Blowfish: " + e, false);
        }
    }

    private static void testKeyFilesOwn() {
        try {
            byte[] seed = hex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
            SshKeyFile plain = SshKeyFile.ed25519FromSeed(seed, "me@phone", null);
            check("written key: not protected", !plain.isProtected() && "ssh-ed25519".equals(plain.type));
            check("written key: public line", plain.publicKeyLine("me@phone").equals(
                    "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea me@phone"));
            SshIdentity id = plain.unlock(null);
            check("written key: signs", Ed25519.verify(Ed25519.publicKey(seed), "x".getBytes(), id.sign("ssh-ed25519", "x".getBytes())));

            SshKeyFile locked = plain.withPassphrase(null, "correct horse");
            check("re-protected key: protected, same public key", locked.isProtected()
                    && locked.fingerprint().equals(plain.fingerprint()) && locked.text().contains("BEGIN OPENSSH PRIVATE KEY"));
            check("re-protected key: the seed is not in the file",
                    !hex(SshBase64.decode(locked.text().replace("-----BEGIN OPENSSH PRIVATE KEY-----", "")
                            .replace("-----END OPENSSH PRIVATE KEY-----", ""))).contains(hex(seed)));
            check("re-protected key: opens with the passphrase",
                    Arrays.equals(id.sign("ssh-ed25519", "y".getBytes()), locked.unlock("correct horse").sign("ssh-ed25519", "y".getBytes())));
            boolean wrong = false;
            try {
                locked.unlock("incorrect horse");
            } catch (SshException e) {
                wrong = "Wrong passphrase".equals(e.getMessage());
            }
            check("re-protected key: wrong passphrase says so", wrong);
            boolean needs = false;
            try {
                locked.unlock(null);
            } catch (SshException e) {
                needs = e.getMessage().contains("needs its passphrase");
            }
            check("re-protected key: no passphrase says so", needs);
            SshKeyFile unlockedAgain = locked.withPassphrase("correct horse", null);
            check("protection removed again: same key", !unlockedAgain.isProtected()
                    && Arrays.equals(plain.publicBlob(), unlockedAgain.publicBlob()) && unlockedAgain.unlock(null) != null);
            SshKeyFile reread = SshKeyFile.parse(locked.text());
            check("stored text parses back", reread.isProtected() && reread.unlock("correct horse") != null);

            SshKeyFile gen = SshKeyFile.generateEd25519("new key", "pw12345");
            SshKeyFile gen2 = SshKeyFile.generateEd25519("new key", "pw12345");
            check("generated keys differ", !gen.fingerprint().equals(gen2.fingerprint()) && gen.isProtected());

            // bcrypt_pbkdf known answer (pinned after the ssh-keygen interop below passed)
            checkEq("bcrypt_pbkdf: OpenBSD test vector (password, salt, 4 rounds, 32 bytes)",
                    "5bbf0cc293587f1c3635555c27796598d47e579071bf427e9d8fbe842aba34d9",
                    hex(BcryptPbkdf.derive("password".getBytes(), "salt".getBytes(), 4, 32)));
            checkEq("bcrypt_pbkdf known answer", BCRYPT_KAT, hex(BcryptPbkdf.derive("password".getBytes(), "salt".getBytes(), 4, 48)));

            String[][] bad = {
                    { "PuTTY-User-Key-File-3: ssh-ed25519\n", "PuTTY" },
                    { "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAINdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea x", "public key" },
                    { "-----BEGIN EC PRIVATE KEY-----\nAAAA\n-----END EC PRIVATE KEY-----", "Only Ed25519 and RSA" },
                    { "-----BEGIN RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\nAAAA\n-----END RSA PRIVATE KEY-----", "ssh-keygen -p" },
                    { "hello", "not an OpenSSH private key" },
                    { "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----", "not an OpenSSH private key" },
            };
            for (String[] b : bad) {
                String msg = null;
                try {
                    SshKeyFile.parse(b[0]);
                } catch (IOException e) {
                    msg = e.getMessage();
                }
                check("unsupported key input explained: " + b[1], msg != null && msg.contains(b[1]));
            }
            // truncated and corrupted files never throw anything but an SshException / IOException
            String text = plain.text();
            boolean clean = true;
            for (int cut = 40; cut < text.length() - 40; cut += 37) {
                try {
                    SshKeyFile.parse(text.substring(0, cut) + "\n-----END OPENSSH PRIVATE KEY-----").unlock(null);
                } catch (IOException e) {
                    // expected
                } catch (RuntimeException e) {
                    clean = false;
                }
            }
            check("truncated key files fail cleanly", clean);
        } catch (Exception e) {
            check("own key files: " + e, false);
        }
    }

    static final String BCRYPT_KAT = "5ba4bfc60c7ac272931458407f4c1c4936ea356c55125c5a279b791d65bf9842d49d7e1b572a9052715ebfa9421e7e94";

    private static String run(java.io.File dir, String... cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.directory(dir);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        p.getOutputStream().close();
        java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
        byte[] b = new byte[4096];
        int n;
        while ((n = p.getInputStream().read(b)) > 0) out.write(b, 0, n);
        p.waitFor();
        return out.toString("UTF-8");
    }

    private static String readText(java.io.File f) throws IOException {
        java.io.FileInputStream in = new java.io.FileInputStream(f);
        try {
            java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            byte[] b = new byte[4096];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
            return out.toString("UTF-8");
        } finally {
            in.close();
        }
    }

    /**
     * Key files made by the real ssh-keygen, when it is installed: an implementation of the file
     * format, bcrypt_pbkdf and both key types that is not ours. The keys exist only in a
     * temporary directory for the length of the test.
     */
    private static void testKeyFilesFromSshKeygen() {
        java.io.File dir = null;
        try {
            if (!new java.io.File("/usr/bin/ssh-keygen").canExecute()) {
                System.out.println("  SKIP: ssh-keygen is not installed; OpenSSH key file interop not run");
                return;
            }
            dir = java.io.File.createTempFile("sshkeys", "");
            dir.delete();
            dir.mkdirs();
            String[][] cases = {
                    { "ed_plain", "-t", "ed25519", "-N", "" },
                    { "ed_pass", "-t", "ed25519", "-N", "secret pass" },
                    { "ed_gcm", "-t", "ed25519", "-N", "secret pass", "-Z", "aes256-gcm@openssh.com" },
                    { "rsa_pass", "-t", "rsa", "-b", "2048", "-N", "secret pass" },
                    { "rsa_pem", "-t", "rsa", "-b", "2048", "-N", "", "-m", "PEM" },
                    { "rsa_p8", "-t", "rsa", "-b", "2048", "-N", "", "-m", "PKCS8" },
            };
            for (String[] c : cases) {
                List<String> cmd = new ArrayList<String>(Arrays.asList("ssh-keygen", "-q", "-C", "c@t", "-f", c[0]));
                cmd.addAll(Arrays.asList(c).subList(1, c.length));
                run(dir, cmd.toArray(new String[0]));
                String pass = c[4].length() > 0 && !"2048".equals(c[4]) ? c[4] : c.length > 6 && c[5].equals("-N") ? c[6] : "";
                if ("rsa_pass".equals(c[0])) pass = "secret pass";
                SshKeyFile k = SshKeyFile.parse(readText(new java.io.File(dir, c[0])));
                String pubLine = readText(new java.io.File(dir, c[0] + ".pub")).trim();
                checkEq("ssh-keygen " + c[0] + ": public key line", pubLine, k.publicKeyLine("c@t"));
                String fp = run(dir, "ssh-keygen", "-l", "-f", c[0] + ".pub").split(" ")[1];
                checkEq("ssh-keygen " + c[0] + ": fingerprint", fp, k.fingerprint());
                checkEq("ssh-keygen " + c[0] + ": protected", pass.length() > 0, k.isProtected());
                SshIdentity id = k.unlock(pass.length() > 0 ? pass : null);
                byte[] msg = "signed by reteget".getBytes();
                for (String alg : id.algorithms(null)) {
                    check("ssh-keygen " + c[0] + ": our " + alg + " signature verifies",
                            SshHostKey.parse(k.publicBlob()).verify(alg, msg,
                                    new SshBuf.Writer().string(alg).string(id.sign(alg, msg)).bytes()));
                }
                if (pass.length() > 0) {
                    boolean wrong = false;
                    try {
                        k.unlock("not the passphrase");
                    } catch (SshException e) {
                        wrong = "Wrong passphrase".equals(e.getMessage());
                    }
                    check("ssh-keygen " + c[0] + ": wrong passphrase refused", wrong);
                }
            }
            // The other direction: ssh-keygen reads a key we generated and protected.
            SshKeyFile ours = SshKeyFile.generateEd25519("made on the phone", "phone pass");
            java.io.File f = new java.io.File(dir, "ours");
            java.io.FileOutputStream o = new java.io.FileOutputStream(f);
            o.write(ours.text().getBytes("UTF-8"));
            o.close();
            f.setReadable(false, false);
            f.setReadable(true, true);
            f.setWritable(false, false);
            f.setWritable(true, true);
            String pub = run(dir, "ssh-keygen", "-y", "-P", "phone pass", "-f", "ours").trim();
            check("ssh-keygen reads a protected key written here: " + pub, pub.startsWith(ours.publicKeyLine("")));
            String refused = run(dir, "ssh-keygen", "-y", "-P", "wrong pass", "-f", "ours");
            check("ssh-keygen refuses it with a wrong passphrase", !refused.contains("ssh-ed25519 AAAA"));
        } catch (Exception e) {
            check("ssh-keygen key files: " + e, false);
        } finally {
            if (dir != null) {
                java.io.File[] fs = dir.listFiles();
                if (fs != null) for (java.io.File x : fs) x.delete();
                dir.delete();
            }
        }
    }

    private static void testPublicKeyAuthentication() {
        TestSshServer srv = null;
        try {
            SshKeyFile ed = SshKeyFile.generateEd25519("k", null);
            SshIdentity edId = ed.unlock(null);
            srv = server();
            srv.allowPassword = false;
            srv.authorizedKeys.add(ed.publicBlob());
            srv.start();
            Fetch f = fetch(srv.port(), "/pub/file.bin", "user", null, edId, TRUST_ALL, null, 0, -1);
            check("Ed25519 key logs in" + (f.error != null ? " (" + f.error + ")" : ""), f.error == null && Arrays.equals(FILE, f.data));
            check("the key is offered before it is used to sign",
                    srv.log.indexOf("publickey ssh-ed25519 query") >= 0
                            && srv.log.indexOf("publickey ssh-ed25519 query") < srv.log.indexOf("publickey ssh-ed25519 signed"));
            f = fetch(srv.port(), "/pub/file.bin", "user", null, null, TRUST_ALL, null, 0, -1);
            check("key needed but none chosen: hint", f.error != null && f.message().contains("needs a key"));
            SshIdentity other = SshKeyFile.generateEd25519("other", null).unlock(null);
            srv.log.clear();
            f = fetch(srv.port(), "/pub/file.bin", "user", null, other, TRUST_ALL, null, 0, -1);
            check("a key the server does not know fails without signing anything",
                    f.error != null && f.message().startsWith("Authentication failed") && !srv.log.contains("publickey ssh-ed25519 signed"));
            srv.close();

            srv = server();
            srv.authorizedKeys.add(ed.publicBlob());
            srv.start();
            f = fetch(srv.port(), "/pub/file.bin", "user", "pw", other, TRUST_ALL, null, 0, -1);
            check("unknown key, then the password works", f.error == null && Arrays.equals(FILE, f.data)
                    && srv.log.contains("auth password"));
            srv.log.clear();
            f = fetch(srv.port(), "/pub/file.bin", "user", "pw", edId, TRUST_ALL, null, 0, -1);
            check("with an accepted key the password is never sent", f.error == null && !srv.log.contains("auth password"));
            srv.close();

            // RSA through a JDK-made key converted from PKCS#8 PEM
            java.security.KeyPair kp = TestSshServer.generate("ssh-rsa");
            String pem = "-----BEGIN PRIVATE KEY-----\n" + SshBase64.encode(kp.getPrivate().getEncoded(), true)
                    + "\n-----END PRIVATE KEY-----\n";
            SshKeyFile rsa = SshKeyFile.parse(pem);
            check("PKCS#8 RSA key converted: same public key as the JDK's",
                    Arrays.equals(TestSshServer.blob(kp.getPublic()), rsa.publicBlob()) && "ssh-rsa".equals(rsa.type));
            SshIdentity rsaId = rsa.withPassphrase(null, "rsa-pass").unlock("rsa-pass");
            for (String[] algs : new String[][] { null, { "rsa-sha2-256" }, { "rsa-sha2-512", "ssh-ed25519" } }) {
                srv = server();
                srv.allowPassword = false;
                srv.authorizedKeys.add(rsa.publicBlob());
                srv.serverSigAlgs = algs;
                srv.start();
                f = fetch(srv.port(), "/pub/file.bin", "user", null, rsaId, TRUST_ALL, null, 0, -1);
                String expect = algs == null ? "rsa-sha2-512" : algs[0];
                check("RSA key logs in, server-sig-algs " + (algs == null ? "absent" : Arrays.toString(algs))
                                + (f.error != null ? " (" + f.error + ")" : ""),
                        f.error == null && Arrays.equals(FILE, f.data) && srv.log.contains("publickey " + expect + " signed"));
                srv.close();
            }
        } catch (Exception e) {
            check("public key authentication: " + e, false);
        } finally {
            if (srv != null) srv.close();
        }
    }

    private static boolean jdkHasEd25519() {
        try {
            Signature.getInstance("Ed25519");
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    static final byte[] FILE = content(300000, 3);

    static byte[] content(int n, int seed) {
        byte[] b = new byte[n];
        new Random(seed).nextBytes(b);
        return b;
    }

    static final SshTransport.HostKeyCheck TRUST_ALL = new SshTransport.HostKeyCheck() {
        public void check(SshHostKey key) {}
    };

    /** The outcome of one download attempt through SftpSession. */
    static final class Fetch {
        byte[] data;
        IOException error;
        String summary;
        int kexCount;
        SftpSession.FileInfo info;

        String message() {
            return error == null ? null : String.valueOf(error.getMessage());
        }
    }

    static Fetch fetch(int port, String path, String user, String password, SshIdentity identity,
                       SshTransport.HostKeyCheck check, String preferredType, long offset, long rekeyBytes) {
        Fetch f = new Fetch();
        SftpSession s = SftpSession.create();
        s.rekeyBytesForTest = rekeyBytes;
        try {
            s.connect("127.0.0.1", port, 5000, 10000, user, password, identity, check, preferredType);
            f.summary = s.summary();
            f.info = s.stat(path);
            final java.io.ByteArrayOutputStream out = new java.io.ByteArrayOutputStream();
            s.read(path, offset, f.info.size, new SftpSession.Sink() {
                public void write(byte[] b, int off, int len) {
                    out.write(b, off, len);
                }
            });
            f.data = out.toByteArray();
            f.kexCount = s.kexCount();
            s.close();
        } catch (IOException e) {
            f.error = e;
            s.abort();
        }
        return f;
    }

    static Fetch fetch(TestSshServer srv, String path) {
        return fetch(srv.port(), path, "user", "pw", null, TRUST_ALL, null, 0, -1);
    }

    static TestSshServer server() throws Exception {
        TestSshServer s = new TestSshServer();
        s.files.put("/pub/file.bin", FILE);
        return s;
    }

    private static void testDhGroup() {
        BigInteger p = SshTransport.DH14_P;
        check("DH group 14: 2048-bit safe prime", p.bitLength() == 2048 && p.isProbablePrime(40)
                && p.subtract(BigInteger.ONE).shiftRight(1).isProbablePrime(40));
    }

    private static void testAlgorithmMatrix() {
        String[] kexes = { "curve25519-sha256", "curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256" };
        String[] ciphers = { "aes128-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com" };
        for (String kex : kexes) {
            for (String cipher : ciphers) {
                TestSshServer srv = null;
                try {
                    srv = server();
                    srv.kexAlgs = new String[] { kex };
                    srv.ciphers = new String[] { cipher };
                    srv.start();
                    Fetch f = fetch(srv, "/pub/file.bin");
                    check(kex + " + " + cipher + ": file identical" + (f.error != null ? " (" + f.error + ")" : ""),
                            f.error == null && Arrays.equals(FILE, f.data) && kex.equals(srv.lastKex) && cipher.equals(srv.lastCipher));
                } catch (Exception e) {
                    check(kex + " + " + cipher + ": " + e, false);
                } finally {
                    if (srv != null) srv.close();
                }
            }
        }
        String[][] hostKeys = { { "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256" }, { "ssh-rsa", "rsa-sha2-512" }, { "ssh-rsa", "rsa-sha2-256" } };
        for (String[] hk : hostKeys) {
            TestSshServer srv = null;
            try {
                srv = server();
                srv.hostKeyType = hk[0];
                if ("ssh-rsa".equals(hk[0])) srv.rsaSigAlgs = new String[] { hk[1] };
                srv.start();
                Fetch f = fetch(srv, "/pub/file.bin");
                check("host key " + hk[1] + ": file identical" + (f.error != null ? " (" + f.error + ")" : ""),
                        f.error == null && Arrays.equals(FILE, f.data) && hk[1].equals(srv.lastHostKeyAlg));
                checkEq("host key " + hk[1] + ": summary", "SSH curve25519-sha256 aes128-ctr " + hk[1], f.summary);
            } catch (Exception e) {
                check("host key " + hk[1] + ": " + e, false);
            } finally {
                if (srv != null) srv.close();
            }
        }
        TestSshServer srv = null;
        try {
            srv = server();
            srv.strict = false;
            srv.start();
            Fetch f = fetch(srv, "/pub/file.bin");
            check("server without strict KEX (CTR, running sequence numbers)", f.error == null && Arrays.equals(FILE, f.data));
            srv.close();
            srv = server();
            srv.ciphers = new String[] { "3des-cbc", "aes128-cbc" };
            srv.start();
            f = fetch(srv, "/pub/file.bin");
            check("no common cipher: says what the server offers",
                    f.error != null && f.message().contains("no common cipher") && f.message().contains("aes128-cbc"));
            srv.close();
            srv = server();
            srv.hostKeyType = "ssh-rsa";
            srv.rsaSigAlgs = new String[] { "ssh-rsa" };
            srv.start();
            f = fetch(srv, "/pub/file.bin");
            check("SHA-1 ssh-rsa host key signatures are not negotiated", f.error != null && f.message().contains("no common host key type"));
        } catch (Exception e) {
            check("negotiation: " + e, false);
        } finally {
            if (srv != null) srv.close();
        }
    }

    private static void testRekey() {
        byte[] big = content(1200000, 9);
        for (String cipher : new String[] { "aes128-ctr", "aes128-gcm@openssh.com" }) {
            for (int strict = 0; strict < 2; strict++) {
                String name = cipher + (strict == 1 ? ", strict" : ", not strict");
                TestSshServer srv = null;
                try {
                    srv = server();
                    srv.files.put("/big", big);
                    srv.ciphers = new String[] { cipher };
                    srv.strict = strict == 1;
                    srv.rekeyAfterFileBytes = 250000;
                    srv.start();
                    Fetch f = fetch(srv, "/big");
                    check("server re-keys during the download (" + name + "): " + srv.kexCount + " exchanges"
                                    + (f.error != null ? " (" + f.error + ")" : ""),
                            f.error == null && Arrays.equals(big, f.data) && srv.kexCount >= 4);
                    srv.close();

                    srv = server();
                    srv.files.put("/big", big);
                    srv.ciphers = new String[] { cipher };
                    srv.strict = strict == 1;
                    srv.start();
                    f = fetch(srv.port(), "/big", "user", "pw", null, TRUST_ALL, null, 0, 300000);
                    check("client re-keys during the download (" + name + "): " + f.kexCount + " exchanges"
                                    + (f.error != null ? " (" + f.error + ")" : ""),
                            // reads already in flight (8 x 32 KiB) count towards the next interval
                            f.error == null && Arrays.equals(big, f.data) && f.kexCount >= 3 && srv.kexCount == f.kexCount);
                } catch (Exception e) {
                    check("re-key (" + name + "): " + e, false);
                } finally {
                    if (srv != null) srv.close();
                }
            }
        }
    }

    private static void testAuthentication() {
        TestSshServer srv = null;
        try {
            srv = server().start();
            Fetch f = fetch(srv.port(), "/pub/file.bin", "user", "wrong", null, TRUST_ALL, null, 0, -1);
            check("wrong password fails", f.error != null && f.message().startsWith("Authentication failed"));
            f = fetch(srv.port(), "/pub/file.bin", "user", null, null, TRUST_ALL, null, 0, -1);
            check("no password given: hint", f.error != null && f.message().contains("needs a password") && f.message().contains("sftp://user:password@"));
            check("without a password nothing but 'none' is tried", !srv.log.contains("auth password") || srv.log.indexOf("auth password") < srv.log.lastIndexOf("auth none"));
            srv.close();

            srv = server();
            srv.allowPassword = false;
            srv.allowKeyboardInteractive = true;
            srv.start();
            f = fetch(srv, "/pub/file.bin");
            check("keyboard-interactive with the password", f.error == null && Arrays.equals(FILE, f.data));
            srv.close();

            srv = server();
            srv.passwordChangeRequired = true;
            srv.start();
            f = fetch(srv, "/pub/file.bin");
            check("password change request is an error", f.error != null && f.message().contains("password changed"));
            srv.close();

            srv = server();
            srv.noSftp = true;
            srv.start();
            f = fetch(srv, "/pub/file.bin");
            check("no sftp subsystem: says so", f.error != null && f.message().contains("SFTP is not enabled"));
        } catch (Exception e) {
            check("authentication: " + e, false);
        } finally {
            if (srv != null) srv.close();
        }
    }

    private static void testHostKeyDecision() {
        TestSshServer srv = null;
        try {
            srv = server().start();
            final SshHostKey[] seen = new SshHostKey[1];
            Fetch f = fetch(srv.port(), "/pub/file.bin", "user", "pw", null, new SshTransport.HostKeyCheck() {
                public void check(SshHostKey key) throws IOException {
                    seen[0] = key;
                    throw new SshException("not trusted");
                }
            }, null, 0, -1);
            check("refused host key stops the connection", f.error != null && "not trusted".equals(f.message()));
            check("nothing was sent for authentication", !srv.log.contains("auth none") && !srv.log.contains("auth password"));
            check("the check saw the server's key", seen[0] != null && Arrays.equals(srv.hostKeyBlob(), seen[0].blob())
                    && seen[0].fingerprint().startsWith("SHA256:") && seen[0].fingerprint().length() == 50);
            srv.close();

            srv = server();
            srv.corruptSignature = true;
            srv.start();
            final boolean[] asked = { false };
            f = fetch(srv.port(), "/pub/file.bin", "user", "pw", null, new SshTransport.HostKeyCheck() {
                public void check(SshHostKey key) {
                    asked[0] = true;
                }
            }, null, 0, -1);
            check("wrong exchange signature (man in the middle) is refused", f.error != null && f.message().contains("signature is wrong"));
            check("the user is not even asked about that key", !asked[0] && !srv.log.contains("auth none"));
        } catch (Exception e) {
            check("host key decision: " + e, false);
        } finally {
            if (srv != null) srv.close();
        }
    }

    private static void testStrictKex() {
        String[] cases = { "before", "during", "debug" };
        for (String c : cases) {
            for (int strict = 0; strict < 2; strict++) {
                TestSshServer srv = null;
                try {
                    srv = server();
                    srv.strict = strict == 1;
                    srv.ignoreBeforeKexinit = c.equals("before");
                    srv.ignoreDuringKex = c.equals("during");
                    srv.debugBeforeNewkeys = c.equals("debug");
                    srv.start();
                    Fetch f = fetch(srv, "/pub/file.bin");
                    if (strict == 1) {
                        check("strict KEX: an extra message (" + c + ") ends the connection",
                                f.error != null && (f.message().contains("strict") || f.message().contains("unexpected SSH message")));
                    } else {
                        check("without strict KEX the same message (" + c + ") is skipped", f.error == null && Arrays.equals(FILE, f.data));
                    }
                } catch (Exception e) {
                    check("strict KEX (" + c + "): " + e, false);
                } finally {
                    if (srv != null) srv.close();
                }
            }
        }
    }

    private static void testSftpBehaviour() {
        TestSshServer srv = null;
        try {
            srv = server();
            srv.files.put("home.bin", FILE);
            srv.directories.add("/pub");
            srv.start();
            Fetch f = fetch(srv, "/pub/missing.bin");
            check("missing file", f.error != null && f.message().contains("No such file") && f.message().contains("/pub/missing.bin"));
            f = fetch(srv, "/pub");
            check("a directory is not a file", f.error != null && f.message().contains("directory"));
            f = fetch(srv, SftpSession.remotePath("/~/home.bin"));
            check("/~/ is relative to the home directory", f.error == null && Arrays.equals(FILE, f.data) && srv.log.contains("stat home.bin"));
            checkEq("an absolute path stays absolute", "/a/b", SftpSession.remotePath("/a/b"));
            f = fetch(srv.port(), "/pub/file.bin", "user", "pw", null, TRUST_ALL, null, 123457, -1);
            check("reading from an offset", f.error == null && Arrays.equals(Arrays.copyOfRange(FILE, 123457, FILE.length), f.data)
                    && srv.log.contains("read 123457 32768"));
            check("stat gives size and time", f.info != null && f.info.size == FILE.length && f.info.mtime == 1700000000L);
            srv.close();

            srv = server();
            srv.shortReadEvery = 3;
            srv.start();
            f = fetch(srv, "/pub/file.bin");
            check("short reads are completed", f.error == null && Arrays.equals(FILE, f.data));
            srv.close();

            srv = server();
            srv.reverseAnswers = true;
            srv.shortReadEvery = 4;
            srv.start();
            f = fetch(srv, "/pub/file.bin");
            check("answers in reverse order are written in file order", f.error == null && Arrays.equals(FILE, f.data));
            int inFlight = 0, max = 0;
            // The client keeps several reads in flight: the first batch the server saw has more than one.
            for (String l : srv.log) {
                if (l.startsWith("read ")) inFlight++;
            }
            check("reads are pipelined", inFlight >= FILE.length / 32768);
            srv.close();

            srv = server();
            srv.cutAfterFileBytes = 100000;
            srv.start();
            f = fetch(srv, "/pub/file.bin");
            check("a cut connection is an error, not a short file", f.error != null && f.data == null);
        } catch (Exception e) {
            check("sftp behaviour: " + e, false);
        } finally {
            if (srv != null) srv.close();
        }
    }

    private static void testVersionExchange() {
        TestSshServer srv = null;
        try {
            srv = server();
            srv.linesBeforeVersion = new String[] { "Welcome to the test server", "second line" };
            srv.start();
            Fetch f = fetch(srv, "/pub/file.bin");
            check("text lines before the version are skipped", f.error == null && Arrays.equals(FILE, f.data));
            srv.close();
            srv = server();
            srv.versionLine = "SSH-1.5-old";
            srv.start();
            f = fetch(srv, "/pub/file.bin");
            check("an SSH-1 server is refused", f.error != null && f.message().contains("SSH-2 needed"));
        } catch (Exception e) {
            check("version exchange: " + e, false);
        } finally {
            if (srv != null) srv.close();
        }
    }

    /** A TCP relay that flips one bit of the server's stream at a given offset. */
    private static int flippingProxy(final int target, final long flipAt) throws IOException {
        final java.net.ServerSocket ps = new java.net.ServerSocket(0, 5, java.net.InetAddress.getByName("127.0.0.1"));
        Thread t = new Thread(new Runnable() {
            public void run() {
                try {
                    final java.net.Socket c = ps.accept();
                    final java.net.Socket s = new java.net.Socket("127.0.0.1", target);
                    Thread up = new Thread(new Runnable() {
                        public void run() {
                            try {
                                byte[] b = new byte[8192];
                                int n;
                                while ((n = c.getInputStream().read(b)) > 0) {
                                    s.getOutputStream().write(b, 0, n);
                                    s.getOutputStream().flush();
                                }
                            } catch (IOException ignored) {
                            }
                        }
                    });
                    up.setDaemon(true);
                    up.start();
                    long pos = 0;
                    byte[] b = new byte[8192];
                    int n;
                    while ((n = s.getInputStream().read(b)) > 0) {
                        if (flipAt >= pos && flipAt < pos + n) b[(int) (flipAt - pos)] ^= 0x20;
                        pos += n;
                        c.getOutputStream().write(b, 0, n);
                        c.getOutputStream().flush();
                    }
                    c.close();
                    s.close();
                } catch (IOException ignored) {
                } finally {
                    try {
                        ps.close();
                    } catch (IOException ignored) {
                    }
                }
            }
        });
        t.setDaemon(true);
        t.start();
        return ps.getLocalPort();
    }

    private static void testTampering() {
        for (String cipher : new String[] { "aes128-ctr", "aes128-gcm@openssh.com" }) {
            TestSshServer srv = null;
            try {
                srv = server();
                srv.ciphers = new String[] { cipher };
                srv.start();
                int proxy = flippingProxy(srv.port(), 150000);
                Fetch f = fetch(proxy, "/pub/file.bin", "user", "pw", null, TRUST_ALL, null, 0, -1);
                check("one flipped bit in the encrypted stream is detected (" + cipher + "): " + f.message(),
                        f.error != null && f.data == null && f.message().contains("corrupt SSH packet"));
                proxy = flippingProxy(srv.port(), 60);
                f = fetch(proxy, "/pub/file.bin", "user", "pw", null, TRUST_ALL, null, 0, -1);
                check("a flipped bit in the server's KEXINIT breaks the exchange (" + cipher + ")", f.error != null);
            } catch (Exception e) {
                check("tampering (" + cipher + "): " + e, false);
            } finally {
                if (srv != null) srv.close();
            }
        }
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
