package org.reteget.core.ssh;

import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import org.reteget.core.tls.AesGcm;
import org.reteget.core.tls.TlsRandom;

/**
 * A private key for public-key authentication, in OpenSSH's own file format
 * ("-----BEGIN OPENSSH PRIVATE KEY-----", PROTOCOL.key): Ed25519 and RSA keys, unprotected or
 * protected by a passphrase (bcrypt KDF with aes256-ctr, aes128-ctr or aes256-gcm@openssh.com).
 *
 * <p>The public half can be read without the passphrase; {@link #unlock} needs it. Unprotected
 * RSA keys in PEM form (PKCS#1 "RSA PRIVATE KEY", PKCS#8 "PRIVATE KEY") are converted on import.
 * Not supported, and said so: ECDSA and DSA keys, PuTTY .ppk files, and PEM files with their
 * old-style encryption (convert those with {@code ssh-keygen -p -f key}).
 */
public final class SshKeyFile {

    private static final String BEGIN = "-----BEGIN OPENSSH PRIVATE KEY-----";
    private static final String END = "-----END OPENSSH PRIVATE KEY-----";
    private static final byte[] MAGIC = SshBuf.utf8("openssh-key-v1\0");
    /** Rounds for keys written here; OpenSSH wrote 16 for years and reads any value. */
    static final int DEFAULT_ROUNDS = 16;

    /** "ssh-ed25519" or "ssh-rsa". */
    public final String type;
    private final byte[] publicBlob;
    private final String cipher;
    private final byte[] kdfOptions;
    private final byte[] privateSection; // as stored: encrypted or not (plus the GCM tag)
    private final String text;

    private SshKeyFile(String type, byte[] publicBlob, String cipher, byte[] kdfOptions, byte[] privateSection, String text) {
        this.type = type;
        this.publicBlob = publicBlob;
        this.cipher = cipher;
        this.kdfOptions = kdfOptions;
        this.privateSection = privateSection;
        this.text = text;
    }

    /**
     * Reads a private key file's text. An unprotected PEM RSA key comes back converted to the
     * OpenSSH format. An SshException says what is wrong with anything else.
     */
    public static SshKeyFile parse(String fileText) throws IOException {
        String t = fileText.replace("\r", "").trim();
        if (t.contains("-----BEGIN RSA PRIVATE KEY-----") || t.contains("-----BEGIN PRIVATE KEY-----")) {
            return parse(fromPemRsa(t));
        }
        if (t.startsWith("PuTTY-User-Key-File")) {
            throw new SshException("This is a PuTTY key; export it from PuTTYgen as an OpenSSH key first");
        }
        if (t.contains("-----BEGIN ENCRYPTED PRIVATE KEY-----")) {
            throw new SshException("This key's protection is not supported; convert it with: ssh-keygen -p -f <key file>");
        }
        if (t.contains("-----BEGIN EC PRIVATE KEY-----") || t.contains("-----BEGIN DSA PRIVATE KEY-----")) {
            throw new SshException("Only Ed25519 and RSA keys are supported");
        }
        if (t.startsWith("ssh-") || t.startsWith("ecdsa-")) {
            throw new SshException("This is a public key; the private key file is needed");
        }
        int b = t.indexOf(BEGIN);
        int e = t.indexOf(END);
        if (b < 0 || e < b) throw new SshException("This is not an OpenSSH private key file");
        byte[] raw = SshBase64.decode(t.substring(b + BEGIN.length(), e));
        if (raw == null || raw.length < MAGIC.length || !Arrays.equals(MAGIC, Arrays.copyOf(raw, MAGIC.length))) {
            throw new SshException("This is not an OpenSSH private key file");
        }
        SshBuf.Reader r = new SshBuf.Reader(raw, MAGIC.length, raw.length - MAGIC.length);
        String cipher = r.text();
        String kdf = r.text();
        byte[] kdfOptions = r.string();
        if (r.u32() != 1) throw new SshException("Key files holding several keys are not supported");
        byte[] publicBlob = r.string();
        byte[] priv = r.string();
        if ("aes256-gcm@openssh.com".equals(cipher)) { // the tag follows the string
            byte[] tag = r.rest();
            byte[] joined = Arrays.copyOf(priv, priv.length + tag.length);
            System.arraycopy(tag, 0, joined, priv.length, tag.length);
            priv = joined;
        }
        boolean none = "none".equals(cipher);
        if (none != "none".equals(kdf) || (!none && !"bcrypt".equals(kdf))) {
            throw new SshException("This key's protection (" + SshHostKey.printable(kdf) + ") is not supported");
        }
        if (!none && keyLength(cipher) < 0) {
            throw new SshException("This key's cipher (" + SshHostKey.printable(cipher) + ") is not supported; "
                    + "re-protect it with: ssh-keygen -p -Z aes256-ctr -f <key file>");
        }
        String type = new SshBuf.Reader(publicBlob).text();
        if (!SshHostKey.ED25519.equals(type) && !SshHostKey.RSA.equals(type)) {
            throw new SshException("Only Ed25519 and RSA keys are supported (this is " + SshHostKey.printable(type) + ")");
        }
        SshHostKey.parse(publicBlob); // well-formed, and RSA of at least 2048 bits
        return new SshKeyFile(type, publicBlob, cipher, kdfOptions, priv, t.substring(b, e + END.length()) + "\n");
    }

    private static int keyLength(String cipher) {
        if ("aes256-ctr".equals(cipher) || "aes256-gcm@openssh.com".equals(cipher)) return 32;
        if ("aes128-ctr".equals(cipher)) return 16;
        return -1;
    }

    /** True when a passphrase is needed to use the key. */
    public boolean isProtected() {
        return !"none".equals(cipher);
    }

    public byte[] publicBlob() {
        return publicBlob.clone();
    }

    /** "SHA256:..." as ssh-keygen -l prints it. */
    public String fingerprint() {
        return SshHostKey.fingerprint(publicBlob);
    }

    /** The line for authorized_keys: type, base64 blob, comment. */
    public String publicKeyLine(String comment) {
        String c = comment == null ? "" : comment.replace('\n', ' ').replace('\r', ' ').trim();
        return type + " " + SshBase64.encode(publicBlob, true) + (c.length() > 0 ? " " + c : "");
    }

    /** The key file's text, as it is stored. */
    public String text() {
        return text;
    }

    /** The decrypted private section, checked; an SshException "Wrong passphrase" when it does not open. */
    private byte[] open(String passphrase) throws IOException {
        byte[] plain;
        if (!isProtected()) {
            plain = privateSection;
        } else {
            if (passphrase == null || passphrase.length() == 0) throw new SshException("This key needs its passphrase");
            SshBuf.Reader o = new SshBuf.Reader(kdfOptions);
            byte[] salt = o.string();
            long rounds = o.u32();
            if (rounds < 1 || rounds > 1000 || salt.length == 0) throw new SshException("This key file is damaged");
            int keyLen = keyLength(cipher);
            boolean gcm = cipher.contains("gcm");
            int ivLen = gcm ? 12 : 16;
            byte[] kiv = BcryptPbkdf.derive(SshBuf.utf8(passphrase), salt, (int) rounds, keyLen + ivLen);
            byte[] key = Arrays.copyOf(kiv, keyLen);
            byte[] iv = Arrays.copyOfRange(kiv, keyLen, keyLen + ivLen);
            try {
                if (gcm) {
                    try {
                        plain = new AesGcm(key).decrypt(iv, privateSection, new byte[0]);
                    } catch (SecurityException e) {
                        throw new SshException("Wrong passphrase");
                    }
                } else {
                    plain = new byte[privateSection.length];
                    new AesCtr(key, iv).process(privateSection, 0, plain.length, plain, 0);
                }
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new SshException("Cannot decrypt the key", e);
            }
        }
        if (plain.length < 8 || !Arrays.equals(Arrays.copyOfRange(plain, 0, 4), Arrays.copyOfRange(plain, 4, 8))) {
            throw new SshException(isProtected() ? "Wrong passphrase" : "This key file is damaged");
        }
        return plain;
    }

    /**
     * The key ready for signing. {@code passphrase} is ignored for an unprotected key.
     * An SshException with "Wrong passphrase" when it does not fit.
     */
    public SshIdentity unlock(String passphrase) throws IOException {
        byte[] plain = open(passphrase);
        try {
            SshBuf.Reader r = new SshBuf.Reader(plain, 8, plain.length - 8);
            String t = r.text();
            if (!type.equals(t)) throw new SshException("This key file is damaged");
            if (SshHostKey.ED25519.equals(t)) {
                byte[] pub = r.string();
                byte[] priv = r.string();
                if (pub.length != 32 || priv.length != 64) throw new SshException("This key file is damaged");
                final byte[] seed = Arrays.copyOf(priv, 32);
                if (!Arrays.equals(pub, Ed25519.publicKey(seed))
                        || !Arrays.equals(publicBlob, new SshBuf.Writer().string(t).string(pub).bytes())) {
                    throw new SshException("This key file is damaged (the public and private halves differ)");
                }
                return new SshIdentity() {
                    public byte[] publicBlob() {
                        return publicBlob.clone();
                    }

                    public String[] algorithms(String[] serverSigAlgs) {
                        return new String[] { SshHostKey.ED25519 };
                    }

                    public byte[] sign(String algorithm, byte[] data) {
                        return Ed25519.sign(seed, data);
                    }
                };
            }
            final BigInteger n = r.mpint();
            BigInteger e = r.mpint();
            final BigInteger d = r.mpint();
            if (!Arrays.equals(publicBlob, new SshBuf.Writer().string(t).mpint(e).mpint(n).bytes())) {
                throw new SshException("This key file is damaged (the public and private halves differ)");
            }
            return new SshIdentity() {
                public byte[] publicBlob() {
                    return publicBlob.clone();
                }

                public String[] algorithms(String[] serverSigAlgs) {
                    if (serverSigAlgs == null) return new String[] { SshHostKey.RSA_SHA2_512, SshHostKey.RSA_SHA2_256 };
                    java.util.List<String> out = new java.util.ArrayList<String>();
                    for (String a : new String[] { SshHostKey.RSA_SHA2_512, SshHostKey.RSA_SHA2_256 }) {
                        if (Arrays.asList(serverSigAlgs).contains(a)) out.add(a);
                    }
                    return out.toArray(new String[out.size()]);
                }

                public byte[] sign(String algorithm, byte[] data) throws IOException {
                    return rsaSign(n, d, SshHostKey.RSA_SHA2_512.equals(algorithm) ? "SHA-512" : "SHA-256", data);
                }
            };
        } finally {
            if (isProtected()) Arrays.fill(plain, (byte) 0);
        }
    }

    /** RSASSA-PKCS1-v1_5 with the platform's RSA when it has the algorithm, otherwise by hand. */
    private static byte[] rsaSign(BigInteger n, BigInteger d, String hash, byte[] data) throws IOException {
        int k = (n.bitLength() + 7) / 8;
        try {
            PrivateKey key = KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(n, d));
            Signature s = Signature.getInstance(hash.replace("-", "") + "withRSA");
            s.initSign(key);
            s.update(data);
            return s.sign();
        } catch (java.security.GeneralSecurityException e) {
            // fall through: build the signature from the definition
        }
        try {
            byte[] prefix = digestInfoPrefix(hash);
            byte[] digest = MessageDigest.getInstance(hash).digest(data);
            byte[] em = new byte[k];
            em[1] = 1;
            int tLen = prefix.length + digest.length;
            for (int i = 2; i < k - tLen - 1; i++) em[i] = (byte) 0xff;
            System.arraycopy(prefix, 0, em, k - tLen, prefix.length);
            System.arraycopy(digest, 0, em, k - digest.length, digest.length);
            byte[] s = new BigInteger(1, em).modPow(d, n).toByteArray();
            byte[] out = new byte[k];
            int len = Math.min(k, s.length);
            System.arraycopy(s, s.length - len, out, k - len, len);
            return out;
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new SshException("Cannot sign with RSA on this device", e);
        }
    }

    /** The DER DigestInfo prefix for SHA-256 or SHA-512 (RFC 8017 section 9.2). */
    private static byte[] digestInfoPrefix(String hash) {
        byte[] p = { 0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,
                0x05, 0x00, 0x04, 0x20 };
        if ("SHA-512".equals(hash)) {
            p[1] = 0x51;
            p[14] = 0x03;
            p[18] = 0x40;
        }
        return p;
    }

    // --- writing ---

    /** A new Ed25519 key file; with a passphrase it is protected with aes256-ctr and bcrypt. */
    public static SshKeyFile generateEd25519(String comment, String passphrase) throws IOException {
        byte[] seed = TlsRandom.bytes(32);
        try {
            return ed25519FromSeed(seed, comment, passphrase);
        } finally {
            Arrays.fill(seed, (byte) 0);
        }
    }

    static SshKeyFile ed25519FromSeed(byte[] seed, String comment, String passphrase) throws IOException {
        byte[] pub = Ed25519.publicKey(seed);
        byte[] priv = Arrays.copyOf(seed, 64);
        System.arraycopy(pub, 0, priv, 32, 32);
        byte[] blob = new SshBuf.Writer().string(SshHostKey.ED25519).string(pub).bytes();
        byte[] keyPart = new SshBuf.Writer().string(SshHostKey.ED25519).string(pub).string(priv).bytes();
        return write(blob, keyPart, comment, passphrase);
    }

    /** The same key under a new passphrase (null or empty: unprotected). */
    public SshKeyFile withPassphrase(String oldPassphrase, String newPassphrase) throws IOException {
        byte[] plain = open(oldPassphrase);
        // After the two check words: the key fields and the comment; the rest is padding.
        SshBuf.Reader r = new SshBuf.Reader(plain, 8, plain.length - 8);
        r.string();
        int fields = SshHostKey.ED25519.equals(type) ? 2 : 6;
        for (int i = 0; i <= fields; i++) r.string(); // the fields, then the comment
        byte[] body = Arrays.copyOfRange(plain, 8, plain.length - r.remaining());
        return write(publicBlob, body, null, newPassphrase);
    }

    /** {@code keyPart} is the type and key fields; with a null comment it already ends with its comment. */
    private static SshKeyFile write(byte[] publicBlob, byte[] keyPart, String comment, String passphrase) throws IOException {
        boolean protect = passphrase != null && passphrase.length() > 0;
        byte[] check = TlsRandom.bytes(4);
        SshBuf.Writer w = new SshBuf.Writer().raw(check).raw(check).raw(keyPart);
        if (comment != null) w.string(comment);
        int block = protect ? 16 : 8;
        for (int i = 1; w.size() % block != 0; i++) w.u8(i);
        byte[] priv = w.bytes();
        String cipher = "none";
        String kdf = "none";
        byte[] kdfOptions = new byte[0];
        if (protect) {
            cipher = "aes256-ctr";
            kdf = "bcrypt";
            byte[] salt = TlsRandom.bytes(16);
            kdfOptions = new SshBuf.Writer().string(salt).u32(DEFAULT_ROUNDS).bytes();
            byte[] kiv = BcryptPbkdf.derive(SshBuf.utf8(passphrase), salt, DEFAULT_ROUNDS, 48);
            try {
                new AesCtr(Arrays.copyOf(kiv, 32), Arrays.copyOfRange(kiv, 32, 48)).process(priv, 0, priv.length, priv, 0);
            } catch (Exception e) {
                throw new SshException("Cannot encrypt the key", e);
            }
        }
        byte[] raw = new SshBuf.Writer().raw(MAGIC).string(cipher).string(kdf).string(kdfOptions).u32(1)
                .string(publicBlob).string(priv).bytes();
        String b64 = SshBase64.encode(raw, true);
        StringBuilder sb = new StringBuilder(BEGIN).append('\n');
        for (int i = 0; i < b64.length(); i += 70) {
            sb.append(b64, i, Math.min(b64.length(), i + 70)).append('\n');
        }
        sb.append(END).append('\n');
        return parse(sb.toString());
    }

    // --- PEM RSA ---

    /** An unprotected PKCS#1 or PKCS#8 RSA key as OpenSSH key text. */
    private static String fromPemRsa(String t) throws IOException {
        if (t.contains("Proc-Type:") || t.contains("DEK-Info:")) {
            throw new SshException("This key's old-style protection is not supported; convert it with: ssh-keygen -p -f <key file>");
        }
        boolean pkcs8 = t.contains("-----BEGIN PRIVATE KEY-----");
        String begin = pkcs8 ? "-----BEGIN PRIVATE KEY-----" : "-----BEGIN RSA PRIVATE KEY-----";
        String end = pkcs8 ? "-----END PRIVATE KEY-----" : "-----END RSA PRIVATE KEY-----";
        int b = t.indexOf(begin);
        int e = t.indexOf(end);
        byte[] der = b < 0 || e < b ? null : SshBase64.decode(t.substring(b + begin.length(), e));
        if (der == null) throw new SshException("This key file is damaged");
        try {
            int[] pos = { 0 };
            int[] seq = tlv(der, pos, 0x30);
            pos[0] = seq[0];
            if (pkcs8) {
                tlv(der, pos, 0x02); // version
                int[] alg = tlv(der, pos, 0x30);
                byte[] rsaOid = { 0x06, 0x09, 0x2a, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xf7, 0x0d, 0x01, 0x01, 0x01 };
                if (alg[1] - alg[0] < rsaOid.length
                        || !Arrays.equals(rsaOid, Arrays.copyOfRange(der, alg[0], alg[0] + rsaOid.length))) {
                    throw new SshException("Only Ed25519 and RSA keys are supported");
                }
                int[] octets = tlv(der, pos, 0x04);
                pos[0] = octets[0];
                int[] inner = tlv(der, pos, 0x30);
                pos[0] = inner[0];
            }
            tlv(der, pos, 0x02); // version
            BigInteger[] v = new BigInteger[8]; // n, e, d, p, q, dP, dQ, qInv
            for (int i = 0; i < 8; i++) {
                int[] x = tlv(der, pos, 0x02);
                v[i] = new BigInteger(1, Arrays.copyOfRange(der, x[0], x[1]));
            }
            byte[] blob = new SshBuf.Writer().string(SshHostKey.RSA).mpint(v[1]).mpint(v[0]).bytes();
            byte[] keyPart = new SshBuf.Writer().string(SshHostKey.RSA).mpint(v[0]).mpint(v[1]).mpint(v[2])
                    .mpint(v[7]).mpint(v[3]).mpint(v[4]).bytes();
            return write(blob, keyPart, "", null).text();
        } catch (ArrayIndexOutOfBoundsException ex) {
            throw new SshException("This key file is damaged");
        }
    }

    /** Reads one DER element with the given tag at pos; returns {content start, content end} and moves pos past it. */
    private static int[] tlv(byte[] der, int[] pos, int tag) throws IOException {
        int p = pos[0];
        if ((der[p] & 0xff) != tag) throw new SshException("This key file is damaged");
        int len = der[p + 1] & 0xff;
        p += 2;
        if (len >= 0x80) {
            int n = len & 0x7f;
            if (n < 1 || n > 3) throw new SshException("This key file is damaged");
            len = 0;
            for (int i = 0; i < n; i++) len = (len << 8) | (der[p++] & 0xff);
        }
        if (len > der.length - p) throw new SshException("This key file is damaged");
        pos[0] = p + len;
        return new int[] { p, p + len };
    }
}
