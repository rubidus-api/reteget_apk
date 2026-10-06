package org.reteget.core.ssh;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.LinkedList;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import org.reteget.core.tls.AesGcm;
import org.reteget.core.tls.EcCurve;
import org.reteget.core.tls.TlsRandom;
import org.reteget.core.tls.X25519;

/**
 * The SSH transport layer (RFC 4253) as a client: version exchange, key exchange, server
 * authentication by host key, and the encrypted packet stream with re-keying.
 *
 * <p>Algorithms, by choice a small modern set (no SHA-1, no CBC, no compression):
 * <ul>
 * <li>key exchange: curve25519-sha256 (RFC 8731), ecdh-sha2-nistp256 (RFC 5656),
 *     diffie-hellman-group14-sha256 (RFC 8268);</li>
 * <li>host keys: ssh-ed25519, ecdsa-sha2-nistp256, rsa-sha2-512, rsa-sha2-256;</li>
 * <li>ciphers: aes128/256-ctr with hmac-sha2-256, aes128/256-gcm@openssh.com.</li>
 * </ul>
 * Strict key exchange (kex-strict-c-v00@openssh.com) is used when the server offers it. The
 * cipher and MAC modes offered are not open to the Terrapin prefix truncation either way: GCM,
 * and encrypt-and-MAC (never the -etm variants) for CTR.
 *
 * <p>One thread drives a connection: {@link #send} and {@link #receive} are not synchronised.
 * A re-key started by either side runs inside those calls.
 */
public final class SshTransport {

    /** Decides whether the server's host key is the right one. */
    public interface HostKeyCheck {
        /**
         * Called once per connection, after the server proved that it holds {@code key} and
         * before anything secret is sent. Throw to refuse the server.
         */
        void check(SshHostKey key) throws IOException;
    }

    static final int MSG_DISCONNECT = 1;
    static final int MSG_IGNORE = 2;
    static final int MSG_UNIMPLEMENTED = 3;
    static final int MSG_DEBUG = 4;
    static final int MSG_SERVICE_REQUEST = 5;
    static final int MSG_SERVICE_ACCEPT = 6;
    static final int MSG_EXT_INFO = 7;
    static final int MSG_KEXINIT = 20;
    static final int MSG_NEWKEYS = 21;
    static final int MSG_KEX_INIT = 30;
    static final int MSG_KEX_REPLY = 31;

    static final String KEX_CURVE25519 = "curve25519-sha256";
    static final String KEX_CURVE25519_LIBSSH = "curve25519-sha256@libssh.org";
    static final String KEX_ECDH_P256 = "ecdh-sha2-nistp256";
    static final String KEX_DH14_SHA256 = "diffie-hellman-group14-sha256";
    static final String KEX_STRICT_CLIENT = "kex-strict-c-v00@openssh.com";
    static final String KEX_STRICT_SERVER = "kex-strict-s-v00@openssh.com";
    static final String EXT_INFO_CLIENT = "ext-info-c";

    static final String AES128_CTR = "aes128-ctr";
    static final String AES256_CTR = "aes256-ctr";
    static final String AES128_GCM = "aes128-gcm@openssh.com";
    static final String AES256_GCM = "aes256-gcm@openssh.com";
    static final String HMAC_SHA2_256 = "hmac-sha2-256";

    /** RFC 3526 group 14: the 2048-bit MODP prime, generator 2. */
    static final BigInteger DH14_P = new BigInteger(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
            + "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
            + "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
            + "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
            + "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
            + "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16);

    private static final int MAX_PACKET = 256 * 1024;
    private static final int MAX_BANNER = 16 * 1024;
    static final String CLIENT_VERSION = "SSH-2.0-ReteGet";

    /** Keys and counters of one direction. */
    private static final class Direction {
        AesCtr ctr;
        Mac mac;
        AesGcm gcm;
        byte[] gcmIv;
        long seq;
        long bytes;

        int block() {
            return ctr != null || gcm != null ? 16 : 8;
        }
    }

    private final InputStream in;
    private final OutputStream out;
    private final HostKeyCheck hostKeyCheck;
    private final String preferredHostKeyType;

    private final Direction send = new Direction();
    private final Direction recv = new Direction();
    private final LinkedList<byte[]> pending = new LinkedList<byte[]>();

    private String serverVersion;
    private byte[] sessionId;
    private SshHostKey hostKey;
    private boolean strict;
    private boolean firstKexDone;
    private String kexAlg, hostKeyAlg, cipherOut, cipherIn;
    private String[] serverSigAlgs;
    private long lastKexAt;

    /** Re-key after this many bytes in both directions, or this much time; package-private for tests. */
    long rekeyBytes = 1L << 30;
    long rekeyMillis = 60L * 60 * 1000;
    /** Counts completed key exchanges (tests). */
    int kexCount;

    /**
     * @param preferredHostKeyType the key type recorded for this server, tried first so that a
     *                             server with several keys shows the known one; null when unknown
     */
    public SshTransport(InputStream in, OutputStream out, HostKeyCheck hostKeyCheck, String preferredHostKeyType) {
        this.in = in;
        this.out = out;
        this.hostKeyCheck = hostKeyCheck;
        this.preferredHostKeyType = preferredHostKeyType;
    }

    /** Version exchange and the first key exchange; the host key has been checked when this returns. */
    public void connect() throws IOException {
        out.write((CLIENT_VERSION + "\r\n").getBytes("US-ASCII"));
        out.flush();
        serverVersion = readServerVersion();

        byte[] mine = buildKexinit();
        writePacket(mine);
        boolean sawOther = false;
        byte[] theirs;
        while (true) {
            theirs = readPacket();
            int type = theirs[0] & 0xff;
            if (type == MSG_KEXINIT) break;
            if (type == MSG_DISCONNECT) throw disconnected(theirs);
            if (type != MSG_IGNORE && type != MSG_DEBUG) {
                throw new SshException("unexpected SSH message " + type + " before the key exchange");
            }
            sawOther = true;
        }
        strict = contains(new SshBuf.Reader(theirs, 17, theirs.length - 17).nameList(), KEX_STRICT_SERVER);
        if (strict && sawOther) {
            throw new SshException("the server broke strict key exchange (a message before KEXINIT)");
        }
        runKex(mine, theirs);
    }

    public byte[] sessionId() {
        return sessionId.clone();
    }

    public SshHostKey hostKey() {
        return hostKey;
    }

    /** Signature algorithms the server said it accepts for public-key authentication (RFC 8308), or null. */
    public String[] serverSigAlgs() {
        return serverSigAlgs;
    }

    public String serverVersion() {
        return serverVersion;
    }

    /** One line for the user, e.g. "SSH curve25519-sha256 aes128-ctr ssh-ed25519". */
    public String summary() {
        return "SSH " + kexAlg + " " + cipherIn + " " + hostKeyAlg;
    }

    /** Asks for a service such as "ssh-userauth" (RFC 4253 section 10). */
    public void requestService(String name) throws IOException {
        send(new SshBuf.Writer().u8(MSG_SERVICE_REQUEST).string(name).bytes());
        byte[] p = receive();
        if ((p[0] & 0xff) != MSG_SERVICE_ACCEPT) {
            throw new SshException("the server did not accept the " + name + " service");
        }
    }

    /** Sends one message; re-keys first when the limits are reached. */
    public void send(byte[] payload) throws IOException {
        if (firstKexDone && (send.bytes + recv.bytes > rekeyBytes
                || System.currentTimeMillis() - lastKexAt > rekeyMillis)) {
            rekey();
        }
        writePacket(payload);
    }

    /** The next message that is not the transport layer's own business. */
    public byte[] receive() throws IOException {
        while (true) {
            if (!pending.isEmpty()) return pending.removeFirst();
            byte[] p = readPacket();
            if (!handledByTransport(p)) return p;
        }
    }

    /** Tells the server we are leaving; errors are ignored. */
    public void disconnect() {
        try {
            writePacket(new SshBuf.Writer().u8(MSG_DISCONNECT).u32(11).string("bye").string("").bytes());
        } catch (Exception ignored) {
        }
    }

    // --- transport messages and re-keying ---

    private boolean handledByTransport(byte[] p) throws IOException {
        switch (p[0] & 0xff) {
            case MSG_DISCONNECT:
                throw disconnected(p);
            case MSG_IGNORE:
            case MSG_DEBUG:
            case MSG_UNIMPLEMENTED:
                return true;
            case MSG_EXT_INFO:
                readExtInfo(p);
                return true;
            case MSG_KEXINIT: {
                byte[] mine = buildKexinit();
                writePacket(mine);
                runKex(mine, p);
                return true;
            }
            default:
                return false;
        }
    }

    private void rekey() throws IOException {
        byte[] mine = buildKexinit();
        writePacket(mine);
        // The server may still be sending data it queued before it saw our KEXINIT.
        while (true) {
            byte[] p = readPacket();
            int type = p[0] & 0xff;
            if (type == MSG_KEXINIT) {
                runKex(mine, p);
                return;
            }
            if (type == MSG_DISCONNECT) throw disconnected(p);
            if (type == MSG_IGNORE || type == MSG_DEBUG || type == MSG_UNIMPLEMENTED) continue;
            if (type == MSG_EXT_INFO) {
                readExtInfo(p);
                continue;
            }
            pending.addLast(p);
        }
    }

    private void readExtInfo(byte[] p) throws IOException {
        SshBuf.Reader r = new SshBuf.Reader(p, 1, p.length - 1);
        long n = r.u32();
        for (long i = 0; i < n && r.remaining() > 0; i++) {
            String name = r.text();
            byte[] value = r.string();
            if ("server-sig-algs".equals(name)) {
                String v = SshBuf.fromUtf8(value);
                serverSigAlgs = v.length() == 0 ? new String[0] : v.split(",");
            }
        }
    }

    private static SshException disconnected(byte[] p) {
        String text = "";
        long code = 0;
        try {
            SshBuf.Reader r = new SshBuf.Reader(p, 1, p.length - 1);
            code = r.u32();
            text = SshHostKey.printable(r.text());
        } catch (IOException ignored) {
        }
        return new SshException("the server closed the connection"
                + (text.length() > 0 ? ": " + text : " (code " + code + ")"));
    }

    // --- key exchange ---

    private String[] hostKeyAlgorithms() {
        String[] all = { SshHostKey.ED25519, SshHostKey.ECDSA_P256, SshHostKey.RSA_SHA2_512, SshHostKey.RSA_SHA2_256 };
        if (preferredHostKeyType == null) return all;
        String[] out = new String[all.length];
        int n = 0;
        for (String a : all) {
            if (preferredHostKeyType.equals(SshHostKey.keyTypeOf(a))) out[n++] = a;
        }
        for (String a : all) {
            if (!preferredHostKeyType.equals(SshHostKey.keyTypeOf(a))) out[n++] = a;
        }
        return out;
    }

    private static final String[] KEX_ALGS = { KEX_CURVE25519, KEX_CURVE25519_LIBSSH, KEX_ECDH_P256, KEX_DH14_SHA256 };
    private static final String[] CIPHERS = { AES128_CTR, AES128_GCM, AES256_CTR, AES256_GCM };
    private static final String[] MACS = { HMAC_SHA2_256 };
    private static final String[] NONE = { "none" };

    private byte[] buildKexinit() {
        String[] kex = new String[KEX_ALGS.length + (firstKexDone ? 0 : 2)];
        System.arraycopy(KEX_ALGS, 0, kex, 0, KEX_ALGS.length);
        if (!firstKexDone) { // the two pseudo-algorithms only count in the first KEXINIT
            kex[KEX_ALGS.length] = EXT_INFO_CLIENT;
            kex[KEX_ALGS.length + 1] = KEX_STRICT_CLIENT;
        }
        return new SshBuf.Writer().u8(MSG_KEXINIT).raw(TlsRandom.bytes(16))
                .nameList(kex).nameList(hostKeyAlgorithms())
                .nameList(CIPHERS).nameList(CIPHERS).nameList(MACS).nameList(MACS)
                .nameList(NONE).nameList(NONE).nameList(new String[0]).nameList(new String[0])
                .bool(false).u32(0).bytes();
    }

    private static boolean contains(String[] list, String name) {
        for (String s : list) {
            if (s.equals(name)) return true;
        }
        return false;
    }

    /** The first of ours that the server also lists (RFC 4253 section 7.1). */
    private static String choose(String what, String[] ours, String[] theirs) throws IOException {
        for (String a : ours) {
            if (contains(theirs, a)) return a;
        }
        StringBuilder sb = new StringBuilder();
        for (String s : theirs) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(s);
        }
        throw new SshException("no common " + what + "; the server offers: " + SshHostKey.printable(sb.toString()));
    }

    private void runKex(byte[] mine, byte[] theirs) throws IOException {
        SshBuf.Reader r = new SshBuf.Reader(theirs, 17, theirs.length - 17);
        String[] sKex = r.nameList();
        String[] sHostKey = r.nameList();
        String[] sCipherOut = r.nameList(); // client to server
        String[] sCipherIn = r.nameList();
        String[] sMacOut = r.nameList();
        String[] sMacIn = r.nameList();
        String[] sCompOut = r.nameList();
        String[] sCompIn = r.nameList();
        r.nameList();
        r.nameList();
        boolean firstFollows = r.bool();

        kexAlg = choose("key exchange method", KEX_ALGS, sKex);
        String[] hostAlgs = hostKeyAlgorithms();
        hostKeyAlg = choose("host key type", hostAlgs, sHostKey);
        cipherOut = choose("cipher", CIPHERS, sCipherOut);
        cipherIn = choose("cipher", CIPHERS, sCipherIn);
        if (!isGcm(cipherOut)) choose("MAC", MACS, sMacOut);
        if (!isGcm(cipherIn)) choose("MAC", MACS, sMacIn);
        choose("compression method", NONE, sCompOut);
        choose("compression method", NONE, sCompIn);
        if (firstFollows && (sKex.length == 0 || !sKex[0].equals(kexAlg)
                || sHostKey.length == 0 || !sHostKey[0].equals(hostKeyAlg))) {
            readKexPacket(-1); // the server's wrong guess
        }

        byte[] kS, sig, k;
        SshBuf.Writer h = new SshBuf.Writer().string(CLIENT_VERSION).string(serverVersion).string(mine).string(theirs);
        try {
            if (KEX_DH14_SHA256.equals(kexAlg)) {
                BigInteger x = new BigInteger(1, TlsRandom.bytes(48));
                BigInteger e = BigInteger.valueOf(2).modPow(x, DH14_P);
                writePacket(new SshBuf.Writer().u8(MSG_KEX_INIT).mpint(e).bytes());
                SshBuf.Reader rep = reply();
                kS = rep.string();
                BigInteger f = rep.mpint();
                sig = rep.string();
                if (f.compareTo(BigInteger.ONE) <= 0 || f.compareTo(DH14_P.subtract(BigInteger.ONE)) >= 0) {
                    throw new SshException("invalid Diffie-Hellman value from the server");
                }
                k = new SshBuf.Writer().mpint(f.modPow(x, DH14_P)).bytes();
                h.string(kS).mpint(e).mpint(f);
            } else if (KEX_ECDH_P256.equals(kexAlg)) {
                BigInteger d = EcCurve.P256.randomScalar();
                byte[] qc = EcCurve.P256.encodePoint(EcCurve.P256.multiplyBase(d));
                writePacket(new SshBuf.Writer().u8(MSG_KEX_INIT).string(qc).bytes());
                SshBuf.Reader rep = reply();
                kS = rep.string();
                byte[] qs = rep.string();
                sig = rep.string();
                k = new SshBuf.Writer().mpint(EcCurve.P256.ecdh(d, EcCurve.P256.decodePoint(qs))).bytes();
                h.string(kS).string(qc).string(qs);
            } else {
                byte[] priv = TlsRandom.bytes(32);
                byte[] qc = X25519.publicKey(priv);
                writePacket(new SshBuf.Writer().u8(MSG_KEX_INIT).string(qc).bytes());
                SshBuf.Reader rep = reply();
                kS = rep.string();
                byte[] qs = rep.string();
                sig = rep.string();
                if (qs.length != 32) throw new SshException("invalid curve25519 value from the server");
                byte[] shared = X25519.scalarMult(priv, qs);
                java.util.Arrays.fill(priv, (byte) 0);
                if (X25519.isAllZero(shared)) throw new SshException("invalid curve25519 value from the server");
                k = new SshBuf.Writer().mpint(shared).bytes(); // RFC 8731: the bytes as a big-endian number
                h.string(kS).string(qc).string(qs);
            }
        } catch (IllegalArgumentException e) {
            throw new SshException("invalid key exchange value from the server");
        }
        byte[] exchangeHash = sha256(h.raw(k).bytes());

        SshHostKey key = SshHostKey.parse(kS);
        if (!key.verify(hostKeyAlg, exchangeHash, sig)) {
            throw new SshException("the server's host key signature is wrong");
        }
        if (!firstKexDone) {
            sessionId = exchangeHash;
            hostKey = key;
            hostKeyCheck.check(key);
        } else if (!key.equals(hostKey)) {
            throw new SshException("the server's host key changed during the connection");
        }

        writePacket(new byte[] { MSG_NEWKEYS });
        setKeys(send, cipherOut, k, exchangeHash, 'A', 'C', 'E');
        readKexPacket(MSG_NEWKEYS);
        setKeys(recv, cipherIn, k, exchangeHash, 'B', 'D', 'F');
        java.util.Arrays.fill(k, (byte) 0);
        firstKexDone = true;
        lastKexAt = System.currentTimeMillis();
        kexCount++;
    }

    private SshBuf.Reader reply() throws IOException {
        byte[] p = readKexPacket(MSG_KEX_REPLY);
        return new SshBuf.Reader(p, 1, p.length - 1);
    }

    /**
     * The next key exchange message, which must be of {@code type} (-1: any). In the first,
     * strict key exchange nothing else may arrive at all.
     */
    private byte[] readKexPacket(int type) throws IOException {
        while (true) {
            byte[] p = readPacket();
            int t = p[0] & 0xff;
            if (t == type || type == -1) return p;
            if (t == MSG_DISCONNECT) throw disconnected(p);
            if ((t == MSG_IGNORE || t == MSG_DEBUG || t == MSG_UNIMPLEMENTED) && !(strict && !firstKexDone)) continue;
            throw new SshException("unexpected SSH message " + t + " during the key exchange");
        }
    }

    private static boolean isGcm(String cipher) {
        return AES128_GCM.equals(cipher) || AES256_GCM.equals(cipher);
    }

    private void setKeys(Direction d, String cipher, byte[] k, byte[] h, char ivLetter, char keyLetter, char macLetter)
            throws IOException {
        int keyLen = AES256_CTR.equals(cipher) || AES256_GCM.equals(cipher) ? 32 : 16;
        try {
            if (isGcm(cipher)) {
                d.gcm = new AesGcm(derive(k, h, keyLetter, keyLen));
                d.gcmIv = derive(k, h, ivLetter, 12);
                d.ctr = null;
                d.mac = null;
            } else {
                d.ctr = new AesCtr(derive(k, h, keyLetter, keyLen), derive(k, h, ivLetter, 16));
                Mac mac = Mac.getInstance("HmacSHA256");
                mac.init(new SecretKeySpec(derive(k, h, macLetter, 32), "HmacSHA256"));
                d.mac = mac;
                d.gcm = null;
                d.gcmIv = null;
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException("cannot set up " + cipher, e);
        }
        d.bytes = 0;
        if (strict) d.seq = 0;
    }

    /** RFC 4253 section 7.2: HASH(K || H || letter || session_id), extended with HASH(K || H || so far). */
    private byte[] derive(byte[] k, byte[] h, char letter, int len) {
        byte[] out = sha256(new SshBuf.Writer().raw(k).raw(h).u8(letter).raw(sessionId).bytes());
        while (out.length < len) {
            byte[] more = sha256(new SshBuf.Writer().raw(k).raw(h).raw(out).bytes());
            byte[] joined = new byte[out.length + more.length];
            System.arraycopy(out, 0, joined, 0, out.length);
            System.arraycopy(more, 0, joined, out.length, more.length);
            out = joined;
        }
        if (out.length == len) return out;
        byte[] cut = new byte[len];
        System.arraycopy(out, 0, cut, 0, len);
        return cut;
    }

    private static byte[] sha256(byte[] b) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(b);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    // --- packets ---

    private String readServerVersion() throws IOException {
        int total = 0;
        StringBuilder line = new StringBuilder();
        while (true) {
            int c = in.read();
            if (c < 0) throw new EOFException("the server closed the connection before identifying itself");
            if (++total > MAX_BANNER) throw new SshException("this does not look like an SSH server");
            if (c == '\n') {
                String s = line.toString();
                if (s.endsWith("\r")) s = s.substring(0, s.length() - 1);
                if (s.startsWith("SSH-")) {
                    if (!s.startsWith("SSH-2.0-") && !s.startsWith("SSH-1.99-")) {
                        throw new SshException("the server only speaks " + SshHostKey.printable(s) + " (SSH-2 needed)");
                    }
                    return s;
                }
                line.setLength(0); // a line of text before the version (RFC 4253 section 4.2)
            } else {
                line.append((char) c);
            }
        }
    }

    private void readFully(byte[] b, int off, int len) throws IOException {
        while (len > 0) {
            int n = in.read(b, off, len);
            if (n < 0) throw new EOFException("the SSH connection was closed");
            off += n;
            len -= n;
        }
    }

    private static void putU32(byte[] b, int off, long v) {
        b[off] = (byte) (v >>> 24);
        b[off + 1] = (byte) (v >>> 16);
        b[off + 2] = (byte) (v >>> 8);
        b[off + 3] = (byte) v;
    }

    private static long getU32(byte[] b, int off) {
        return ((long) (b[off] & 0xff) << 24) | ((b[off + 1] & 0xff) << 16) | ((b[off + 2] & 0xff) << 8) | (b[off + 3] & 0xff);
    }

    private static void nextNonce(byte[] iv) {
        for (int i = 11; i >= 4; i--) {
            if (++iv[i] != 0) break;
        }
    }

    private void writePacket(byte[] payload) throws IOException {
        Direction d = send;
        int block = d.block();
        int body = 1 + payload.length;
        int padded = d.gcm != null ? body : body + 4;
        int pad = block - padded % block;
        if (pad < 4) pad += block;
        int packetLen = body + pad;
        byte[] p = new byte[4 + packetLen];
        putU32(p, 0, packetLen);
        p[4] = (byte) pad;
        System.arraycopy(payload, 0, p, 5, payload.length);
        byte[] padding = TlsRandom.bytes(pad);
        System.arraycopy(padding, 0, p, 5 + payload.length, pad);
        try {
            if (d.gcm != null) {
                byte[] aad = { p[0], p[1], p[2], p[3] };
                byte[] ct = d.gcm.encrypt(d.gcmIv, p, 4, packetLen, aad);
                nextNonce(d.gcmIv);
                out.write(aad);
                out.write(ct);
            } else if (d.ctr != null) {
                byte[] seq = new byte[4];
                putU32(seq, 0, d.seq);
                d.mac.update(seq);
                byte[] mac = d.mac.doFinal(p);
                d.ctr.process(p, 0, p.length, p, 0);
                out.write(p);
                out.write(mac);
            } else {
                out.write(p);
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException("cannot encrypt an SSH packet", e);
        }
        out.flush();
        d.seq = (d.seq + 1) & 0xffffffffL;
        d.bytes += p.length;
    }

    /** Reads, authenticates and decrypts one packet; returns its payload (at least one byte). */
    private byte[] readPacket() throws IOException {
        Direction d = recv;
        byte[] p; // padding length, payload, padding
        try {
            if (d.gcm != null) {
                byte[] lenBytes = new byte[4];
                readFully(lenBytes, 0, 4);
                long len = getU32(lenBytes, 0);
                if (len < 16 || len > MAX_PACKET || len % 16 != 0) throw new SshException("corrupt SSH packet (length)");
                byte[] ct = new byte[(int) len + AesGcm.TAG_LEN];
                readFully(ct, 0, ct.length);
                try {
                    p = d.gcm.decrypt(d.gcmIv, ct, 0, ct.length, lenBytes);
                } catch (SecurityException e) {
                    throw new SshException("corrupt SSH packet (authentication failed)");
                }
                nextNonce(d.gcmIv);
            } else if (d.ctr != null) {
                byte[] first = new byte[16];
                readFully(first, 0, 16);
                d.ctr.process(first, 0, 16, first, 0);
                long len = getU32(first, 0);
                if (len < 12 || len > MAX_PACKET || (len + 4) % 16 != 0) throw new SshException("corrupt SSH packet (length)");
                byte[] whole = new byte[(int) len + 4];
                System.arraycopy(first, 0, whole, 0, 16);
                readFully(whole, 16, whole.length - 16);
                d.ctr.process(whole, 16, whole.length - 16, whole, 16);
                byte[] mac = new byte[32];
                readFully(mac, 0, 32);
                byte[] seq = new byte[4];
                putU32(seq, 0, d.seq);
                d.mac.update(seq);
                if (!MessageDigest.isEqual(d.mac.doFinal(whole), mac)) {
                    throw new SshException("corrupt SSH packet (authentication failed)");
                }
                p = new byte[(int) len];
                System.arraycopy(whole, 4, p, 0, p.length);
            } else {
                byte[] lenBytes = new byte[4];
                readFully(lenBytes, 0, 4);
                long len = getU32(lenBytes, 0);
                if (len < 12 || len > MAX_PACKET || (len + 4) % 8 != 0) throw new SshException("corrupt SSH packet (length)");
                p = new byte[(int) len];
                readFully(p, 0, p.length);
            }
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new SshException("cannot decrypt an SSH packet", e);
        }
        int pad = p[0] & 0xff;
        int payloadLen = p.length - 1 - pad;
        if (pad < 4 || payloadLen < 1) throw new SshException("corrupt SSH packet (padding)");
        d.seq = (d.seq + 1) & 0xffffffffL;
        d.bytes += p.length + 4;
        byte[] payload = new byte[payloadLen];
        System.arraycopy(p, 1, payload, 0, payloadLen);
        return payload;
    }
}
