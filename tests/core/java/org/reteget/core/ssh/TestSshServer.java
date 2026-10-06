package org.reteget.core.ssh;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.interfaces.XECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.NamedParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPublicKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * An SSH server with an SFTP subsystem for the tests, on 127.0.0.1. Every cryptographic
 * operation is the JDK's (JCA: X25519, ECDH, Ed25519, ECDSA, RSA, AES/CTR, AES/GCM, HmacSHA256),
 * so it is an implementation independent of the client under test, as the JDK TLS server is for
 * the TLS tests. Needs JDK 15 or newer. The fields configure what it offers and how it misbehaves.
 */
final class TestSshServer implements Runnable {

    // --- configuration ---
    String[] kexAlgs = { "curve25519-sha256", "ecdh-sha2-nistp256", "diffie-hellman-group14-sha256" };
    String hostKeyType = "ssh-ed25519"; // or ecdsa-sha2-nistp256, ssh-rsa
    String[] rsaSigAlgs = { "rsa-sha2-512", "rsa-sha2-256" };
    String[] ciphers = { "aes128-ctr", "aes256-ctr", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com" };
    String[] macs = { "hmac-sha2-256" };
    boolean strict = true;
    boolean ignoreBeforeKexinit;
    boolean ignoreDuringKex;
    boolean debugBeforeNewkeys;
    boolean corruptSignature;
    String versionLine = "SSH-2.0-TestSshServer_1.0";
    String[] linesBeforeVersion = new String[0];
    /** Start a server-side re-key each time this many file bytes went out (-1: never). */
    long rekeyAfterFileBytes = -1;

    String user = "user";
    String password = "pw";
    boolean allowPassword = true;
    boolean allowKeyboardInteractive;
    boolean passwordChangeRequired;
    final List<byte[]> authorizedKeys = new ArrayList<byte[]>();
    String[] serverSigAlgs; // sent as EXT_INFO when not null

    final Map<String, byte[]> files = new HashMap<String, byte[]>();
    final Map<String, Long> mtimes = new HashMap<String, Long>();
    final List<String> directories = new ArrayList<String>();
    boolean noSftp;
    /** Close the socket after this many file bytes, on the first connection only (-1: never). */
    long cutAfterFileBytes = -1;
    /** Every n-th READ answers with half of what was asked (0: never). */
    int shortReadEvery;
    boolean reverseAnswers;

    // --- observations ---
    final List<String> log = Collections.synchronizedList(new ArrayList<String>());
    volatile int connections;
    volatile int kexCount;
    volatile String lastCipher, lastKex, lastHostKeyAlg;

    private final ServerSocket ss;
    private volatile boolean closed;
    private KeyPair hostKeyPair;
    private final SecureRandom random = new SecureRandom();

    TestSshServer() throws IOException {
        ss = new ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"));
    }

    TestSshServer start() throws Exception {
        hostKeyPair = generate(hostKeyType);
        Thread t = new Thread(this, "TestSshServer");
        t.setDaemon(true);
        t.start();
        return this;
    }

    /** A new host key, as if the server had been reinstalled (or replaced by an attacker). */
    void newHostKey() throws Exception {
        hostKeyPair = generate(hostKeyType);
    }

    int port() {
        return ss.getLocalPort();
    }

    byte[] hostKeyBlob() throws Exception {
        return blob(hostKeyPair.getPublic());
    }

    void close() {
        closed = true;
        try {
            ss.close();
        } catch (IOException ignored) {
        }
    }

    static KeyPair generate(String type) throws Exception {
        if ("ssh-ed25519".equals(type)) return KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        if ("ecdsa-sha2-nistp256".equals(type)) {
            KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
            g.initialize(new ECGenParameterSpec("secp256r1"));
            return g.generateKeyPair();
        }
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(2048);
        return g.generateKeyPair();
    }

    /** The SSH public key blob of a JDK public key. */
    static byte[] blob(PublicKey k) throws Exception {
        W w = new W();
        if (k instanceof RSAPublicKey) {
            RSAPublicKey r = (RSAPublicKey) k;
            return w.str("ssh-rsa").mpint(r.getPublicExponent()).mpint(r.getModulus()).bytes();
        }
        if (k instanceof ECPublicKey) {
            return w.str("ecdsa-sha2-nistp256").str("nistp256").str(point((ECPublicKey) k)).bytes();
        }
        byte[] spki = k.getEncoded();
        return w.str("ssh-ed25519").str(Arrays.copyOfRange(spki, spki.length - 32, spki.length)).bytes();
    }

    static byte[] point(ECPublicKey k) {
        byte[] out = new byte[65];
        out[0] = 4;
        fixed(k.getW().getAffineX(), out, 1);
        fixed(k.getW().getAffineY(), out, 33);
        return out;
    }

    private static void fixed(BigInteger v, byte[] out, int off) {
        byte[] b = v.toByteArray();
        int n = Math.min(32, b.length);
        System.arraycopy(b, b.length - n, out, off + 32 - n, n);
    }

    public void run() {
        while (!closed) {
            final Socket s;
            try {
                s = ss.accept();
            } catch (IOException e) {
                return;
            }
            final int number = ++connections;
            Thread t = new Thread(new Runnable() {
                public void run() {
                    try {
                        new Conn(s, number).serve();
                    } catch (EOFException e) {
                        // the client went away
                    } catch (Exception e) {
                        log.add("server error: " + e);
                    } finally {
                        try {
                            s.close();
                        } catch (IOException ignored) {
                        }
                    }
                }
            }, "TestSshServer-conn");
            t.setDaemon(true);
            t.start();
        }
    }

    /** Minimal writer of SSH types (kept apart from the client's SshBuf on purpose). */
    static final class W {
        final ByteArrayOutputStream o = new ByteArrayOutputStream();

        W u8(int v) {
            o.write(v);
            return this;
        }

        W u32(long v) {
            o.write((int) (v >>> 24));
            o.write((int) (v >>> 16));
            o.write((int) (v >>> 8));
            o.write((int) v);
            return this;
        }

        W u64(long v) {
            return u32(v >>> 32).u32(v);
        }

        W raw(byte[] b) {
            o.write(b, 0, b.length);
            return this;
        }

        W str(byte[] b) {
            return u32(b.length).raw(b);
        }

        W str(String s) {
            return str(s.getBytes(java.nio.charset.StandardCharsets.UTF_8));
        }

        W mpint(BigInteger v) {
            return str(v.signum() == 0 ? new byte[0] : v.toByteArray());
        }

        W names(String[] n) {
            return str(String.join(",", n));
        }

        byte[] bytes() {
            return o.toByteArray();
        }
    }

    static final class R {
        final byte[] b;
        int p;

        R(byte[] b, int off) {
            this.b = b;
            this.p = off;
        }

        int u8() {
            return b[p++] & 0xff;
        }

        long u32() {
            long v = ((long) (b[p] & 0xff) << 24) | ((b[p + 1] & 0xff) << 16) | ((b[p + 2] & 0xff) << 8) | (b[p + 3] & 0xff);
            p += 4;
            return v;
        }

        long u64() {
            long hi = u32();
            return (hi << 32) | u32();
        }

        byte[] str() {
            int n = (int) u32();
            byte[] r = Arrays.copyOfRange(b, p, p + n);
            p += n;
            return r;
        }

        String text() {
            return new String(str(), java.nio.charset.StandardCharsets.UTF_8);
        }

        String[] names() {
            String s = text();
            return s.isEmpty() ? new String[0] : s.split(",");
        }
    }

    private final class Conn {
        final Socket socket;
        final int number;
        final InputStream in;
        final OutputStream out;

        // one direction's keys
        Cipher ctrOut, ctrIn;
        Mac macOut, macIn;
        SecretKeySpec gcmKeyOut, gcmKeyIn;
        byte[] gcmIvOut, gcmIvIn;
        long seqOut, seqIn;

        String clientVersion;
        byte[] sessionId;
        boolean clientStrict, clientExtInfo, firstKexDone, authenticated;
        long clientChannel, clientWindow, clientMaxPacket;
        final LinkedList<byte[]> outQueue = new LinkedList<byte[]>();
        final ByteArrayOutputStream sftpIn = new ByteArrayOutputStream();
        long fileBytesSent, fileBytesSinceRekey;
        int reads;
        final Map<String, String> handles = new HashMap<String, String>();
        int nextHandle;

        Conn(Socket s, int number) throws IOException {
            this.socket = s;
            this.number = number;
            s.setSoTimeout(10000);
            this.in = new BufferedInputStream(s.getInputStream());
            this.out = new BufferedOutputStream(s.getOutputStream());
        }

        void serve() throws Exception {
            for (String l : linesBeforeVersion) out.write((l + "\r\n").getBytes("US-ASCII"));
            out.write((versionLine + "\r\n").getBytes("US-ASCII"));
            out.flush();
            StringBuilder sb = new StringBuilder();
            int c;
            while ((c = in.read()) != '\n') {
                if (c < 0) throw new EOFException();
                sb.append((char) c);
            }
            clientVersion = sb.toString().trim();

            if (ignoreBeforeKexinit) send(new W().u8(2).str("x").bytes());
            byte[] mine = kexinit();
            send(mine);
            byte[] theirs = recv();
            if ((theirs[0] & 0xff) != 20) throw new IOException("expected KEXINIT, got " + (theirs[0] & 0xff));
            kex(mine, theirs);

            while (true) {
                byte[] p = recv();
                handle(p);
                flush();
                if (rekeyAfterFileBytes >= 0 && fileBytesSinceRekey >= rekeyAfterFileBytes && authenticated) {
                    fileBytesSinceRekey = 0;
                    byte[] k = kexinit();
                    send(k);
                    List<byte[]> deferred = new ArrayList<byte[]>();
                    while (true) {
                        byte[] q = recv();
                        if ((q[0] & 0xff) == 20) {
                            kex(k, q);
                            break;
                        }
                        deferred.add(q);
                    }
                    for (byte[] q : deferred) handle(q);
                    flush();
                }
            }
        }

        byte[] kexinit() {
            String[] k = kexAlgs;
            if (strict && !firstKexDone) {
                k = Arrays.copyOf(kexAlgs, kexAlgs.length + 1);
                k[kexAlgs.length] = "kex-strict-s-v00@openssh.com";
            }
            String[] hk = "ssh-rsa".equals(hostKeyType) ? rsaSigAlgs : new String[] { hostKeyType };
            byte[] cookie = new byte[16];
            random.nextBytes(cookie);
            return new W().u8(20).raw(cookie).names(k).names(hk).names(ciphers).names(ciphers).names(macs).names(macs)
                    .names(new String[] { "none" }).names(new String[] { "none" }).names(new String[0]).names(new String[0])
                    .u8(0).u32(0).bytes();
        }

        String pick(String[] client, String[] server) throws IOException {
            for (String c : client) {
                for (String s : server) {
                    if (c.equals(s)) return c;
                }
            }
            throw new IOException("no common algorithm");
        }

        void kex(byte[] mine, byte[] theirs) throws Exception {
            R r = new R(theirs, 17);
            String[] cKex = r.names();
            String[] cHostKey = r.names();
            String[] cCipherC2S = r.names();
            String[] cCipherS2C = r.names();
            if (!firstKexDone) {
                clientStrict = Arrays.asList(cKex).contains("kex-strict-c-v00@openssh.com");
                clientExtInfo = Arrays.asList(cKex).contains("ext-info-c");
            }
            String kexAlg = pick(cKex, kexAlgs);
            String hostAlg = pick(cHostKey, "ssh-rsa".equals(hostKeyType) ? rsaSigAlgs : new String[] { hostKeyType });
            String cipherIn = pick(cCipherC2S, ciphers);
            String cipherOut = pick(cCipherS2C, ciphers);
            lastKex = kexAlg;
            lastCipher = cipherOut;
            lastHostKeyAlg = hostAlg;

            if (ignoreDuringKex) send(new W().u8(2).str("x").bytes());
            byte[] init = recv();
            if ((init[0] & 0xff) != 30) throw new IOException("expected KEX init, got " + (init[0] & 0xff));
            R ir = new R(init, 1);
            byte[] kS = blob(hostKeyPair.getPublic());
            W h = new W().str(clientVersion).str(versionLine).str(theirs).str(mine).str(kS);
            W reply = new W().u8(31).str(kS);
            BigInteger k;
            if (kexAlg.startsWith("curve25519")) {
                byte[] qc = ir.str();
                KeyPair kp = KeyPairGenerator.getInstance("X25519").generateKeyPair();
                byte[] qs = littleEndian(((XECPublicKey) kp.getPublic()).getU());
                byte[] u = qc.clone();
                u[31] &= 0x7f;
                PublicKey peer = KeyFactory.getInstance("X25519").generatePublic(
                        new XECPublicKeySpec(NamedParameterSpec.X25519, new BigInteger(1, reverse(u))));
                KeyAgreement ka = KeyAgreement.getInstance("X25519");
                ka.init(kp.getPrivate());
                ka.doPhase(peer, true);
                k = new BigInteger(1, ka.generateSecret());
                h.str(qc).str(qs);
                reply.str(qs);
            } else if (kexAlg.startsWith("ecdh")) {
                byte[] qc = ir.str();
                KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
                g.initialize(new ECGenParameterSpec("secp256r1"));
                KeyPair kp = g.generateKeyPair();
                byte[] qs = point((ECPublicKey) kp.getPublic());
                ECPoint w = new ECPoint(new BigInteger(1, Arrays.copyOfRange(qc, 1, 33)), new BigInteger(1, Arrays.copyOfRange(qc, 33, 65)));
                PublicKey peer = KeyFactory.getInstance("EC").generatePublic(
                        new ECPublicKeySpec(w, ((ECPublicKey) kp.getPublic()).getParams()));
                KeyAgreement ka = KeyAgreement.getInstance("ECDH");
                ka.init(kp.getPrivate());
                ka.doPhase(peer, true);
                k = new BigInteger(1, ka.generateSecret());
                h.str(qc).str(qs);
                reply.str(qs);
            } else {
                BigInteger e = new BigInteger(1, ir.str());
                BigInteger y = new BigInteger(320, random);
                BigInteger f = BigInteger.valueOf(2).modPow(y, SshTransport.DH14_P);
                k = e.modPow(y, SshTransport.DH14_P);
                h.mpint(e).mpint(f);
                reply.mpint(f);
            }
            byte[] exchangeHash = MessageDigest.getInstance("SHA-256").digest(h.mpint(k).bytes());
            if (sessionId == null) sessionId = exchangeHash;
            byte[] toSign = exchangeHash.clone();
            if (corruptSignature) toSign[0] ^= 1;
            reply.str(new W().str(hostAlg).str(sign(hostAlg, hostKeyPair, toSign)).bytes());
            send(reply.bytes());
            if (debugBeforeNewkeys) send(new W().u8(4).u8(0).str("debug").str("").bytes());
            send(new byte[] { 21 });
            byte[] kBytes = new W().mpint(k).bytes();
            setKeys(true, cipherOut, kBytes, exchangeHash);
            byte[] nk = recv();
            if ((nk[0] & 0xff) != 21) throw new IOException("expected NEWKEYS, got " + (nk[0] & 0xff));
            setKeys(false, cipherIn, kBytes, exchangeHash);
            boolean first = !firstKexDone;
            firstKexDone = true;
            kexCount++;
            if (first && clientExtInfo && serverSigAlgs != null) {
                send(new W().u8(7).u32(1).str("server-sig-algs").str(String.join(",", serverSigAlgs)).bytes());
            }
        }

        byte[] derive(byte[] k, byte[] h, char letter, int len) throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            md.update(k);
            md.update(h);
            md.update((byte) letter);
            byte[] out = md.digest(sessionId);
            while (out.length < len) {
                md.update(k);
                md.update(h);
                byte[] more = md.digest(out);
                byte[] j = Arrays.copyOf(out, out.length + more.length);
                System.arraycopy(more, 0, j, out.length, more.length);
                out = j;
            }
            return Arrays.copyOf(out, len);
        }

        void setKeys(boolean outgoing, String cipher, byte[] k, byte[] h) throws Exception {
            // server to client: IV 'B', key 'D', MAC 'F'; client to server: 'A', 'C', 'E'
            char iv = outgoing ? 'B' : 'A', key = outgoing ? 'D' : 'C', mac = outgoing ? 'F' : 'E';
            int keyLen = cipher.startsWith("aes256") ? 32 : 16;
            Cipher ctr = null;
            Mac m = null;
            SecretKeySpec gcmKey = null;
            byte[] gcmIv = null;
            if (cipher.contains("gcm")) {
                gcmKey = new SecretKeySpec(derive(k, h, key, keyLen), "AES");
                gcmIv = derive(k, h, iv, 12);
            } else {
                ctr = Cipher.getInstance("AES/CTR/NoPadding");
                ctr.init(outgoing ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE, new SecretKeySpec(derive(k, h, key, keyLen), "AES"),
                        new IvParameterSpec(derive(k, h, iv, 16)));
                m = Mac.getInstance("HmacSHA256");
                m.init(new SecretKeySpec(derive(k, h, mac, 32), "HmacSHA256"));
            }
            if (outgoing) {
                ctrOut = ctr;
                macOut = m;
                gcmKeyOut = gcmKey;
                gcmIvOut = gcmIv;
                if (strict && clientStrict) seqOut = 0;
            } else {
                ctrIn = ctr;
                macIn = m;
                gcmKeyIn = gcmKey;
                gcmIvIn = gcmIv;
                if (strict && clientStrict) seqIn = 0;
            }
        }

        void send(byte[] payload) throws Exception {
            boolean gcm = gcmKeyOut != null;
            int block = gcm || ctrOut != null ? 16 : 8;
            int body = 1 + payload.length;
            int pad = block - (gcm ? body : body + 4) % block;
            if (pad < 4) pad += block;
            byte[] p = new byte[4 + body + pad];
            int len = body + pad;
            p[0] = (byte) (len >>> 24);
            p[1] = (byte) (len >>> 16);
            p[2] = (byte) (len >>> 8);
            p[3] = (byte) len;
            p[4] = (byte) pad;
            System.arraycopy(payload, 0, p, 5, payload.length);
            if (gcm) {
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, gcmKeyOut, new GCMParameterSpec(128, gcmIvOut));
                c.updateAAD(p, 0, 4);
                out.write(p, 0, 4);
                out.write(c.doFinal(p, 4, len));
                bump(gcmIvOut);
            } else if (ctrOut != null) {
                macOut.update(new byte[] { (byte) (seqOut >>> 24), (byte) (seqOut >>> 16), (byte) (seqOut >>> 8), (byte) seqOut });
                byte[] mac = macOut.doFinal(p);
                out.write(ctrOut.update(p));
                out.write(mac);
            } else {
                out.write(p);
            }
            out.flush();
            seqOut = (seqOut + 1) & 0xffffffffL;
        }

        void bump(byte[] iv) {
            for (int i = 11; i >= 4; i--) {
                if (++iv[i] != 0) break;
            }
        }

        byte[] readN(int n) throws IOException {
            byte[] b = new byte[n];
            int off = 0;
            while (off < n) {
                int r = in.read(b, off, n - off);
                if (r < 0) throw new EOFException();
                off += r;
            }
            return b;
        }

        byte[] recv() throws Exception {
            byte[] p;
            if (gcmKeyIn != null) {
                byte[] lb = readN(4);
                int len = (int) new R(lb, 0).u32();
                byte[] ct = readN(len + 16);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, gcmKeyIn, new GCMParameterSpec(128, gcmIvIn));
                c.updateAAD(lb);
                p = c.doFinal(ct);
                bump(gcmIvIn);
            } else if (ctrIn != null) {
                byte[] first = ctrIn.update(readN(16));
                int len = (int) new R(first, 0).u32();
                byte[] rest = len + 4 > 16 ? ctrIn.update(readN(len + 4 - 16)) : new byte[0];
                byte[] whole = Arrays.copyOf(first, len + 4);
                System.arraycopy(rest, 0, whole, 16, rest.length);
                byte[] mac = readN(32);
                macIn.update(new byte[] { (byte) (seqIn >>> 24), (byte) (seqIn >>> 16), (byte) (seqIn >>> 8), (byte) seqIn });
                if (!MessageDigest.isEqual(macIn.doFinal(whole), mac)) throw new IOException("bad MAC from the client");
                p = Arrays.copyOfRange(whole, 4, whole.length);
            } else {
                int len = (int) new R(readN(4), 0).u32();
                p = readN(len);
            }
            seqIn = (seqIn + 1) & 0xffffffffL;
            int pad = p[0] & 0xff;
            return Arrays.copyOfRange(p, 1, p.length - pad);
        }

        // --- messages after the key exchange ---

        void handle(byte[] p) throws Exception {
            R r = new R(p, 1);
            switch (p[0] & 0xff) {
                case 1:
                    throw new EOFException();
                case 2:
                case 3:
                case 4:
                    return;
                case 5: {
                    send(new W().u8(6).str(r.str()).bytes());
                    return;
                }
                case 20: {
                    byte[] mine = kexinit();
                    send(mine);
                    kex(mine, p);
                    return;
                }
                case 50:
                    auth(p);
                    return;
                case 90: {
                    r.str();
                    clientChannel = r.u32();
                    clientWindow = r.u32();
                    clientMaxPacket = r.u32();
                    send(new W().u8(91).u32(clientChannel).u32(7).u32(1 << 20).u32(32768).bytes());
                    return;
                }
                case 93:
                    r.u32();
                    clientWindow += r.u32();
                    return;
                case 94: {
                    r.u32();
                    byte[] data = r.str();
                    sftpIn.write(data, 0, data.length);
                    sftp();
                    return;
                }
                case 98: {
                    r.u32();
                    String type = r.text();
                    boolean reply = r.u8() != 0;
                    boolean ok = "subsystem".equals(type) && "sftp".equals(r.text()) && !noSftp && authenticated;
                    if (reply) send(new W().u8(ok ? 99 : 100).u32(clientChannel).bytes());
                    return;
                }
                default:
                    throw new IOException("test server: unexpected message " + (p[0] & 0xff));
            }
        }

        String[] methods() {
            List<String> m = new ArrayList<String>();
            if (!authorizedKeys.isEmpty()) m.add("publickey");
            if (allowPassword) m.add("password");
            if (allowKeyboardInteractive) m.add("keyboard-interactive");
            return m.toArray(new String[0]);
        }

        void fail() throws Exception {
            send(new W().u8(51).names(methods()).u8(0).bytes());
        }

        void auth(byte[] p) throws Exception {
            R r = new R(p, 1);
            String u = r.text();
            r.text();
            String method = r.text();
            log.add("auth " + method);
            if ("password".equals(method) && allowPassword) {
                r.u8();
                String given = r.text();
                if (passwordChangeRequired) {
                    send(new W().u8(60).str("change it").str("").bytes());
                } else if (user.equals(u) && password.equals(given)) {
                    authenticated = true;
                    send(new byte[] { 52 });
                } else {
                    fail();
                }
            } else if ("keyboard-interactive".equals(method) && allowKeyboardInteractive) {
                send(new W().u8(60).str("").str("").str("").u32(1).str("Password: ").u8(0).bytes());
                R a = new R(recv(), 1);
                boolean ok = a.u32() == 1 && user.equals(u) && password.equals(a.text());
                if (!ok) {
                    fail();
                    return;
                }
                send(new W().u8(60).str("").str("").str("").u32(0).bytes());
                recv();
                authenticated = true;
                send(new byte[] { 52 });
            } else if ("publickey".equals(method) && !authorizedKeys.isEmpty()) {
                boolean hasSig = r.u8() != 0;
                String alg = r.text();
                byte[] blob = r.str();
                boolean known = false;
                for (byte[] k : authorizedKeys) known |= Arrays.equals(k, blob);
                String keyType = new R(blob, 0).text();
                boolean algOk = "ssh-ed25519".equals(keyType) ? "ssh-ed25519".equals(alg)
                        : "ssh-rsa".equals(keyType) && ("rsa-sha2-256".equals(alg) || "rsa-sha2-512".equals(alg))
                        && (serverSigAlgs == null || Arrays.asList(serverSigAlgs).contains(alg));
                log.add("publickey " + alg + (hasSig ? " signed" : " query"));
                if (!known || !algOk || !user.equals(u)) {
                    fail();
                } else if (!hasSig) {
                    send(new W().u8(60).str(alg).str(blob).bytes());
                } else {
                    int sigStart = r.p;
                    R sr = new R(r.str(), 0);
                    String sigAlg = sr.text();
                    byte[] sig = sr.str();
                    byte[] signed = new W().str(sessionId).raw(Arrays.copyOfRange(p, 0, sigStart)).bytes();
                    if (alg.equals(sigAlg) && verify(alg, blob, signed, sig)) {
                        authenticated = true;
                        send(new byte[] { 52 });
                    } else {
                        fail();
                    }
                }
            } else {
                fail();
            }
        }

        // --- SFTP ---

        void data(byte[] sftpPacket) {
            outQueue.addLast(new W().str(sftpPacket).bytes());
        }

        void flush() throws Exception {
            while (!outQueue.isEmpty()) {
                byte[] d = outQueue.getFirst();
                if (d.length > clientWindow) return; // wait for a window adjust
                if (d.length > clientMaxPacket) throw new IOException("client max packet too small for the test server");
                outQueue.removeFirst();
                clientWindow -= d.length;
                send(new W().u8(94).u32(clientChannel).str(d).bytes());
            }
        }

        void sftp() throws Exception {
            byte[] buf = sftpIn.toByteArray();
            int pos = 0;
            List<byte[]> answers = new ArrayList<byte[]>();
            while (buf.length - pos >= 4) {
                int len = (int) new R(buf, pos).u32();
                if (buf.length - pos - 4 < len) break;
                byte[] a = sftpRequest(Arrays.copyOfRange(buf, pos + 4, pos + 4 + len));
                if (a != null) answers.add(a);
                pos += 4 + len;
            }
            sftpIn.reset();
            sftpIn.write(buf, pos, buf.length - pos);
            if (reverseAnswers) Collections.reverse(answers);
            for (byte[] a : answers) data(a);
        }

        byte[] status(long id, int code, String text) {
            return new W().u8(101).u32(id).u32(code).str(text).str("").bytes();
        }

        byte[] sftpRequest(byte[] q) throws Exception {
            R r = new R(q, 1);
            int type = q[0] & 0xff;
            if (type == 1) return new W().u8(2).u32(3).bytes();
            long id = r.u32();
            switch (type) {
                case 17:
                case 7: {
                    String path = r.text();
                    log.add("stat " + path);
                    if (directories.contains(path)) return new W().u8(105).u32(id).u32(4).u32(040755).bytes();
                    byte[] f = files.get(path);
                    if (f == null) return status(id, 2, "No such file");
                    Long mt = mtimes.get(path);
                    return new W().u8(105).u32(id).u32(1 | 4 | 8).u64(f.length).u32(0100644)
                            .u32(1700000000L).u32(mt == null ? 1700000000L : mt.longValue()).bytes();
                }
                case 3: {
                    String path = r.text();
                    log.add("open " + path);
                    if (!files.containsKey(path)) return status(id, "secret.bin".equals(path) ? 3 : 2, "cannot open");
                    String h = "h" + (nextHandle++);
                    handles.put(h, path);
                    return new W().u8(102).u32(id).str(h).bytes();
                }
                case 4:
                    handles.remove(new String(r.str(), "UTF-8"));
                    return status(id, 0, "OK");
                case 5: {
                    byte[] f = files.get(handles.get(new String(r.str(), "UTF-8")));
                    long off = r.u64();
                    int n = (int) r.u32();
                    log.add("read " + off + " " + n);
                    if (f == null) return status(id, 4, "bad handle");
                    if (off >= f.length) return status(id, 1, "EOF");
                    n = (int) Math.min(n, f.length - off);
                    if (shortReadEvery > 0 && ++reads % shortReadEvery == 0 && n > 1) n = n / 2;
                    fileBytesSent += n;
                    fileBytesSinceRekey += n;
                    if (cutAfterFileBytes >= 0 && number == 1 && fileBytesSent > cutAfterFileBytes) {
                        flush();
                        socket.close();
                        throw new EOFException();
                    }
                    return new W().u8(103).u32(id).u32(n).raw(Arrays.copyOfRange(f, (int) off, (int) off + n)).bytes();
                }
                default:
                    return status(id, 8, "unsupported");
            }
        }
    }

    // --- JCA helpers ---

    static byte[] reverse(byte[] b) {
        byte[] r = new byte[b.length];
        for (int i = 0; i < b.length; i++) r[i] = b[b.length - 1 - i];
        return r;
    }

    static byte[] littleEndian(BigInteger u) {
        byte[] be = u.toByteArray();
        byte[] out = new byte[32];
        for (int i = 0; i < Math.min(32, be.length); i++) out[i] = be[be.length - 1 - i];
        return out;
    }

    static byte[] sign(String alg, KeyPair kp, byte[] data) throws Exception {
        if ("ssh-ed25519".equals(alg)) {
            Signature s = Signature.getInstance("Ed25519");
            s.initSign(kp.getPrivate());
            s.update(data);
            return s.sign();
        }
        if ("ecdsa-sha2-nistp256".equals(alg)) {
            Signature s = Signature.getInstance("SHA256withECDSA");
            s.initSign(kp.getPrivate());
            s.update(data);
            byte[] der = s.sign();
            // SEQUENCE { INTEGER r, INTEGER s }
            int p = 2;
            if ((der[1] & 0x80) != 0) p = 2 + (der[1] & 0x7f);
            int rl = der[p + 1];
            BigInteger r = new BigInteger(Arrays.copyOfRange(der, p + 2, p + 2 + rl));
            p += 2 + rl;
            int sl = der[p + 1];
            BigInteger sv = new BigInteger(Arrays.copyOfRange(der, p + 2, p + 2 + sl));
            return new W().mpint(r).mpint(sv).bytes();
        }
        Signature s = Signature.getInstance("rsa-sha2-512".equals(alg) ? "SHA512withRSA" : "SHA256withRSA");
        s.initSign(kp.getPrivate());
        s.update(data);
        return s.sign();
    }

    static boolean verify(String alg, byte[] blob, byte[] data, byte[] sig) throws Exception {
        R r = new R(blob, 0);
        r.text();
        if ("ssh-ed25519".equals(alg)) {
            byte[] prefix = { 0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00 };
            byte[] enc = Arrays.copyOf(prefix, 44);
            System.arraycopy(r.str(), 0, enc, 12, 32);
            Signature s = Signature.getInstance("Ed25519");
            s.initVerify(KeyFactory.getInstance("Ed25519").generatePublic(new X509EncodedKeySpec(enc)));
            s.update(data);
            return s.verify(sig);
        }
        BigInteger e = new BigInteger(r.str());
        BigInteger n = new BigInteger(r.str());
        Signature s = Signature.getInstance("rsa-sha2-512".equals(alg) ? "SHA512withRSA" : "SHA256withRSA");
        s.initVerify(KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(n, e)));
        s.update(data);
        return s.verify(sig);
    }
}
