package org.reteget.core.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

/**
 * TLS 1.3 client (RFC 8446), full handshake with server authentication.
 *
 * Profile: TLS_AES_128_GCM_SHA256; key exchange X25519 (sent first) or secp256r1 (sent after a
 * HelloRetryRequest asks for it); server signatures ECDSA P-256/P-384 and RSA-PSS. Not
 * supported, and refused explicitly: PSK/resumption, 0-RTT, client certificates.
 * NewSessionTicket is read and discarded; KeyUpdate is honoured in both directions.
 *
 * The handshake is linear code rather than a table: each step reads exactly the message
 * the protocol allows next, so any other message fails with unexpected_message.
 */
public final class Tls13Socket implements TlsConnection {

    static final int CT_CHANGE_CIPHER_SPEC = 20;
    static final int CT_ALERT = 21;
    static final int CT_HANDSHAKE = 22;
    static final int CT_APPLICATION_DATA = 23;

    static final int HT_CLIENT_HELLO = 1;
    static final int HT_SERVER_HELLO = 2;
    static final int HT_NEW_SESSION_TICKET = 4;
    static final int HT_ENCRYPTED_EXTENSIONS = 8;
    static final int HT_CERTIFICATE = 11;
    static final int HT_CERTIFICATE_REQUEST = 13;
    static final int HT_CERTIFICATE_VERIFY = 15;
    static final int HT_FINISHED = 20;
    static final int HT_KEY_UPDATE = 24;
    static final int HT_MESSAGE_HASH = 254;

    static final int EXT_SERVER_NAME = 0;
    static final int EXT_SUPPORTED_GROUPS = 10;
    static final int EXT_SIGNATURE_ALGORITHMS = 13;
    static final int EXT_ALPN = 16;
    static final int EXT_SUPPORTED_VERSIONS = 43;
    static final int EXT_COOKIE = 44;
    static final int EXT_SIGNATURE_ALGORITHMS_CERT = 50;
    static final int EXT_KEY_SHARE = 51;

    /** Extensions a server may send in EncryptedExtensions (RFC 8446 section 4.2 table). */
    private static final int[] EE_ALLOWED = { 0, 1, 10, 14, 15, 16, 19, 20, 28, 42 };

    static final int GROUP_X25519 = 0x001d;
    static final int GROUP_SECP256R1 = 0x0017;
    static final int TLS_AES_128_GCM_SHA256 = 0x1301;
    static final int VERSION_TLS13 = 0x0304;
    static final int VERSION_TLS12 = 0x0303;

    static final int MAX_PLAINTEXT = 16384;
    static final int MAX_CIPHERTEXT = MAX_PLAINTEXT + 256;
    static final int MAX_HANDSHAKE_MESSAGE = 256 * 1024;
    static final int MAX_HANDSHAKE_TOTAL = 1024 * 1024;
    static final int MAX_CERTIFICATES = 8;
    static final int MAX_CERTIFICATE_SIZE = 64 * 1024;
    static final int HANDSHAKE_TIMEOUT_MS = 30000;
    /** AES-GCM may protect about 2^24.5 full records per key (RFC 8446 section 5.5). */
    static final long READ_RECORD_LIMIT = 1L << 24;
    static final long WRITE_KEY_UPDATE_AT = 1L << 20;

    static final byte[] HRR_RANDOM = RsaVerifier.hex(
            "cf21ad74e59a6111be1d8c021e65b891c2a211167abb8c5e079e09e2c8a8339c");
    static final byte[] DOWNGRADE_TLS12 = RsaVerifier.hex("444f574e47524401");
    static final byte[] DOWNGRADE_TLS11 = RsaVerifier.hex("444f574e47524400");
    private static final byte[] EMPTY = new byte[0];
    private static final byte[] ALPN_HTTP11 = Hkdf.ascii("http/1.1");

    /** Directional record protection for one traffic secret. */
    static final class Protection {
        final byte[] secret;
        final AesGcm aead;
        final byte[] iv;
        long seq;

        Protection(byte[] secret) throws Exception {
            this.secret = secret;
            this.aead = new AesGcm(Hkdf.expandLabel(secret, "key", EMPTY, 16));
            this.iv = Hkdf.expandLabel(secret, "iv", EMPTY, AesGcm.NONCE_LEN);
        }

        byte[] nonce() {
            byte[] n = iv.clone();
            for (int i = 0; i < 8; i++) {
                n[4 + i] ^= (byte) (seq >>> (56 - 8 * i));
            }
            return n;
        }

        Protection next() throws Exception {
            return new Protection(Hkdf.expandLabel(secret, "traffic upd", EMPTY, Hkdf.HASH_LEN));
        }
    }

    private static final class Record {
        final int type;
        final byte[] data;

        Record(int type, byte[] data) {
            this.type = type;
            this.data = data;
        }
    }

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final String host;
    private final CertificatePolicy policy;

    private final Object readLock = new Object();
    private final Object writeLock = new Object();

    private Protection readProtection;
    private Protection writeProtection;
    private final ByteArrayOutputStream transcript = new ByteArrayOutputStream();
    private byte[] handshakeBuffer = new byte[0];
    private int handshakeBytesTotal;
    private boolean handshakeDone;
    private boolean inputClosed;
    private volatile boolean closed;
    private long handshakeDeadline;

    private byte[] appBuffer = EMPTY;
    private int appPos;

    private String groupName = "";
    private String signatureName = "";

    // Test hooks, package-private: tests replay RFC 8448 with its exact ClientHello and key.
    int rsaMinBits = RsaVerifier.MIN_BITS;
    int keyUpdatesReceived;
    byte[] clientHelloOverride;
    byte[] x25519PrivateOverride;

    private final InputStream appIn = new InputStream() {
        @Override
        public int read() throws IOException {
            byte[] b = new byte[1];
            int n = read(b, 0, 1);
            return n <= 0 ? -1 : b[0] & 0xff;
        }

        @Override
        public int read(byte[] b, int off, int len) throws IOException {
            return readApplicationData(b, off, len);
        }

        @Override
        public int available() {
            synchronized (readLock) {
                return appBuffer.length - appPos;
            }
        }

        @Override
        public void close() throws IOException {
            Tls13Socket.this.close();
        }
    };

    private final OutputStream appOut = new OutputStream() {
        @Override
        public void write(int b) throws IOException {
            write(new byte[] { (byte) b }, 0, 1);
        }

        @Override
        public void write(byte[] b, int off, int len) throws IOException {
            writeApplicationData(b, off, len);
        }

        @Override
        public void flush() throws IOException {
            out.flush();
        }

        @Override
        public void close() throws IOException {
            Tls13Socket.this.close();
        }
    };

    Tls13Socket(Socket socket, InputStream in, OutputStream out, String host, CertificatePolicy policy) {
        this.socket = socket;
        this.in = in;
        this.out = out;
        this.host = host;
        this.policy = policy;
    }

    /**
     * Opens a TCP connection and completes a TLS 1.3 handshake.
     *
     * @throws TlsVersionException when the server does not speak TLS 1.3 (before any
     *         authentication took place); every other failure is final.
     */
    public static Tls13Socket connect(String host, int port, int timeoutMs, CertificatePolicy policy)
            throws IOException {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            s.setTcpNoDelay(true);
            Tls13Socket t = new Tls13Socket(s, s.getInputStream(), s.getOutputStream(), host, policy);
            t.handshake();
            return t;
        } catch (IOException e) {
            closeQuietly(s);
            throw e;
        } catch (RuntimeException e) {
            closeQuietly(s);
            throw new TlsException(TlsException.INTERNAL_ERROR, "TLS 1.3 internal error: " + e, e);
        }
    }

    @Override
    public InputStream getInputStream() {
        return appIn;
    }

    @Override
    public OutputStream getOutputStream() {
        return appOut;
    }

    @Override
    public String getProtocol() {
        return "TLSv1.3";
    }

    @Override
    public String getCipherSuite() {
        return "TLS_AES_128_GCM_SHA256";
    }

    @Override
    public String getSummary() {
        return "TLS 1.3 AES_128_GCM_SHA256 " + groupName + " " + signatureName
                + (policy.isInsecure() ? " (certificate NOT verified)" : "");
    }

    // ------------------------------------------------------------------ handshake

    void handshake() throws IOException {
        handshakeDeadline = System.nanoTime() + HANDSHAKE_TIMEOUT_MS * 1000000L;
        try {
            runHandshake();
        } catch (TlsException e) {
            if (!e.received) {
                sendAlertQuietly(e.alert);
            }
            closeTransport();
            throw e;
        } catch (IOException e) {
            closeTransport();
            throw e;
        } catch (SecurityException e) {
            sendAlertQuietly(TlsException.BAD_RECORD_MAC);
            closeTransport();
            throw new TlsException(TlsException.BAD_RECORD_MAC, "record authentication failed", e);
        } catch (Exception e) {
            sendAlertQuietly(TlsException.INTERNAL_ERROR);
            closeTransport();
            throw new TlsException(TlsException.INTERNAL_ERROR, "TLS 1.3 handshake error: " + e, e);
        }
        handshakeDeadline = 0;
    }

    private void runHandshake() throws Exception {
        byte[] random = TlsRandom.bytes(32);
        byte[] sessionId = TlsRandom.bytes(32); // non-empty: middlebox compatibility mode
        byte[] x25519Private = x25519PrivateOverride != null ? x25519PrivateOverride : TlsRandom.bytes(32);

        byte[] clientHello = clientHelloOverride != null ? clientHelloOverride
                : buildClientHello(random, sessionId, GROUP_X25519, X25519.publicKey(x25519Private), null);
        ClientHelloInfo offered = ClientHelloInfo.parse(clientHello);
        boolean compatMode = offered.sessionId.length > 0;
        boolean ccsSent = false;

        writePlain(CT_HANDSHAKE, clientHello, 0x0301);
        out.flush();
        transcript.write(clientHello);

        byte[] serverHello = readServerHelloOrFallback();
        ServerHelloInfo sh = ServerHelloInfo.parse(serverHello, offered);
        int sentGroup = offered.keyShareGroup;
        BigInteger p256Private = null;

        if (sh.helloRetry) {
            int group = sh.keyShareGroup;
            if (group == -1 && sh.cookie == null) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "HelloRetryRequest changes nothing");
            }
            if (group == -1) {
                group = sentGroup;
            } else if (group == sentGroup || !offered.groups.contains(group)) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "HelloRetryRequest selected an invalid group");
            }
            byte[] share;
            if (group == GROUP_SECP256R1) {
                p256Private = EcCurve.P256.randomScalar();
                share = EcCurve.P256.encodePoint(EcCurve.P256.multiplyBase(p256Private));
            } else if (group == GROUP_X25519) {
                share = X25519.publicKey(x25519Private);
            } else {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "HelloRetryRequest group not offered");
            }
            // Replace ClientHello1 by message_hash(Hash(ClientHello1)), then add the HRR.
            byte[] ch1Hash = sha256(transcript.toByteArray());
            transcript.reset();
            transcript.write(TlsWriter.handshake(HT_MESSAGE_HASH, ch1Hash));
            transcript.write(serverHello);

            byte[] clientHello2 = buildClientHello(offered.random, offered.sessionId, group, share, sh.cookie);
            if (compatMode) {
                writePlain(CT_CHANGE_CIPHER_SPEC, new byte[] { 1 }, VERSION_TLS12);
                ccsSent = true;
            }
            writePlain(CT_HANDSHAKE, clientHello2, VERSION_TLS12);
            out.flush();
            transcript.write(clientHello2);
            sentGroup = group;

            byte[] serverHello2 = nextHandshakeMessage();
            if (type(serverHello2) != HT_SERVER_HELLO) {
                throw unexpected("expected ServerHello after HelloRetryRequest");
            }
            ServerHelloInfo sh2 = ServerHelloInfo.parse(serverHello2, offered);
            if (sh2.helloRetry) {
                throw unexpected("second HelloRetryRequest");
            }
            if (sh2.cipherSuite != sh.cipherSuite) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "cipher suite changed after HelloRetryRequest");
            }
            serverHello = serverHello2;
            sh = sh2;
        }
        if (sh.keyShareGroup != sentGroup || sh.keyShare == null) {
            throw new TlsException(TlsException.ILLEGAL_PARAMETER, "server key share does not match the offered group");
        }
        transcript.write(serverHello);

        byte[] shared;
        if (sentGroup == GROUP_X25519) {
            if (sh.keyShare.length != X25519.KEY_LEN) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "bad X25519 key share length");
            }
            shared = X25519.scalarMult(x25519Private, sh.keyShare);
            if (X25519.isAllZero(shared)) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "X25519 shared secret is zero");
            }
            groupName = "x25519";
        } else {
            EcCurve.Point peer;
            try {
                peer = EcCurve.P256.decodePoint(sh.keyShare);
            } catch (IllegalArgumentException e) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "invalid P-256 key share", e);
            }
            shared = EcCurve.P256.ecdh(p256Private, peer);
            groupName = "secp256r1";
        }
        Arrays.fill(x25519Private, (byte) 0);

        // Key schedule up to the handshake traffic secrets.
        byte[] zeros = new byte[Hkdf.HASH_LEN];
        byte[] emptyHash = sha256(EMPTY);
        byte[] early = Hkdf.extract(zeros, zeros);
        byte[] handshakeSecret = Hkdf.extract(Hkdf.deriveSecret(early, "derived", emptyHash), shared);
        Arrays.fill(shared, (byte) 0);
        byte[] helloHash = transcriptHash();
        byte[] clientHs = Hkdf.deriveSecret(handshakeSecret, "c hs traffic", helloHash);
        byte[] serverHs = Hkdf.deriveSecret(handshakeSecret, "s hs traffic", helloHash);
        byte[] master = Hkdf.extract(Hkdf.deriveSecret(handshakeSecret, "derived", emptyHash), zeros);

        requireKeyChangeBoundary();
        readProtection = new Protection(serverHs);

        // EncryptedExtensions
        byte[] ee = nextHandshakeMessage();
        if (type(ee) != HT_ENCRYPTED_EXTENSIONS) {
            throw unexpected("expected EncryptedExtensions");
        }
        parseEncryptedExtensions(ee, offered);
        transcript.write(ee);

        // Certificate (a CertificateRequest here means the server wants client authentication)
        byte[] certMsg = nextHandshakeMessage();
        if (type(certMsg) == HT_CERTIFICATE_REQUEST) {
            throw new TlsException(TlsException.HANDSHAKE_FAILURE,
                    "server requires a client certificate, which is not supported");
        }
        if (type(certMsg) != HT_CERTIFICATE) {
            throw unexpected("expected Certificate");
        }
        X509Cert[] chain = parseCertificate(certMsg, offered);
        transcript.write(certMsg);
        PublicKeyInfo serverKey = chain[0].publicKey;
        try {
            policy.check(host, chain, platformChain(chain));
        } catch (CertificateException e) {
            throw new TlsException(TlsException.BAD_CERTIFICATE,
                    "server certificate rejected: " + e.getMessage(), e);
        }

        // CertificateVerify: signature over the transcript through Certificate.
        byte[] cv = nextHandshakeMessage();
        if (type(cv) != HT_CERTIFICATE_VERIFY) {
            throw unexpected("expected CertificateVerify");
        }
        TlsReader cvr = body(cv);
        int scheme = cvr.u16();
        byte[] signature = cvr.vec16();
        cvr.expectEnd();
        if (!offered.signatureSchemes.contains(scheme)) {
            throw new TlsException(TlsException.ILLEGAL_PARAMETER,
                    "server used a signature scheme that was not offered: " + SignatureSchemes.name(scheme));
        }
        byte[] signed = certificateVerifyContent(transcriptHash());
        boolean ok;
        try {
            ok = SignatureSchemes.verify(scheme, serverKey, signed, signature, true, rsaMinBits);
        } catch (IllegalArgumentException e) {
            throw new TlsException(TlsException.UNSUPPORTED_CERTIFICATE, e.getMessage(), e);
        }
        if (!ok) {
            throw new TlsException(TlsException.DECRYPT_ERROR, "server CertificateVerify signature is invalid");
        }
        signatureName = SignatureSchemes.name(scheme);
        transcript.write(cv);

        // Server Finished
        byte[] fin = nextHandshakeMessage();
        if (type(fin) != HT_FINISHED) {
            throw unexpected("expected Finished");
        }
        byte[] expected = Hkdf.hmac(Hkdf.expandLabel(serverHs, "finished", EMPTY, Hkdf.HASH_LEN), transcriptHash());
        TlsReader fr = body(fin);
        byte[] verifyData = fr.bytes(Hkdf.HASH_LEN);
        fr.expectEnd();
        if (!MessageDigest.isEqual(expected, verifyData)) {
            throw new TlsException(TlsException.DECRYPT_ERROR, "server Finished does not verify");
        }
        transcript.write(fin);

        byte[] serverFinishedHash = transcriptHash();
        byte[] clientAp = Hkdf.deriveSecret(master, "c ap traffic", serverFinishedHash);
        byte[] serverAp = Hkdf.deriveSecret(master, "s ap traffic", serverFinishedHash);
        requireKeyChangeBoundary();
        readProtection = new Protection(serverAp);

        // Client flight: [compat CCS] Finished under the client handshake key.
        if (compatMode && !ccsSent) {
            writePlain(CT_CHANGE_CIPHER_SPEC, new byte[] { 1 }, VERSION_TLS12);
        }
        writeProtection = new Protection(clientHs);
        byte[] clientVerify = Hkdf.hmac(Hkdf.expandLabel(clientHs, "finished", EMPTY, Hkdf.HASH_LEN),
                serverFinishedHash);
        writeProtected(CT_HANDSHAKE, TlsWriter.handshake(HT_FINISHED, clientVerify));
        out.flush();
        writeProtection = new Protection(clientAp);

        Arrays.fill(handshakeSecret, (byte) 0);
        Arrays.fill(master, (byte) 0);
        transcript.reset();
        handshakeDone = true;
    }

    /** Reads the first server message, turning "server does not do TLS 1.3" into TlsVersionException. */
    private byte[] readServerHelloOrFallback() throws Exception {
        byte[] msg;
        try {
            msg = nextHandshakeMessage();
        } catch (TlsException e) {
            if (e.received && (e.alert == TlsException.PROTOCOL_VERSION
                    || e.alert == TlsException.HANDSHAKE_FAILURE
                    || e.alert == TlsException.INSUFFICIENT_SECURITY)) {
                throw new TlsVersionException("server refused the TLS 1.3 ClientHello (alert " + e.alert + ")");
            }
            throw e;
        } catch (EOFException e) {
            throw new TlsVersionException("server closed the connection after the TLS 1.3 ClientHello");
        } catch (SocketException e) {
            throw new TlsVersionException("server reset the connection after the TLS 1.3 ClientHello");
        }
        if (type(msg) != HT_SERVER_HELLO) {
            throw unexpected("expected ServerHello");
        }
        return msg;
    }

    byte[] buildClientHello(byte[] random, byte[] sessionId, int shareGroup, byte[] share, byte[] cookie) {
        TlsWriter ext = new TlsWriter();
        if (!HostnameChecker.isIpLiteral(host)) {
            byte[] name = Hkdf.ascii(host);
            ext.extension(EXT_SERVER_NAME,
                    new TlsWriter().vec16(new TlsWriter().u8(0).vec16(name).toByteArray()).toByteArray());
        }
        ext.extension(EXT_SUPPORTED_GROUPS,
                new TlsWriter().vec16(new TlsWriter().u16(GROUP_X25519).u16(GROUP_SECP256R1).toByteArray())
                        .toByteArray());
        ext.extension(EXT_SIGNATURE_ALGORITHMS, schemeList(SignatureSchemes.TLS13_HANDSHAKE));
        ext.extension(EXT_SIGNATURE_ALGORITHMS_CERT, schemeList(SignatureSchemes.CERTIFICATES));
        ext.extension(EXT_ALPN, new TlsWriter().vec16(new TlsWriter().vec8(ALPN_HTTP11).toByteArray()).toByteArray());
        ext.extension(EXT_SUPPORTED_VERSIONS, new TlsWriter().vec8(new TlsWriter().u16(VERSION_TLS13).toByteArray())
                .toByteArray());
        if (cookie != null) {
            ext.extension(EXT_COOKIE, new TlsWriter().vec16(cookie).toByteArray());
        }
        ext.extension(EXT_KEY_SHARE,
                new TlsWriter().vec16(new TlsWriter().u16(shareGroup).vec16(share).toByteArray()).toByteArray());

        TlsWriter body = new TlsWriter()
                .u16(VERSION_TLS12)
                .raw(random)
                .vec8(sessionId)
                .vec16(new TlsWriter().u16(TLS_AES_128_GCM_SHA256).toByteArray())
                .vec8(new byte[] { 0 })
                .vec16(ext.toByteArray());
        return TlsWriter.handshake(HT_CLIENT_HELLO, body.toByteArray());
    }

    private static byte[] schemeList(int[] schemes) {
        TlsWriter w = new TlsWriter();
        for (int s : schemes) {
            w.u16(s);
        }
        return new TlsWriter().vec16(w.toByteArray()).toByteArray();
    }

    private void parseEncryptedExtensions(byte[] msg, ClientHelloInfo offered) throws TlsException {
        TlsReader r = body(msg);
        TlsReader exts = r.subVec16();
        r.expectEnd();
        Set<Integer> seen = new HashSet<Integer>();
        while (exts.hasRemaining()) {
            int type = exts.u16();
            byte[] data = exts.vec16();
            if (!seen.add(type)) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "duplicate extension " + type);
            }
            if (!offered.extensions.contains(type)) {
                throw new TlsException(TlsException.UNSUPPORTED_EXTENSION, "server sent unrequested extension " + type);
            }
            boolean allowed = false;
            for (int a : EE_ALLOWED) {
                allowed |= a == type;
            }
            if (!allowed) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "extension " + type + " not allowed here");
            }
            if (type == EXT_ALPN) {
                TlsReader a = new TlsReader(data);
                TlsReader list = a.subVec16();
                a.expectEnd();
                byte[] proto = list.vec8();
                list.expectEnd();
                if (!Arrays.equals(proto, ALPN_HTTP11)) {
                    throw new TlsException(TlsException.NO_APPLICATION_PROTOCOL, "server selected an unexpected ALPN protocol");
                }
            }
        }
    }

    private X509Cert[] parseCertificate(byte[] msg, ClientHelloInfo offered) throws Exception {
        TlsReader r = body(msg);
        byte[] context = r.vec8();
        if (context.length != 0) {
            throw new TlsException(TlsException.ILLEGAL_PARAMETER, "server Certificate has a request context");
        }
        TlsReader list = r.subVec24();
        r.expectEnd();
        java.util.List<X509Cert> certs = new java.util.ArrayList<X509Cert>();
        while (list.hasRemaining()) {
            if (certs.size() == MAX_CERTIFICATES) {
                throw new TlsException(TlsException.BAD_CERTIFICATE, "certificate chain longer than " + MAX_CERTIFICATES);
            }
            byte[] der = list.vec24();
            if (der.length == 0 || der.length > MAX_CERTIFICATE_SIZE) {
                throw new TlsException(TlsException.BAD_CERTIFICATE, "certificate size out of range");
            }
            TlsReader exts = list.subVec16();
            while (exts.hasRemaining()) {
                int type = exts.u16();
                exts.vec16();
                if (!offered.extensions.contains(type)) {
                    throw new TlsException(TlsException.UNSUPPORTED_EXTENSION,
                            "certificate entry carries unrequested extension " + type);
                }
            }
            X509Cert cert = parseCertificateDer(der, certs.isEmpty());
            if (cert != null) {
                certs.add(cert);
            }
        }
        if (certs.isEmpty()) {
            throw new TlsException(TlsException.DECODE_ERROR, "server sent an empty certificate list");
        }
        return certs.toArray(new X509Cert[certs.size()]);
    }

    /**
     * Parses one certificate. An unusable leaf is fatal; an unusable extra certificate
     * is dropped (returns null), since path building may not need it.
     */
    static X509Cert parseCertificateDer(byte[] der, boolean leaf) throws TlsException {
        try {
            return X509Cert.parse(der);
        } catch (RuntimeException e) {
            if (!leaf) {
                return null;
            }
            throw new TlsException(TlsException.UNSUPPORTED_CERTIFICATE,
                    "cannot use server certificate: " + e.getMessage(), e);
        }
    }

    /** The chain as platform objects for the platform trust manager, or null if it cannot parse them. */
    static X509Certificate[] platformChain(X509Cert[] chain) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate[] out = new X509Certificate[chain.length];
            for (int i = 0; i < chain.length; i++) {
                out[i] = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(chain[i].der));
            }
            return out;
        } catch (Exception e) {
            return null;
        }
    }

    static byte[] certificateVerifyContent(byte[] transcriptHash) {
        byte[] context = Hkdf.ascii("TLS 1.3, server CertificateVerify");
        byte[] out = new byte[64 + context.length + 1 + transcriptHash.length];
        Arrays.fill(out, 0, 64, (byte) 0x20);
        System.arraycopy(context, 0, out, 64, context.length);
        out[64 + context.length] = 0;
        System.arraycopy(transcriptHash, 0, out, 65 + context.length, transcriptHash.length);
        return out;
    }

    // ------------------------------------------------------------------ parsed hellos

    /** What our own ClientHello offered; parsed back from its bytes so every check uses the truth. */
    static final class ClientHelloInfo {
        byte[] random;
        byte[] sessionId;
        final Set<Integer> extensions = new HashSet<Integer>();
        final Set<Integer> groups = new HashSet<Integer>();
        final Set<Integer> signatureSchemes = new HashSet<Integer>();
        final Set<Integer> suites = new HashSet<Integer>();
        int keyShareGroup = -1;

        static ClientHelloInfo parse(byte[] msg) throws TlsException {
            ClientHelloInfo info = new ClientHelloInfo();
            TlsReader r = body(msg);
            r.u16();
            info.random = r.bytes(32);
            info.sessionId = r.vec8();
            TlsReader suites = r.subVec16();
            while (suites.hasRemaining()) {
                info.suites.add(suites.u16());
            }
            r.vec8();
            TlsReader exts = r.subVec16();
            while (exts.hasRemaining()) {
                int type = exts.u16();
                TlsReader data = exts.subVec16();
                info.extensions.add(type);
                if (type == EXT_SUPPORTED_GROUPS) {
                    TlsReader l = data.subVec16();
                    while (l.hasRemaining()) info.groups.add(l.u16());
                } else if (type == EXT_SIGNATURE_ALGORITHMS) {
                    TlsReader l = data.subVec16();
                    while (l.hasRemaining()) info.signatureSchemes.add(l.u16());
                } else if (type == EXT_KEY_SHARE) {
                    TlsReader l = data.subVec16();
                    info.keyShareGroup = l.u16();
                    l.vec16();
                }
            }
            return info;
        }
    }

    static final class ServerHelloInfo {
        boolean helloRetry;
        int cipherSuite;
        int keyShareGroup = -1;
        byte[] keyShare;
        byte[] cookie;

        static ServerHelloInfo parse(byte[] msg, ClientHelloInfo offered) throws TlsException {
            ServerHelloInfo info = new ServerHelloInfo();
            TlsReader r = body(msg);
            int legacyVersion = r.u16();
            byte[] random = r.bytes(32);
            byte[] sessionId = r.vec8();
            info.cipherSuite = r.u16();
            int compression = r.u8();
            Map<Integer, byte[]> exts = new HashMap<Integer, byte[]>();
            if (r.hasRemaining()) {
                TlsReader e = r.subVec16();
                while (e.hasRemaining()) {
                    int type = e.u16();
                    byte[] data = e.vec16();
                    if (exts.put(type, data) != null) {
                        throw new TlsException(TlsException.ILLEGAL_PARAMETER, "duplicate ServerHello extension " + type);
                    }
                }
            }
            r.expectEnd();

            byte[] sv = exts.get(EXT_SUPPORTED_VERSIONS);
            if (sv == null) {
                byte[] tail = Arrays.copyOfRange(random, 24, 32);
                if (Arrays.equals(tail, DOWNGRADE_TLS12) || Arrays.equals(tail, DOWNGRADE_TLS11)) {
                    throw new TlsException(TlsException.ILLEGAL_PARAMETER,
                            "server signalled a protocol downgrade; refusing TLS 1.2");
                }
                throw new TlsVersionException("server selected TLS version 0x" + Integer.toHexString(legacyVersion));
            }
            TlsReader svr = new TlsReader(sv);
            int version = svr.u16();
            svr.expectEnd();
            if (version != VERSION_TLS13 || legacyVersion != VERSION_TLS12) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "server selected an unsupported version");
            }
            if (!Arrays.equals(sessionId, offered.sessionId)) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "ServerHello session id does not echo ours");
            }
            if (!offered.suites.contains(info.cipherSuite) || info.cipherSuite != TLS_AES_128_GCM_SHA256) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "server selected a cipher suite we did not offer");
            }
            if (compression != 0) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "server selected compression");
            }
            info.helloRetry = Arrays.equals(random, HRR_RANDOM);
            for (Integer type : exts.keySet()) {
                boolean allowed = type == EXT_SUPPORTED_VERSIONS || type == EXT_KEY_SHARE
                        || (info.helloRetry && type == EXT_COOKIE);
                if (!allowed) {
                    throw new TlsException(offered.extensions.contains(type) || type == EXT_COOKIE
                            ? TlsException.ILLEGAL_PARAMETER : TlsException.UNSUPPORTED_EXTENSION,
                            "extension " + type + " not allowed in ServerHello");
                }
            }
            byte[] ks = exts.get(EXT_KEY_SHARE);
            if (info.helloRetry) {
                if (ks != null) {
                    TlsReader k = new TlsReader(ks);
                    info.keyShareGroup = k.u16();
                    k.expectEnd();
                }
                byte[] cookie = exts.get(EXT_COOKIE);
                if (cookie != null) {
                    TlsReader c = new TlsReader(cookie);
                    info.cookie = c.vec16();
                    c.expectEnd();
                    if (info.cookie.length == 0) {
                        throw new TlsException(TlsException.DECODE_ERROR, "empty HelloRetryRequest cookie");
                    }
                }
            } else {
                if (ks == null) {
                    throw new TlsException(TlsException.MISSING_EXTENSION, "ServerHello lacks key_share");
                }
                TlsReader k = new TlsReader(ks);
                info.keyShareGroup = k.u16();
                info.keyShare = k.vec16();
                k.expectEnd();
            }
            return info;
        }
    }

    // ------------------------------------------------------------------ record layer

    private Record readRecord() throws Exception {
        while (true) {
            if (handshakeDeadline != 0 && System.nanoTime() - handshakeDeadline > 0) {
                throw new java.net.SocketTimeoutException("TLS handshake timed out");
            }
            byte[] header = new byte[5];
            if (!readFully(header, true)) {
                return null;
            }
            int type = header[0] & 0xff;
            int len = ((header[3] & 0xff) << 8) | (header[4] & 0xff);
            if (header[1] != 3) {
                throw new TlsException(TlsException.DECODE_ERROR, "not a TLS record");
            }
            if (len > MAX_CIPHERTEXT) {
                throw new TlsException(TlsException.RECORD_OVERFLOW, "record too large");
            }
            byte[] payload = new byte[len];
            readFully(payload, false);

            if (type == CT_CHANGE_CIPHER_SPEC) {
                if (!handshakeDone && len == 1 && payload[0] == 1) {
                    continue; // middlebox compatibility; not part of the transcript
                }
                throw unexpected("unexpected change_cipher_spec record");
            }
            if (readProtection == null) {
                // Plaintext records exist only before the server handshake key. Afterwards an
                // unprotected record (even an alert) is refused: an unauthenticated close_notify
                // would otherwise let anyone on the path truncate a download.
                if (type == CT_APPLICATION_DATA) {
                    throw unexpected("application data before encryption");
                }
                if (len > MAX_PLAINTEXT) {
                    throw new TlsException(TlsException.RECORD_OVERFLOW, "plaintext record too large");
                }
                if (len == 0 && type != CT_APPLICATION_DATA) {
                    throw unexpected("empty record");
                }
                return new Record(type, payload);
            }
            if (type != CT_APPLICATION_DATA) {
                throw unexpected("unprotected record type " + type + " after key change");
            }
            Protection p = readProtection;
            if (p.seq >= READ_RECORD_LIMIT) {
                throw new TlsException(TlsException.INTERNAL_ERROR, "server exceeded the record limit without KeyUpdate");
            }
            byte[] inner;
            try {
                inner = p.aead.decrypt(p.nonce(), payload, header);
            } catch (SecurityException e) {
                throw new TlsException(TlsException.BAD_RECORD_MAC, "record authentication failed", e);
            }
            p.seq++;
            int end = inner.length;
            while (end > 0 && inner[end - 1] == 0) {
                end--;
            }
            if (end == 0) {
                throw unexpected("protected record has no content type");
            }
            int innerType = inner[end - 1] & 0xff;
            int contentLen = end - 1;
            if (contentLen > MAX_PLAINTEXT) {
                throw new TlsException(TlsException.RECORD_OVERFLOW, "decrypted record too large");
            }
            if (contentLen == 0 && innerType != CT_APPLICATION_DATA) {
                throw unexpected("empty protected record");
            }
            if (innerType == CT_CHANGE_CIPHER_SPEC) {
                throw unexpected("protected change_cipher_spec");
            }
            return new Record(innerType, Arrays.copyOf(inner, contentLen));
        }
    }

    private boolean readFully(byte[] b, boolean eofAllowedAtStart) throws IOException {
        int pos = 0;
        while (pos < b.length) {
            int n = in.read(b, pos, b.length - pos);
            if (n < 0) {
                if (pos == 0 && eofAllowedAtStart) {
                    return false;
                }
                throw new EOFException("connection closed inside a TLS record");
            }
            pos += n;
        }
        return true;
    }

    /** Returns the next complete handshake message (header included) during the handshake. */
    private byte[] nextHandshakeMessage() throws Exception {
        while (true) {
            byte[] msg = takeHandshakeMessage();
            if (msg != null) {
                return msg;
            }
            Record rec = readRecord();
            if (rec == null) {
                throw new EOFException("connection closed during the TLS handshake");
            }
            if (rec.type == CT_ALERT) {
                throw alertReceived(rec.data);
            }
            if (rec.type != CT_HANDSHAKE) {
                throw unexpected("expected a handshake record, got type " + rec.type);
            }
            appendHandshake(rec.data);
        }
    }

    private void appendHandshake(byte[] data) throws TlsException {
        handshakeBytesTotal += data.length;
        if (!handshakeDone && handshakeBytesTotal > MAX_HANDSHAKE_TOTAL) {
            throw new TlsException(TlsException.INTERNAL_ERROR, "handshake exceeds the size budget");
        }
        byte[] merged = new byte[handshakeBuffer.length + data.length];
        System.arraycopy(handshakeBuffer, 0, merged, 0, handshakeBuffer.length);
        System.arraycopy(data, 0, merged, handshakeBuffer.length, data.length);
        handshakeBuffer = merged;
    }

    private byte[] takeHandshakeMessage() throws TlsException {
        if (handshakeBuffer.length < 4) {
            return null;
        }
        int len = ((handshakeBuffer[1] & 0xff) << 16) | ((handshakeBuffer[2] & 0xff) << 8) | (handshakeBuffer[3] & 0xff);
        if (len > MAX_HANDSHAKE_MESSAGE) {
            throw new TlsException(TlsException.INTERNAL_ERROR, "handshake message too large");
        }
        if (handshakeBuffer.length < 4 + len) {
            return null;
        }
        byte[] msg = Arrays.copyOf(handshakeBuffer, 4 + len);
        handshakeBuffer = Arrays.copyOfRange(handshakeBuffer, 4 + len, handshakeBuffer.length);
        return msg;
    }

    /** A key change must fall on a record boundary: no half-read handshake data may remain. */
    private void requireKeyChangeBoundary() throws TlsException {
        if (handshakeBuffer.length != 0) {
            throw unexpected("handshake data spans a key change");
        }
    }

    private void writePlain(int type, byte[] data, int recordVersion) throws IOException {
        int pos = 0;
        do {
            int n = Math.min(MAX_PLAINTEXT, data.length - pos);
            byte[] rec = new byte[5 + n];
            rec[0] = (byte) type;
            rec[1] = (byte) (recordVersion >>> 8);
            rec[2] = (byte) recordVersion;
            rec[3] = (byte) (n >>> 8);
            rec[4] = (byte) n;
            System.arraycopy(data, pos, rec, 5, n);
            out.write(rec);
            pos += n;
        } while (pos < data.length);
    }

    private void writeProtected(int type, byte[] data) throws Exception {
        writeProtected(type, data, 0, data.length);
    }

    private void writeProtected(int type, byte[] data, int off, int len) throws Exception {
        int pos = 0;
        do {
            int n = Math.min(MAX_PLAINTEXT, len - pos);
            byte[] inner = new byte[n + 1];
            System.arraycopy(data, off + pos, inner, 0, n);
            inner[n] = (byte) type;
            int cipherLen = inner.length + AesGcm.TAG_LEN;
            byte[] header = { CT_APPLICATION_DATA, 3, 3, (byte) (cipherLen >>> 8), (byte) cipherLen };
            Protection p = writeProtection;
            byte[] sealed = p.aead.encrypt(p.nonce(), inner, header);
            p.seq++;
            byte[] rec = new byte[5 + sealed.length];
            System.arraycopy(header, 0, rec, 0, 5);
            System.arraycopy(sealed, 0, rec, 5, sealed.length);
            out.write(rec);
            pos += n;
        } while (pos < len);
    }

    // ------------------------------------------------------------------ application data

    private int readApplicationData(byte[] b, int off, int len) throws IOException {
        synchronized (readLock) {
            if (len == 0) {
                return 0;
            }
            while (appPos >= appBuffer.length) {
                if (inputClosed || closed) {
                    return -1;
                }
                Record rec;
                try {
                    rec = readRecord();
                } catch (IOException e) {
                    failQuietly(e);
                    throw e;
                } catch (Exception e) {
                    failQuietly(null);
                    throw new TlsException(TlsException.INTERNAL_ERROR, "TLS read error: " + e, e);
                }
                if (rec == null) {
                    // TCP closed without close_notify. The HTTP layer's length checks
                    // decide whether the body is complete.
                    inputClosed = true;
                    return -1;
                }
                if (rec.type == CT_APPLICATION_DATA) {
                    appBuffer = rec.data;
                    appPos = 0;
                } else if (rec.type == CT_HANDSHAKE) {
                    try {
                        handlePostHandshake(rec.data);
                    } catch (IOException e) {
                        failQuietly(e);
                        throw e;
                    } catch (Exception e) {
                        failQuietly(null);
                        throw new TlsException(TlsException.INTERNAL_ERROR, "TLS post-handshake error: " + e, e);
                    }
                } else if (rec.type == CT_ALERT) {
                    TlsException alert = alertReceived(rec.data);
                    if (alert.alert == TlsException.CLOSE_NOTIFY) {
                        inputClosed = true;
                        return -1;
                    }
                    if (alert.alert == 90) {
                        continue; // user_canceled: a close_notify follows
                    }
                    closeTransport();
                    throw alert;
                } else {
                    TlsException e = unexpected("unexpected record type " + rec.type);
                    failQuietly(e);
                    throw e;
                }
            }
            int n = Math.min(len, appBuffer.length - appPos);
            System.arraycopy(appBuffer, appPos, b, off, n);
            appPos += n;
            return n;
        }
    }

    private void handlePostHandshake(byte[] data) throws Exception {
        appendHandshake(data);
        byte[] msg;
        while ((msg = takeHandshakeMessage()) != null) {
            int t = type(msg);
            if (t == HT_NEW_SESSION_TICKET) {
                continue; // resumption is not used
            }
            if (t != HT_KEY_UPDATE) {
                throw unexpected("unexpected post-handshake message " + t);
            }
            TlsReader r = body(msg);
            int request = r.u8();
            r.expectEnd();
            if (request != 0 && request != 1) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "bad KeyUpdate request value");
            }
            requireKeyChangeBoundary();
            readProtection = readProtection.next();
            keyUpdatesReceived++;
            if (request == 1) {
                synchronized (writeLock) {
                    sendKeyUpdate(false);
                    out.flush();
                }
            }
        }
    }

    /** Caller holds writeLock. */
    private void sendKeyUpdate(boolean requestPeer) throws Exception {
        writeProtected(CT_HANDSHAKE, TlsWriter.handshake(HT_KEY_UPDATE, new byte[] { (byte) (requestPeer ? 1 : 0) }));
        writeProtection = writeProtection.next();
    }

    private void writeApplicationData(byte[] b, int off, int len) throws IOException {
        synchronized (writeLock) {
            if (closed) {
                throw new IOException("TLS connection closed");
            }
            try {
                writeProtected(CT_APPLICATION_DATA, b, off, len);
                if (writeProtection.seq >= WRITE_KEY_UPDATE_AT) {
                    sendKeyUpdate(false);
                }
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new TlsException(TlsException.INTERNAL_ERROR, "TLS write error: " + e, e);
            }
        }
    }

    // ------------------------------------------------------------------ alerts and closing

    private static TlsException alertReceived(byte[] data) {
        if (data.length != 2) {
            return new TlsException(TlsException.DECODE_ERROR, "malformed alert");
        }
        int desc = data[1] & 0xff;
        return new TlsException(desc, true, "server sent TLS alert " + desc, null);
    }

    private static TlsException unexpected(String message) {
        return new TlsException(TlsException.UNEXPECTED_MESSAGE, message);
    }

    private void failQuietly(IOException cause) {
        if (cause instanceof TlsException && !((TlsException) cause).received) {
            sendAlertQuietly(((TlsException) cause).alert);
        }
        closeTransport();
    }

    private void sendAlertQuietly(int description) {
        synchronized (writeLock) {
            try {
                byte[] alert = { (byte) (description == TlsException.CLOSE_NOTIFY ? 1 : 2), (byte) description };
                if (writeProtection != null) {
                    writeProtected(CT_ALERT, alert);
                } else {
                    writePlain(CT_ALERT, alert, VERSION_TLS12);
                }
                out.flush();
            } catch (Exception ignored) {
                // best effort
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (closed) {
            return;
        }
        if (handshakeDone) {
            sendAlertQuietly(TlsException.CLOSE_NOTIFY);
        }
        closeTransport();
    }

    private void closeTransport() {
        closed = true;
        if (socket != null) {
            closeQuietly(socket);
        } else {
            try { in.close(); } catch (IOException ignored) {}
            try { out.close(); } catch (IOException ignored) {}
        }
    }

    private static void closeQuietly(Socket s) {
        try {
            s.close();
        } catch (IOException ignored) {
            // nothing to do
        }
    }

    // ------------------------------------------------------------------ helpers

    private byte[] transcriptHash() throws Exception {
        return sha256(transcript.toByteArray());
    }

    static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    private static int type(byte[] msg) {
        return msg[0] & 0xff;
    }

    private static TlsReader body(byte[] msg) {
        return new TlsReader(msg, 4, msg.length - 4);
    }
}
