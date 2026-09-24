package org.reteget.core.tls;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/**
 * TLS 1.2 client (RFC 5246), used only when a server does not speak TLS 1.3.
 *
 * Profile: ECDHE_ECDSA / ECDHE_RSA with AES_128_GCM_SHA256 (RFC 5289), key exchange
 * X25519 or secp256r1, Extended Master Secret when the server supports it (RFC 7627).
 * The ServerKeyExchange signature, the certificate chain and host name, and the server
 * Finished are all verified before any application data is exchanged. Resumption,
 * renegotiation, client certificates and static RSA key exchange are not supported.
 *
 * A separate state machine from {@link Tls13Socket}, as RFC-0002 section 15 asks.
 */
public final class Tls12Socket implements TlsConnection {

    static final int CT_CHANGE_CIPHER_SPEC = 20;
    static final int CT_ALERT = 21;
    static final int CT_HANDSHAKE = 22;
    static final int CT_APPLICATION_DATA = 23;

    static final int HT_HELLO_REQUEST = 0;
    static final int HT_CLIENT_HELLO = 1;
    static final int HT_SERVER_HELLO = 2;
    static final int HT_CERTIFICATE = 11;
    static final int HT_SERVER_KEY_EXCHANGE = 12;
    static final int HT_CERTIFICATE_REQUEST = 13;
    static final int HT_SERVER_HELLO_DONE = 14;
    static final int HT_CLIENT_KEY_EXCHANGE = 16;
    static final int HT_FINISHED = 20;

    static final int EXT_SERVER_NAME = 0;
    static final int EXT_SUPPORTED_GROUPS = 10;
    static final int EXT_EC_POINT_FORMATS = 11;
    static final int EXT_SIGNATURE_ALGORITHMS = 13;
    static final int EXT_EXTENDED_MASTER_SECRET = 23;
    static final int EXT_RENEGOTIATION_INFO = 0xff01;

    static final int ECDHE_ECDSA_AES_128_GCM_SHA256 = 0xc02b;
    static final int ECDHE_RSA_AES_128_GCM_SHA256 = 0xc02f;
    static final int EMPTY_RENEGOTIATION_INFO_SCSV = 0x00ff;

    static final int MAX_PLAINTEXT = 16384;
    static final int MAX_CIPHERTEXT = MAX_PLAINTEXT + 8 + AesGcm.TAG_LEN;
    static final int MAX_HANDSHAKE_TOTAL = 1024 * 1024;
    static final long SEQUENCE_LIMIT = 1L << 24;

    private final Socket socket;
    private final InputStream in;
    private final OutputStream out;
    private final String host;
    private final CertificatePolicy policy;
    private final Object readLock = new Object();
    private final Object writeLock = new Object();

    private final ByteArrayOutputStream transcript = new ByteArrayOutputStream();
    private byte[] handshakeBuffer = new byte[0];
    private int handshakeBytesTotal;

    private AesGcm readAead, writeAead;
    private byte[] readSalt, writeSalt;
    private long readSeq, writeSeq;
    private boolean handshakeDone;
    private boolean inputClosed;
    private volatile boolean closed;
    private long handshakeDeadline;

    private byte[] appBuffer = new byte[0];
    private int appPos;

    private String suiteName = "";
    private String groupName = "";
    private String signatureName = "";
    private boolean extendedMasterSecret;

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
        public void close() throws IOException {
            Tls12Socket.this.close();
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
            Tls12Socket.this.close();
        }
    };

    Tls12Socket(Socket socket, InputStream in, OutputStream out, String host, CertificatePolicy policy) {
        this.socket = socket;
        this.in = in;
        this.out = out;
        this.host = host;
        this.policy = policy;
    }

    public static Tls12Socket connect(String host, int port, int timeoutMs, CertificatePolicy policy)
            throws IOException {
        Socket s = new Socket();
        try {
            s.connect(new InetSocketAddress(host, port), timeoutMs);
            s.setSoTimeout(timeoutMs);
            s.setTcpNoDelay(true);
            Tls12Socket t = new Tls12Socket(s, s.getInputStream(), s.getOutputStream(), host, policy);
            t.handshake();
            return t;
        } catch (IOException e) {
            try { s.close(); } catch (IOException ignored) {}
            throw e;
        } catch (RuntimeException e) {
            try { s.close(); } catch (IOException ignored) {}
            throw new TlsException(TlsException.INTERNAL_ERROR, "TLS 1.2 internal error: " + e, e);
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
        return "TLSv1.2";
    }

    @Override
    public String getCipherSuite() {
        return suiteName;
    }

    @Override
    public String getSummary() {
        return "TLS 1.2 " + suiteName.replace("TLS_", "") + " " + groupName + " " + signatureName
                + (extendedMasterSecret ? " EMS" : "")
                + (policy.isInsecure() ? " (certificate NOT verified)" : "");
    }

    // ------------------------------------------------------------------ handshake

    void handshake() throws IOException {
        handshakeDeadline = System.nanoTime() + Tls13Socket.HANDSHAKE_TIMEOUT_MS * 1000000L;
        try {
            runHandshake();
        } catch (TlsException e) {
            if (!e.received) sendAlertQuietly(e.alert);
            closeTransport();
            throw e;
        } catch (IOException e) {
            closeTransport();
            throw e;
        } catch (Exception e) {
            sendAlertQuietly(TlsException.INTERNAL_ERROR);
            closeTransport();
            throw new TlsException(TlsException.INTERNAL_ERROR, "TLS 1.2 handshake error: " + e, e);
        }
        handshakeDeadline = 0;
    }

    private void runHandshake() throws Exception {
        byte[] clientRandom = TlsRandom.bytes(32);
        byte[] clientHello = buildClientHello(clientRandom);
        writePlain(CT_HANDSHAKE, clientHello, 0x0301);
        out.flush();
        transcript.write(clientHello);

        // ServerHello
        byte[] sh = nextHandshakeMessage();
        if (type(sh) != HT_SERVER_HELLO) throw unexpected("expected ServerHello");
        transcript.write(sh);
        TlsReader r = body(sh);
        int version = r.u16();
        byte[] serverRandom = r.bytes(32);
        r.vec8(); // session id: resumption is not used
        int suite = r.u16();
        int compression = r.u8();
        Set<Integer> seen = new HashSet<Integer>();
        boolean secureRenegotiation = false;
        if (r.hasRemaining()) {
            TlsReader exts = r.subVec16();
            while (exts.hasRemaining()) {
                int t = exts.u16();
                byte[] data = exts.vec16();
                if (!seen.add(t)) throw new TlsException(TlsException.ILLEGAL_PARAMETER, "duplicate extension " + t);
                if (t == EXT_RENEGOTIATION_INFO) {
                    if (data.length != 1 || data[0] != 0) {
                        throw new TlsException(TlsException.HANDSHAKE_FAILURE, "bad renegotiation_info");
                    }
                    secureRenegotiation = true;
                } else if (t == EXT_EXTENDED_MASTER_SECRET) {
                    if (data.length != 0) throw new TlsException(TlsException.DECODE_ERROR, "bad extended_master_secret");
                    extendedMasterSecret = true;
                } else if (t != EXT_EC_POINT_FORMATS && t != EXT_SERVER_NAME) {
                    throw new TlsException(TlsException.UNSUPPORTED_EXTENSION, "unrequested extension " + t);
                }
            }
        }
        r.expectEnd();
        if (version != 0x0303) {
            throw new TlsException(TlsException.PROTOCOL_VERSION, "server does not support TLS 1.2");
        }
        byte[] tail = Arrays.copyOfRange(serverRandom, 24, 32);
        if (Arrays.equals(tail, Tls13Socket.DOWNGRADE_TLS12) || Arrays.equals(tail, Tls13Socket.DOWNGRADE_TLS11)) {
            throw new TlsException(TlsException.ILLEGAL_PARAMETER,
                    "server supports TLS 1.3 but TLS 1.2 was negotiated: possible downgrade attack");
        }
        if (suite != ECDHE_ECDSA_AES_128_GCM_SHA256 && suite != ECDHE_RSA_AES_128_GCM_SHA256) {
            throw new TlsException(TlsException.ILLEGAL_PARAMETER, "server selected a cipher suite we did not offer");
        }
        if (compression != 0) throw new TlsException(TlsException.ILLEGAL_PARAMETER, "server selected compression");
        suiteName = suite == ECDHE_ECDSA_AES_128_GCM_SHA256
                ? "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256" : "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";

        // Certificate
        byte[] certMsg = nextHandshakeMessage();
        if (type(certMsg) != HT_CERTIFICATE) throw unexpected("expected Certificate");
        transcript.write(certMsg);
        TlsReader cr = body(certMsg);
        TlsReader list = cr.subVec24();
        cr.expectEnd();
        java.util.List<X509Cert> certs = new java.util.ArrayList<X509Cert>();
        while (list.hasRemaining()) {
            if (certs.size() == Tls13Socket.MAX_CERTIFICATES) {
                throw new TlsException(TlsException.BAD_CERTIFICATE, "certificate chain too long");
            }
            byte[] der = list.vec24();
            if (der.length == 0 || der.length > Tls13Socket.MAX_CERTIFICATE_SIZE) {
                throw new TlsException(TlsException.BAD_CERTIFICATE, "certificate size out of range");
            }
            X509Cert c = Tls13Socket.parseCertificateDer(der, certs.isEmpty());
            if (c != null) certs.add(c);
        }
        if (certs.isEmpty()) throw new TlsException(TlsException.DECODE_ERROR, "server sent no certificate");
        X509Cert[] chain = certs.toArray(new X509Cert[certs.size()]);
        PublicKeyInfo serverKey = chain[0].publicKey;
        if (suite == ECDHE_ECDSA_AES_128_GCM_SHA256 ? !serverKey.isEc() : !serverKey.isRsa()) {
            throw new TlsException(TlsException.UNSUPPORTED_CERTIFICATE, "certificate key does not match the cipher suite");
        }
        try {
            policy.check(host, chain, Tls13Socket.platformChain(chain));
        } catch (CertificateException e) {
            throw new TlsException(TlsException.BAD_CERTIFICATE, "server certificate rejected: " + e.getMessage(), e);
        }

        // ServerKeyExchange: ECParameters || ServerECDHParams.public || signature
        byte[] ske = nextHandshakeMessage();
        if (type(ske) != HT_SERVER_KEY_EXCHANGE) throw unexpected("expected ServerKeyExchange");
        transcript.write(ske);
        TlsReader kr = body(ske);
        int curveType = kr.u8();
        int group = kr.u16();
        byte[] serverPublic = kr.vec8();
        int paramsLen = 4 + serverPublic.length;
        int scheme = kr.u16();
        byte[] signature = kr.vec16();
        kr.expectEnd();
        if (curveType != 3 || (group != Tls13Socket.GROUP_X25519 && group != Tls13Socket.GROUP_SECP256R1)) {
            throw new TlsException(TlsException.ILLEGAL_PARAMETER, "server chose an unoffered key exchange group");
        }
        if (!SignatureSchemes.contains(SignatureSchemes.TLS12_HANDSHAKE, scheme)) {
            throw new TlsException(TlsException.ILLEGAL_PARAMETER, "server used an unoffered signature scheme");
        }
        byte[] signedParams = new byte[64 + paramsLen];
        System.arraycopy(clientRandom, 0, signedParams, 0, 32);
        System.arraycopy(serverRandom, 0, signedParams, 32, 32);
        System.arraycopy(ske, 4, signedParams, 64, paramsLen);
        boolean ok;
        try {
            ok = SignatureSchemes.verify(scheme, serverKey, signedParams, signature, false);
        } catch (IllegalArgumentException e) {
            throw new TlsException(TlsException.UNSUPPORTED_CERTIFICATE, e.getMessage(), e);
        }
        if (!ok) throw new TlsException(TlsException.DECRYPT_ERROR, "ServerKeyExchange signature is invalid");
        signatureName = SignatureSchemes.name(scheme);

        // ServerHelloDone (a CertificateRequest here means client authentication)
        byte[] done = nextHandshakeMessage();
        if (type(done) == HT_CERTIFICATE_REQUEST) {
            throw new TlsException(TlsException.HANDSHAKE_FAILURE, "server requires a client certificate, which is not supported");
        }
        if (type(done) != HT_SERVER_HELLO_DONE || done.length != 4) throw unexpected("expected ServerHelloDone");
        transcript.write(done);

        // Key exchange
        byte[] ourPublic;
        byte[] premaster;
        if (group == Tls13Socket.GROUP_X25519) {
            if (serverPublic.length != X25519.KEY_LEN) throw new TlsException(TlsException.ILLEGAL_PARAMETER, "bad X25519 key");
            byte[] priv = TlsRandom.bytes(32);
            ourPublic = X25519.publicKey(priv);
            premaster = X25519.scalarMult(priv, serverPublic);
            Arrays.fill(priv, (byte) 0);
            if (X25519.isAllZero(premaster)) throw new TlsException(TlsException.ILLEGAL_PARAMETER, "X25519 shared secret is zero");
            groupName = "x25519";
        } else {
            EcCurve.Point peer;
            try {
                peer = EcCurve.P256.decodePoint(serverPublic);
            } catch (IllegalArgumentException e) {
                throw new TlsException(TlsException.ILLEGAL_PARAMETER, "invalid P-256 server key", e);
            }
            BigInteger k = EcCurve.P256.randomScalar();
            ourPublic = EcCurve.P256.encodePoint(EcCurve.P256.multiplyBase(k));
            premaster = EcCurve.P256.ecdh(k, peer);
            groupName = "secp256r1";
        }
        byte[] cke = TlsWriter.handshake(HT_CLIENT_KEY_EXCHANGE, new TlsWriter().vec8(ourPublic).toByteArray());
        transcript.write(cke);

        byte[] master = extendedMasterSecret
                ? prf(premaster, "extended master secret", sha256(transcript.toByteArray()), 48)
                : prf(premaster, "master secret", cat(clientRandom, serverRandom), 48);
        Arrays.fill(premaster, (byte) 0);
        byte[] keyBlock = prf(master, "key expansion", cat(serverRandom, clientRandom), 40);
        writeAead = new AesGcm(Arrays.copyOfRange(keyBlock, 0, 16));
        AesGcm serverAead = new AesGcm(Arrays.copyOfRange(keyBlock, 16, 32));
        writeSalt = Arrays.copyOfRange(keyBlock, 32, 36);
        byte[] serverSalt = Arrays.copyOfRange(keyBlock, 36, 40);
        Arrays.fill(keyBlock, (byte) 0);

        writePlain(CT_HANDSHAKE, cke, 0x0303);
        writePlain(CT_CHANGE_CIPHER_SPEC, new byte[] { 1 }, 0x0303);
        byte[] clientFinished = TlsWriter.handshake(HT_FINISHED,
                prf(master, "client finished", sha256(transcript.toByteArray()), 12));
        transcript.write(clientFinished);
        writeProtected(CT_HANDSHAKE, clientFinished, 0, clientFinished.length);
        out.flush();

        // Server ChangeCipherSpec, then Finished under the new keys.
        if (handshakeBuffer.length != 0) throw unexpected("handshake data before ChangeCipherSpec");
        byte[][] rec = readRecord();
        if (rec == null) throw new EOFException("connection closed before server ChangeCipherSpec");
        if ((rec[0][0] & 0xff) == CT_ALERT) throw alertReceived(rec[1]);
        if ((rec[0][0] & 0xff) != CT_CHANGE_CIPHER_SPEC || rec[1].length != 1 || rec[1][0] != 1) {
            throw unexpected("expected ChangeCipherSpec");
        }
        readAead = serverAead;
        readSalt = serverSalt;
        byte[] fin = nextHandshakeMessage();
        if (type(fin) != HT_FINISHED) throw unexpected("expected Finished");
        byte[] expected = prf(master, "server finished", sha256(transcript.toByteArray()), 12);
        TlsReader fr = body(fin);
        byte[] verify = fr.bytes(12);
        fr.expectEnd();
        if (!MessageDigest.isEqual(expected, verify)) {
            throw new TlsException(TlsException.DECRYPT_ERROR, "server Finished does not verify");
        }
        if (handshakeBuffer.length != 0) throw unexpected("trailing handshake data after Finished");
        Arrays.fill(master, (byte) 0);
        transcript.reset();
        handshakeDone = true;
        if (!secureRenegotiation) {
            // Legacy server; harmless for us because renegotiation is always refused.
            signatureName = signatureName + " (no RI)";
        }
    }

    private byte[] buildClientHello(byte[] random) {
        TlsWriter ext = new TlsWriter();
        if (!HostnameChecker.isIpLiteral(host)) {
            ext.extension(EXT_SERVER_NAME, new TlsWriter().vec16(
                    new TlsWriter().u8(0).vec16(Hkdf.ascii(host)).toByteArray()).toByteArray());
        }
        ext.extension(EXT_SUPPORTED_GROUPS, new TlsWriter().vec16(new TlsWriter()
                .u16(Tls13Socket.GROUP_X25519).u16(Tls13Socket.GROUP_SECP256R1).toByteArray()).toByteArray());
        ext.extension(EXT_EC_POINT_FORMATS, new byte[] { 1, 0 });
        TlsWriter schemes = new TlsWriter();
        for (int s : SignatureSchemes.TLS12_HANDSHAKE) schemes.u16(s);
        ext.extension(EXT_SIGNATURE_ALGORITHMS, new TlsWriter().vec16(schemes.toByteArray()).toByteArray());
        ext.extension(EXT_EXTENDED_MASTER_SECRET, new byte[0]);
        TlsWriter body = new TlsWriter()
                .u16(0x0303)
                .raw(random)
                .vec8(new byte[0])
                .vec16(new TlsWriter().u16(ECDHE_ECDSA_AES_128_GCM_SHA256).u16(ECDHE_RSA_AES_128_GCM_SHA256)
                        .u16(EMPTY_RENEGOTIATION_INFO_SCSV).toByteArray())
                .vec8(new byte[] { 0 })
                .vec16(ext.toByteArray());
        return TlsWriter.handshake(HT_CLIENT_HELLO, body.toByteArray());
    }

    /** TLS 1.2 PRF with HMAC-SHA256 (RFC 5246 section 5). */
    static byte[] prf(byte[] secret, String label, byte[] seed, int length) throws Exception {
        byte[] labelSeed = cat(Hkdf.ascii(label), seed);
        byte[] out = new byte[length];
        byte[] a = labelSeed;
        int pos = 0;
        while (pos < length) {
            a = Hkdf.hmac(secret, a);
            byte[] block = Hkdf.hmac(secret, cat(a, labelSeed));
            int n = Math.min(block.length, length - pos);
            System.arraycopy(block, 0, out, pos, n);
            pos += n;
        }
        return out;
    }

    // ------------------------------------------------------------------ records

    /** Returns {header, plaintext}, or null at a clean EOF before a record. */
    private byte[][] readRecord() throws Exception {
        if (handshakeDeadline != 0 && System.nanoTime() - handshakeDeadline > 0) {
            throw new java.net.SocketTimeoutException("TLS handshake timed out");
        }
        byte[] header = new byte[5];
        int pos = 0;
        while (pos < 5) {
            int n = in.read(header, pos, 5 - pos);
            if (n < 0) {
                if (pos == 0) return null;
                throw new EOFException("connection closed inside a TLS record");
            }
            pos += n;
        }
        int type = header[0] & 0xff;
        int len = ((header[3] & 0xff) << 8) | (header[4] & 0xff);
        if (header[1] != 3) throw new TlsException(TlsException.DECODE_ERROR, "not a TLS record");
        if (len > MAX_CIPHERTEXT) throw new TlsException(TlsException.RECORD_OVERFLOW, "record too large");
        byte[] payload = new byte[len];
        pos = 0;
        while (pos < len) {
            int n = in.read(payload, pos, len - pos);
            if (n < 0) throw new EOFException("connection closed inside a TLS record");
            pos += n;
        }
        if (readAead == null) {
            if (type == CT_APPLICATION_DATA) throw unexpected("application data before encryption");
            if (len > MAX_PLAINTEXT) throw new TlsException(TlsException.RECORD_OVERFLOW, "record too large");
            return new byte[][] { header, payload };
        }
        if (type == CT_CHANGE_CIPHER_SPEC) throw unexpected("second ChangeCipherSpec");
        if (len < 8 + AesGcm.TAG_LEN) throw new TlsException(TlsException.BAD_RECORD_MAC, "record too short");
        if (readSeq >= SEQUENCE_LIMIT) throw new TlsException(TlsException.INTERNAL_ERROR, "record limit reached");
        byte[] nonce = new byte[12];
        System.arraycopy(readSalt, 0, nonce, 0, 4);
        System.arraycopy(payload, 0, nonce, 4, 8);
        int plainLen = len - 8 - AesGcm.TAG_LEN;
        byte[] plain;
        try {
            plain = readAead.decrypt(nonce, payload, 8, len - 8, aad(readSeq, type, plainLen));
        } catch (SecurityException e) {
            throw new TlsException(TlsException.BAD_RECORD_MAC, "record authentication failed", e);
        }
        readSeq++;
        if (plain.length > MAX_PLAINTEXT) throw new TlsException(TlsException.RECORD_OVERFLOW, "record too large");
        return new byte[][] { header, plain };
    }

    private static byte[] aad(long seq, int type, int length) {
        byte[] a = new byte[13];
        AesGcm.putLong(seq, a, 0);
        a[8] = (byte) type;
        a[9] = 3;
        a[10] = 3;
        a[11] = (byte) (length >>> 8);
        a[12] = (byte) length;
        return a;
    }

    private void writePlain(int type, byte[] data, int version) throws IOException {
        byte[] rec = new byte[5 + data.length];
        rec[0] = (byte) type;
        rec[1] = (byte) (version >>> 8);
        rec[2] = (byte) version;
        rec[3] = (byte) (data.length >>> 8);
        rec[4] = (byte) data.length;
        System.arraycopy(data, 0, rec, 5, data.length);
        out.write(rec);
    }

    private void writeProtected(int type, byte[] data, int off, int len) throws Exception {
        int pos = 0;
        do {
            int n = Math.min(MAX_PLAINTEXT, len - pos);
            byte[] explicit = new byte[8];
            AesGcm.putLong(writeSeq, explicit, 0);
            byte[] nonce = new byte[12];
            System.arraycopy(writeSalt, 0, nonce, 0, 4);
            System.arraycopy(explicit, 0, nonce, 4, 8);
            byte[] sealed = writeAead.encrypt(nonce, data, off + pos, n, aad(writeSeq, type, n));
            writeSeq++;
            int recLen = 8 + sealed.length;
            byte[] rec = new byte[5 + recLen];
            rec[0] = (byte) type;
            rec[1] = 3;
            rec[2] = 3;
            rec[3] = (byte) (recLen >>> 8);
            rec[4] = (byte) recLen;
            System.arraycopy(explicit, 0, rec, 5, 8);
            System.arraycopy(sealed, 0, rec, 13, sealed.length);
            out.write(rec);
            pos += n;
        } while (pos < len);
    }

    private byte[] nextHandshakeMessage() throws Exception {
        while (true) {
            if (handshakeBuffer.length >= 4) {
                int len = ((handshakeBuffer[1] & 0xff) << 16) | ((handshakeBuffer[2] & 0xff) << 8)
                        | (handshakeBuffer[3] & 0xff);
                if (len > Tls13Socket.MAX_HANDSHAKE_MESSAGE) {
                    throw new TlsException(TlsException.INTERNAL_ERROR, "handshake message too large");
                }
                if (handshakeBuffer.length >= 4 + len) {
                    byte[] msg = Arrays.copyOf(handshakeBuffer, 4 + len);
                    handshakeBuffer = Arrays.copyOfRange(handshakeBuffer, 4 + len, handshakeBuffer.length);
                    if (type(msg) == HT_HELLO_REQUEST && !handshakeDone) {
                        continue; // RFC 5246 7.4.1.1: ignored during a handshake
                    }
                    return msg;
                }
            }
            byte[][] rec = readRecord();
            if (rec == null) throw new EOFException("connection closed during the TLS handshake");
            int type = rec[0][0] & 0xff;
            if (type == CT_ALERT) throw alertReceived(rec[1]);
            if (type != CT_HANDSHAKE || rec[1].length == 0) throw unexpected("expected a handshake record");
            handshakeBytesTotal += rec[1].length;
            if (handshakeBytesTotal > MAX_HANDSHAKE_TOTAL) {
                throw new TlsException(TlsException.INTERNAL_ERROR, "handshake exceeds the size budget");
            }
            handshakeBuffer = cat(handshakeBuffer, rec[1]);
        }
    }

    // ------------------------------------------------------------------ application data

    private int readApplicationData(byte[] b, int off, int len) throws IOException {
        synchronized (readLock) {
            if (len == 0) return 0;
            while (appPos >= appBuffer.length) {
                if (inputClosed || closed) return -1;
                byte[][] rec;
                try {
                    rec = readRecord();
                } catch (TlsException e) {
                    if (!e.received) sendAlertQuietly(e.alert);
                    closeTransport();
                    throw e;
                } catch (IOException e) {
                    closeTransport();
                    throw e;
                } catch (Exception e) {
                    closeTransport();
                    throw new TlsException(TlsException.INTERNAL_ERROR, "TLS read error: " + e, e);
                }
                if (rec == null) {
                    inputClosed = true;
                    return -1;
                }
                int type = rec[0][0] & 0xff;
                if (type == CT_APPLICATION_DATA) {
                    appBuffer = rec[1];
                    appPos = 0;
                } else if (type == CT_ALERT) {
                    TlsException alert = alertReceived(rec[1]);
                    if (alert.alert == TlsException.CLOSE_NOTIFY) {
                        inputClosed = true;
                        return -1;
                    }
                    if (rec[1].length == 2 && rec[1][0] == 1) continue; // other warnings
                    closeTransport();
                    throw alert;
                } else if (type == CT_HANDSHAKE && rec[1].length == 4 && rec[1][0] == HT_HELLO_REQUEST) {
                    sendAlertQuietly(100, 1); // warning: no_renegotiation
                } else {
                    TlsException e = unexpected("unexpected record type " + type);
                    sendAlertQuietly(e.alert);
                    closeTransport();
                    throw e;
                }
            }
            int n = Math.min(len, appBuffer.length - appPos);
            System.arraycopy(appBuffer, appPos, b, off, n);
            appPos += n;
            return n;
        }
    }

    private void writeApplicationData(byte[] b, int off, int len) throws IOException {
        synchronized (writeLock) {
            if (closed) throw new IOException("TLS connection closed");
            if (writeSeq >= SEQUENCE_LIMIT) throw new TlsException(TlsException.INTERNAL_ERROR, "record limit reached");
            try {
                writeProtected(CT_APPLICATION_DATA, b, off, len);
            } catch (IOException e) {
                throw e;
            } catch (Exception e) {
                throw new TlsException(TlsException.INTERNAL_ERROR, "TLS write error: " + e, e);
            }
        }
    }

    // ------------------------------------------------------------------ alerts, closing, helpers

    private static TlsException alertReceived(byte[] data) {
        if (data.length != 2) return new TlsException(TlsException.DECODE_ERROR, "malformed alert");
        return new TlsException(data[1] & 0xff, true, "server sent TLS alert " + (data[1] & 0xff), null);
    }

    private static TlsException unexpected(String m) {
        return new TlsException(TlsException.UNEXPECTED_MESSAGE, m);
    }

    private void sendAlertQuietly(int description) {
        sendAlertQuietly(description, description == TlsException.CLOSE_NOTIFY ? 1 : 2);
    }

    private void sendAlertQuietly(int description, int level) {
        synchronized (writeLock) {
            try {
                byte[] alert = { (byte) level, (byte) description };
                if (writeAead != null) {
                    writeProtected(CT_ALERT, alert, 0, 2);
                } else {
                    writePlain(CT_ALERT, alert, 0x0303);
                }
                out.flush();
            } catch (Exception ignored) {
                // best effort
            }
        }
    }

    @Override
    public void close() throws IOException {
        if (closed) return;
        if (handshakeDone) sendAlertQuietly(TlsException.CLOSE_NOTIFY);
        closeTransport();
    }

    private void closeTransport() {
        closed = true;
        if (socket != null) {
            try { socket.close(); } catch (IOException ignored) {}
        } else {
            try { in.close(); } catch (IOException ignored) {}
            try { out.close(); } catch (IOException ignored) {}
        }
    }

    private static byte[] sha256(byte[] data) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(data);
    }

    static byte[] cat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    private static int type(byte[] msg) {
        return msg[0] & 0xff;
    }

    private static TlsReader body(byte[] msg) {
        return new TlsReader(msg, 4, msg.length - 4);
    }
}
