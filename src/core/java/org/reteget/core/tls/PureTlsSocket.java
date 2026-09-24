package org.reteget.core.tls;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.Closeable;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.X509TrustManager;

/**
 * Pure-Java TLS 1.2 client implementation providing standard InputStream and OutputStream.
 *
 * Implements:
 * - RFC 5246 (TLS 1.2) Record Layer and Handshake
 * - NIST P-256 (secp256r1) ECDHE Key Exchange with java.math.BigInteger
 * - Pure-Java AES-128-GCM with GHASH and AES/ECB/NoPadding (RFC 5116 / RFC 5288)
 * - TLS 1.2 PRF (RFC 5246) with HmacSHA256
 * - Server Name Indication (SNI) and Supported Groups extensions
 * - Optional X.509 Certificate Chain verification
 *
 * Enables modern HTTPS downloads on legacy Android devices (Android 4.1 / API 16, e.g. Galaxy Note 2)
 * where the system OpenSSL lacks TLS 1.2 GCM ciphers required by GitHub and modern CDNs.
 */
public class PureTlsSocket implements Closeable {

    // NIST P-256 Curve Parameters (secp256r1 / prime256v1)
    private static final BigInteger P = new BigInteger("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16);
    private static final BigInteger A = P.subtract(BigInteger.valueOf(3));
    private static final BigInteger B = new BigInteger("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b", 16);
    private static final BigInteger GX = new BigInteger("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16);
    private static final BigInteger GY = new BigInteger("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16);

    private static class Point {
        final BigInteger x, y;
        Point(BigInteger x, BigInteger y) { this.x = x; this.y = y; }
    }

    private static Point pointAdd(Point p1, Point p2) {
        if (p1 == null) return p2;
        if (p2 == null) return p1;
        if (p1.x.equals(p2.x)) {
            if (!p1.y.equals(p2.y)) return null;
            BigInteger lambda = p1.x.multiply(p1.x).multiply(BigInteger.valueOf(3)).add(A)
                    .multiply(p1.y.shiftLeft(1).modInverse(P)).mod(P);
            BigInteger x3 = lambda.multiply(lambda).subtract(p1.x.shiftLeft(1)).mod(P);
            BigInteger y3 = lambda.multiply(p1.x.subtract(x3)).subtract(p1.y).mod(P);
            return new Point(x3, y3);
        } else {
            BigInteger lambda = p2.y.subtract(p1.y).multiply(p2.x.subtract(p1.x).modInverse(P)).mod(P);
            BigInteger x3 = lambda.multiply(lambda).subtract(p1.x).subtract(p2.x).mod(P);
            BigInteger y3 = lambda.multiply(p1.x.subtract(x3)).subtract(p1.y).mod(P);
            return new Point(x3, y3);
        }
    }

    private static Point scalarMult(BigInteger k, Point p) {
        Point res = null;
        Point addend = p;
        while (k.signum() > 0) {
            if (k.testBit(0)) {
                res = pointAdd(res, addend);
            }
            addend = pointAdd(addend, addend);
            k = k.shiftRight(1);
        }
        return res;
    }

    private static byte[] toFixed32(BigInteger bi) {
        byte[] raw = bi.toByteArray();
        byte[] res = new byte[32];
        if (raw.length > 32) {
            System.arraycopy(raw, raw.length - 32, res, 0, 32);
        } else {
            System.arraycopy(raw, 0, res, 32 - raw.length, raw.length);
        }
        return res;
    }

    private static byte[] prfSha256(byte[] secret, String label, byte[] seed, int outLen) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret, "HmacSHA256"));
        byte[] labelBytes = label.getBytes("US-ASCII");
        byte[] s = new byte[labelBytes.length + seed.length];
        System.arraycopy(labelBytes, 0, s, 0, labelBytes.length);
        System.arraycopy(seed, 0, s, labelBytes.length, seed.length);

        byte[] a = s;
        byte[] out = new byte[outLen];
        int pos = 0;
        while (pos < outLen) {
            mac.reset();
            mac.update(a);
            a = mac.doFinal();

            mac.reset();
            mac.update(a);
            mac.update(s);
            byte[] block = mac.doFinal();

            int copy = Math.min(block.length, outLen - pos);
            System.arraycopy(block, 0, out, pos, copy);
            pos += copy;
        }
        return out;
    }

    public static class PureGcm {
        private final Cipher aesEcb;
        private final byte[] H;

        public PureGcm(byte[] key) throws Exception {
            this.aesEcb = Cipher.getInstance("AES/ECB/NoPadding");
            this.aesEcb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
            this.H = aesEcb.doFinal(new byte[16]);
        }

        private static void gmult(byte[] X, byte[] H) {
            long z0 = 0, z1 = 0;
            long v0 = getLong(H, 0);
            long v1 = getLong(H, 8);

            for (int i = 0; i < 2; i++) {
                long bits = getLong(X, i * 8);
                for (int j = 0; j < 64; j++) {
                    if ((bits & (1L << (63 - j))) != 0) {
                        z0 ^= v0;
                        z1 ^= v1;
                    }
                    boolean lsb = (v1 & 1) != 0;
                    v1 = (v1 >>> 1) | (v0 << 63);
                    v0 >>>= 1;
                    if (lsb) {
                        v0 ^= 0xe100000000000000L;
                    }
                }
            }
            putLong(z0, X, 0);
            putLong(z1, X, 8);
        }

        private static long getLong(byte[] b, int off) {
            return (((long) b[off] & 0xff) << 56)
                    | (((long) b[off + 1] & 0xff) << 48)
                    | (((long) b[off + 2] & 0xff) << 40)
                    | (((long) b[off + 3] & 0xff) << 32)
                    | (((long) b[off + 4] & 0xff) << 24)
                    | (((long) b[off + 5] & 0xff) << 16)
                    | (((long) b[off + 6] & 0xff) << 8)
                    | ((long) b[off + 7] & 0xff);
        }

        private static void putLong(long val, byte[] b, int off) {
            b[off] = (byte) (val >>> 56);
            b[off + 1] = (byte) (val >>> 48);
            b[off + 2] = (byte) (val >>> 40);
            b[off + 3] = (byte) (val >>> 32);
            b[off + 4] = (byte) (val >>> 24);
            b[off + 5] = (byte) (val >>> 16);
            b[off + 6] = (byte) (val >>> 8);
            b[off + 7] = (byte) val;
        }

        public byte[] encrypt(byte[] iv12, byte[] plaintext, byte[] aad) throws Exception {
            byte[] j0 = new byte[16];
            System.arraycopy(iv12, 0, j0, 0, 12);
            j0[15] = 1;

            byte[] ciphertext = new byte[plaintext.length];
            byte[] counter = Arrays.copyOf(j0, 16);

            int blocks = (plaintext.length + 15) / 16;
            for (int i = 0; i < blocks; i++) {
                inc32(counter);
                byte[] mask = aesEcb.doFinal(counter);
                int off = i * 16;
                int len = Math.min(16, plaintext.length - off);
                for (int j = 0; j < len; j++) {
                    ciphertext[off + j] = (byte) (plaintext[off + j] ^ mask[j]);
                }
            }

            byte[] S = new byte[16];
            ghashUpdate(S, aad);
            ghashUpdate(S, ciphertext);

            byte[] lenBlock = new byte[16];
            putLong(((long) aad.length) * 8L, lenBlock, 0);
            putLong(((long) ciphertext.length) * 8L, lenBlock, 8);
            ghashUpdate(S, lenBlock);

            byte[] tagMask = aesEcb.doFinal(j0);
            byte[] tag = new byte[16];
            for (int i = 0; i < 16; i++) {
                tag[i] = (byte) (S[i] ^ tagMask[i]);
            }

            byte[] out = new byte[ciphertext.length + 16];
            System.arraycopy(ciphertext, 0, out, 0, ciphertext.length);
            System.arraycopy(tag, 0, out, ciphertext.length, 16);
            return out;
        }

        public byte[] decrypt(byte[] iv12, byte[] ciphertextWithTag, byte[] aad) throws Exception {
            if (ciphertextWithTag.length < 16) throw new IllegalArgumentException("Payload too short");
            int cipherLen = ciphertextWithTag.length - 16;
            byte[] ciphertext = Arrays.copyOfRange(ciphertextWithTag, 0, cipherLen);
            byte[] expectedTag = Arrays.copyOfRange(ciphertextWithTag, cipherLen, ciphertextWithTag.length);

            byte[] j0 = new byte[16];
            System.arraycopy(iv12, 0, j0, 0, 12);
            j0[15] = 1;

            byte[] S = new byte[16];
            ghashUpdate(S, aad);
            ghashUpdate(S, ciphertext);

            byte[] lenBlock = new byte[16];
            putLong(((long) aad.length) * 8L, lenBlock, 0);
            putLong(((long) ciphertext.length) * 8L, lenBlock, 8);
            ghashUpdate(S, lenBlock);

            byte[] tagMask = aesEcb.doFinal(j0);
            byte[] computedTag = new byte[16];
            for (int i = 0; i < 16; i++) {
                computedTag[i] = (byte) (S[i] ^ tagMask[i]);
            }

            if (!MessageDigest.isEqual(computedTag, expectedTag)) {
                throw new SecurityException("GCM tag mismatch!");
            }

            byte[] plaintext = new byte[cipherLen];
            byte[] counter = Arrays.copyOf(j0, 16);
            int blocks = (cipherLen + 15) / 16;
            for (int i = 0; i < blocks; i++) {
                inc32(counter);
                byte[] mask = aesEcb.doFinal(counter);
                int off = i * 16;
                int len = Math.min(16, cipherLen - off);
                for (int j = 0; j < len; j++) {
                    plaintext[off + j] = (byte) (ciphertext[off + j] ^ mask[j]);
                }
            }
            return plaintext;
        }

        private void ghashUpdate(byte[] S, byte[] data) {
            if (data == null || data.length == 0) return;
            int blocks = (data.length + 15) / 16;
            byte[] block = new byte[16];
            for (int i = 0; i < blocks; i++) {
                int off = i * 16;
                int len = Math.min(16, data.length - off);
                Arrays.fill(block, (byte) 0);
                System.arraycopy(data, off, block, 0, len);
                for (int j = 0; j < 16; j++) {
                    S[j] ^= block[j];
                }
                gmult(S, H);
            }
        }

        private static void inc32(byte[] block) {
            for (int i = 15; i >= 12; i--) {
                if (++block[i] != 0) break;
            }
        }
    }

    private final Socket socket;
    private final DataInputStream dis;
    private final OutputStream rawOut;
    private final PureGcm clientGcm;
    private final PureGcm serverGcm;
    private final byte[] clientIV;
    private final byte[] serverIV;
    private long clientSeq = 1;
    private long serverSeq = 1;
    private boolean closed = false;

    private byte[] inBuf = new byte[0];
    private int inBufPos = 0;

    private final InputStream tlsIn;
    private final OutputStream tlsOut;

    private PureTlsSocket(Socket socket, PureGcm clientGcm, PureGcm serverGcm,
                          byte[] clientIV, byte[] serverIV, DataInputStream dis, OutputStream rawOut) {
        this.socket = socket;
        this.clientGcm = clientGcm;
        this.serverGcm = serverGcm;
        this.clientIV = clientIV;
        this.serverIV = serverIV;
        this.dis = dis;
        this.rawOut = rawOut;

        this.tlsIn = new InputStream() {
            @Override
            public int read() throws IOException {
                byte[] b = new byte[1];
                int n = read(b, 0, 1);
                return n == -1 ? -1 : (b[0] & 0xff);
            }

            @Override
            public int read(byte[] b, int off, int len) throws IOException {
                try {
                    return readRecord(b, off, len);
                } catch (IOException e) {
                    throw e;
                } catch (Exception e) {
                    throw new IOException("TLS read error: " + e.getMessage(), e);
                }
            }

            @Override
            public void close() throws IOException {
                PureTlsSocket.this.close();
            }
        };

        this.tlsOut = new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                write(new byte[] { (byte) b });
            }

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
                try {
                    writeRecord(b, off, len);
                } catch (IOException e) {
                    throw e;
                } catch (Exception e) {
                    throw new IOException("TLS write error: " + e.getMessage(), e);
                }
            }

            @Override
            public void flush() throws IOException {
                rawOut.flush();
            }

            @Override
            public void close() throws IOException {
                PureTlsSocket.this.close();
            }
        };
    }

    public InputStream getInputStream() {
        return tlsIn;
    }

    public OutputStream getOutputStream() {
        return tlsOut;
    }

    private synchronized void writeRecord(byte[] data, int off, int length) throws Exception {
        if (closed) throw new IOException("Socket closed");
        int pos = off;
        int remaining = length;
        while (remaining > 0) {
            int len = Math.min(16384, remaining);
            byte[] chunk = Arrays.copyOfRange(data, pos, pos + len);
            pos += len;
            remaining -= len;

            byte[] explicitNonce = new byte[8];
            PureGcm.putLong(clientSeq, explicitNonce, 0);

            byte[] nonce = new byte[12];
            System.arraycopy(clientIV, 0, nonce, 0, 4);
            System.arraycopy(explicitNonce, 0, nonce, 4, 8);

            byte[] aad = new byte[13];
            PureGcm.putLong(clientSeq, aad, 0);
            aad[8] = 0x17; // Application Data
            aad[9] = 0x03;
            aad[10] = 0x03;
            aad[11] = (byte) (len >> 8);
            aad[12] = (byte) len;

            byte[] encrypted = clientGcm.encrypt(nonce, chunk, aad);
            int recLen = 8 + encrypted.length;

            rawOut.write(new byte[] { 0x17, 0x03, 0x03, (byte) (recLen >> 8), (byte) recLen });
            rawOut.write(explicitNonce);
            rawOut.write(encrypted);
            clientSeq++;
        }
        rawOut.flush();
    }

    private synchronized int readRecord(byte[] buf, int offset, int maxLen) throws Exception {
        if (closed) return -1;
        if (inBufPos < inBuf.length) {
            int avail = inBuf.length - inBufPos;
            int toCopy = Math.min(avail, maxLen);
            System.arraycopy(inBuf, inBufPos, buf, offset, toCopy);
            inBufPos += toCopy;
            return toCopy;
        }

        while (true) {
            int recType;
            try {
                recType = dis.readUnsignedByte();
            } catch (EOFException e) {
                return -1;
            }
            int maj = dis.readUnsignedByte();
            int min = dis.readUnsignedByte();
            int recLen = dis.readUnsignedShort();
            byte[] recData = new byte[recLen];
            dis.readFully(recData);

            if (recType == 0x15) { // Alert
                if (recData.length >= 2 && recData[1] == 0) { // close_notify
                    close();
                    return -1;
                }
                throw new IOException("TLS Alert received: level=" + recData[0] + " desc=" + recData[1]);
            }

            if (recType == 0x17) { // Application Data
                byte[] explicitNonce = Arrays.copyOfRange(recData, 0, 8);
                byte[] cipherWithTag = Arrays.copyOfRange(recData, 8, recLen);

                byte[] nonce = new byte[12];
                System.arraycopy(serverIV, 0, nonce, 0, 4);
                System.arraycopy(explicitNonce, 0, nonce, 4, 8);

                int plainLen = cipherWithTag.length - 16;
                byte[] aad = new byte[13];
                PureGcm.putLong(serverSeq, aad, 0);
                aad[8] = 0x17;
                aad[9] = 0x03;
                aad[10] = 0x03;
                aad[11] = (byte) (plainLen >> 8);
                aad[12] = (byte) plainLen;

                byte[] plain = serverGcm.decrypt(nonce, cipherWithTag, aad);
                serverSeq++;

                inBuf = plain;
                inBufPos = 0;

                int toCopy = Math.min(plain.length, maxLen);
                System.arraycopy(plain, 0, buf, offset, toCopy);
                inBufPos += toCopy;
                return toCopy;
            }
        }
    }

    @Override
    public synchronized void close() throws IOException {
        if (closed) return;
        closed = true;
        try {
            socket.close();
        } catch (Exception ignored) {}
    }

    public static PureTlsSocket connect(String host, int port, int timeoutMs, X509TrustManager trustManager) throws IOException {
        try {
            return doConnect(host, port, timeoutMs, trustManager);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            throw new IOException("TLS handshake failed: " + e.getMessage(), e);
        }
    }

    private static PureTlsSocket doConnect(String host, int port, int timeoutMs, X509TrustManager trustManager) throws Exception {
        Socket socket = new Socket();
        socket.connect(new InetSocketAddress(host, port), timeoutMs);
        socket.setSoTimeout(timeoutMs);

        OutputStream out = socket.getOutputStream();
        InputStream in = socket.getInputStream();

        SecureRandom rand = new SecureRandom();
        byte[] clientRandom = new byte[32];
        rand.nextBytes(clientRandom);
        int gmt = (int) (System.currentTimeMillis() / 1000L);
        clientRandom[0] = (byte) (gmt >> 24);
        clientRandom[1] = (byte) (gmt >> 16);
        clientRandom[2] = (byte) (gmt >> 8);
        clientRandom[3] = (byte) (gmt);

        // ClientHello
        ByteArrayOutputStream ch = new ByteArrayOutputStream();
        ch.write(new byte[] { 0x03, 0x03 });
        ch.write(clientRandom);
        ch.write(0x00); // Session ID len

        // Cipher suites: ECDHE-RSA-AES128-GCM-SHA256 (0xc02f), ECDHE-ECDSA-AES128-GCM-SHA256 (0xc02b)
        ch.write(new byte[] { 0x00, 0x04, (byte) 0xc0, 0x2f, (byte) 0xc0, 0x2b });
        ch.write(new byte[] { 0x01, 0x00 }); // Compression: null

        ByteArrayOutputStream ext = new ByteArrayOutputStream();

        // 1. SNI
        byte[] hostBytes = host.getBytes("US-ASCII");
        int serverNameListLen = hostBytes.length + 3;
        int sniExtLen = serverNameListLen + 2;
        ext.write(new byte[] { 0x00, 0x00 });
        ext.write(new byte[] { (byte) (sniExtLen >> 8), (byte) sniExtLen });
        ext.write(new byte[] { (byte) (serverNameListLen >> 8), (byte) serverNameListLen });
        ext.write(0x00);
        ext.write(new byte[] { (byte) (hostBytes.length >> 8), (byte) hostBytes.length });
        ext.write(hostBytes);

        // 2. Supported Groups (secp256r1)
        ext.write(new byte[] { 0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17 });

        // 3. EC Point Formats (uncompressed)
        ext.write(new byte[] { 0x00, 0x0b, 0x00, 0x02, 0x01, 0x00 });

        // 4. Signature Algorithms (RSA+SHA256, ECDSA+SHA256)
        ext.write(new byte[] { 0x00, 0x0d, 0x00, 0x06, 0x00, 0x04, 0x04, 0x01, 0x04, 0x03 });

        byte[] extBytes = ext.toByteArray();
        ch.write((extBytes.length >> 8) & 0xff);
        ch.write(extBytes.length & 0xff);
        ch.write(extBytes);

        byte[] chBody = ch.toByteArray();
        ByteArrayOutputStream handshakeBuf = new ByteArrayOutputStream();
        handshakeBuf.write(0x01);
        handshakeBuf.write((chBody.length >> 16) & 0xff);
        handshakeBuf.write((chBody.length >> 8) & 0xff);
        handshakeBuf.write(chBody.length & 0xff);
        handshakeBuf.write(chBody);
        byte[] chMsg = handshakeBuf.toByteArray();

        ByteArrayOutputStream rec = new ByteArrayOutputStream();
        rec.write(new byte[] { 0x16, 0x03, 0x03 });
        rec.write((chMsg.length >> 8) & 0xff);
        rec.write(chMsg.length & 0xff);
        rec.write(chMsg);

        out.write(rec.toByteArray());
        out.flush();

        MessageDigest handshakeHash = MessageDigest.getInstance("SHA-256");
        handshakeHash.update(chMsg);

        byte[] serverRandom = null;
        Point serverEcPub = null;
        List<X509Certificate> serverCertList = new ArrayList<X509Certificate>();

        DataInputStream dis = new DataInputStream(in);
        boolean readingHandshake = true;
        while (readingHandshake) {
            int recType = dis.readUnsignedByte();
            int maj = dis.readUnsignedByte();
            int min = dis.readUnsignedByte();
            int recLen = dis.readUnsignedShort();
            byte[] recData = new byte[recLen];
            dis.readFully(recData);

            if (recType == 0x15) {
                throw new IOException("TLS Alert during handshake: level=" + recData[0] + " desc=" + recData[1]);
            }

            if (recType == 0x16) {
                handshakeHash.update(recData);
                int off = 0;
                while (off < recLen) {
                    int hsType = recData[off] & 0xff;
                    int hsLen = ((recData[off + 1] & 0xff) << 16) | ((recData[off + 2] & 0xff) << 8) | (recData[off + 3] & 0xff);
                    off += 4;
                    byte[] hsBody = Arrays.copyOfRange(recData, off, off + hsLen);
                    off += hsLen;

                    if (hsType == 0x02) { // ServerHello
                        serverRandom = Arrays.copyOfRange(hsBody, 2, 34);
                    } else if (hsType == 0x0b) { // Certificate
                        if (trustManager != null) {
                            CertificateFactory cf = CertificateFactory.getInstance("X.509");
                            int certsLen = ((hsBody[0] & 0xff) << 16) | ((hsBody[1] & 0xff) << 8) | (hsBody[2] & 0xff);
                            int cOff = 3;
                            while (cOff < certsLen + 3) {
                                int cLen = ((hsBody[cOff] & 0xff) << 16) | ((hsBody[cOff + 1] & 0xff) << 8) | (hsBody[cOff + 2] & 0xff);
                                cOff += 3;
                                byte[] certDer = Arrays.copyOfRange(hsBody, cOff, cOff + cLen);
                                cOff += cLen;
                                X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(certDer));
                                serverCertList.add(cert);
                            }
                        }
                    } else if (hsType == 0x0c) { // ServerKeyExchange
                        int pointLen = hsBody[3] & 0xff;
                        if (pointLen == 65 && hsBody[4] == 0x04) {
                            byte[] sx = Arrays.copyOfRange(hsBody, 5, 37);
                            byte[] sy = Arrays.copyOfRange(hsBody, 37, 69);
                            serverEcPub = new Point(new BigInteger(1, sx), new BigInteger(1, sy));
                        }
                    } else if (hsType == 0x0e) { // ServerHelloDone
                        readingHandshake = false;
                        break;
                    }
                }
            }
        }

        // Validate Certificate Chain if trustManager provided
        if (trustManager != null && !serverCertList.isEmpty()) {
            X509Certificate[] chain = serverCertList.toArray(new X509Certificate[0]);
            trustManager.checkServerTrusted(chain, "ECDHE_RSA");
        }

        BigInteger clientPriv = new BigInteger(256, rand).mod(P.subtract(BigInteger.ONE)).add(BigInteger.ONE);
        Point clientPub = scalarMult(clientPriv, new Point(GX, GY));
        byte[] cx = toFixed32(clientPub.x);
        byte[] cy = toFixed32(clientPub.y);
        byte[] clientPubBytes = new byte[65];
        clientPubBytes[0] = 0x04;
        System.arraycopy(cx, 0, clientPubBytes, 1, 32);
        System.arraycopy(cy, 0, clientPubBytes, 33, 32);

        Point shared = scalarMult(clientPriv, serverEcPub);
        byte[] preMaster = toFixed32(shared.x);

        byte[] ckePayload = new byte[66];
        ckePayload[0] = 65;
        System.arraycopy(clientPubBytes, 0, ckePayload, 1, 65);
        ByteArrayOutputStream ckeMsg = new ByteArrayOutputStream();
        ckeMsg.write(0x10);
        ckeMsg.write(0x00);
        ckeMsg.write(0x00);
        ckeMsg.write(66);
        ckeMsg.write(ckePayload);
        byte[] ckeMsgBytes = ckeMsg.toByteArray();
        handshakeHash.update(ckeMsgBytes);

        out.write(new byte[] { 0x16, 0x03, 0x03, (byte)(ckeMsgBytes.length >> 8), (byte)ckeMsgBytes.length });
        out.write(ckeMsgBytes);

        // ChangeCipherSpec
        out.write(new byte[] { 0x14, 0x03, 0x03, 0x00, 0x01, 0x01 });

        byte[] seed = new byte[64];
        System.arraycopy(clientRandom, 0, seed, 0, 32);
        System.arraycopy(serverRandom, 0, seed, 32, 32);
        byte[] masterSecret = prfSha256(preMaster, "master secret", seed, 48);

        byte[] keyExpansionSeed = new byte[64];
        System.arraycopy(serverRandom, 0, keyExpansionSeed, 0, 32);
        System.arraycopy(clientRandom, 0, keyExpansionSeed, 32, 32);
        byte[] keyBlock = prfSha256(masterSecret, "key expansion", keyExpansionSeed, 40);

        byte[] clientKey = Arrays.copyOfRange(keyBlock, 0, 16);
        byte[] serverKey = Arrays.copyOfRange(keyBlock, 16, 32);
        byte[] clientIV = Arrays.copyOfRange(keyBlock, 32, 36);
        byte[] serverIV = Arrays.copyOfRange(keyBlock, 36, 40);

        PureGcm clientGcm = new PureGcm(clientKey);
        PureGcm serverGcm = new PureGcm(serverKey);

        byte[] hashSnapshot = handshakeHash.digest();
        byte[] verifyData = prfSha256(masterSecret, "client finished", hashSnapshot, 12);
        byte[] finMsg = new byte[16];
        finMsg[0] = 0x14;
        finMsg[1] = 0x00;
        finMsg[2] = 0x00;
        finMsg[3] = 0x0c;
        System.arraycopy(verifyData, 0, finMsg, 4, 12);

        byte[] explicitNonce = new byte[8];
        byte[] nonce = new byte[12];
        System.arraycopy(clientIV, 0, nonce, 0, 4);
        System.arraycopy(explicitNonce, 0, nonce, 4, 8);

        byte[] aad = new byte[] {
            0, 0, 0, 0, 0, 0, 0, 0,
            0x16, 0x03, 0x03, 0x00, 16
        };

        byte[] cipherFin = clientGcm.encrypt(nonce, finMsg, aad);
        int totalFinRecLen = explicitNonce.length + cipherFin.length;
        out.write(new byte[] { 0x16, 0x03, 0x03, (byte)(totalFinRecLen >> 8), (byte)totalFinRecLen });
        out.write(explicitNonce);
        out.write(cipherFin);
        out.flush();

        // Read Server ChangeCipherSpec
        int sCcsType = dis.readUnsignedByte();
        int ccsMaj = dis.readUnsignedByte();
        int ccsMin = dis.readUnsignedByte();
        int sCcsLen = dis.readUnsignedShort();
        byte[] sCcsData = new byte[sCcsLen];
        dis.readFully(sCcsData);

        // Read Server Finished
        int sFinType = dis.readUnsignedByte();
        int finMaj = dis.readUnsignedByte();
        int finMin = dis.readUnsignedByte();
        int sFinLen = dis.readUnsignedShort();
        byte[] sFinData = new byte[sFinLen];
        dis.readFully(sFinData);

        byte[] sExplicitNonce = Arrays.copyOfRange(sFinData, 0, 8);
        byte[] sCipher = Arrays.copyOfRange(sFinData, 8, sFinLen);
        byte[] sNonce = new byte[12];
        System.arraycopy(serverIV, 0, sNonce, 0, 4);
        System.arraycopy(sExplicitNonce, 0, sNonce, 4, 8);

        byte[] sAad = new byte[] {
            0, 0, 0, 0, 0, 0, 0, 0,
            0x16, 0x03, 0x03, (byte)((sFinLen - 8 - 16) >> 8), (byte)(sFinLen - 8 - 16)
        };
        serverGcm.decrypt(sNonce, sCipher, sAad);

        return new PureTlsSocket(socket, clientGcm, serverGcm, clientIV, serverIV, dis, out);
    }
}
