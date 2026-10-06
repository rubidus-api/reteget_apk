package org.reteget.core.ssh;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Arrays;
import org.reteget.core.tls.EcCurve;
import org.reteget.core.tls.RsaVerifier;

/**
 * A server's public host key as it arrives in the key exchange: ssh-ed25519 (RFC 8709),
 * ecdsa-sha2-nistp256 (RFC 5656) or ssh-rsa used with rsa-sha2-256/512 signatures (RFC 8332).
 * SHA-1 signatures ("ssh-rsa" as a signature algorithm) and DSA are not accepted.
 */
public final class SshHostKey {

    public static final String ED25519 = "ssh-ed25519";
    public static final String ECDSA_P256 = "ecdsa-sha2-nistp256";
    public static final String RSA = "ssh-rsa";
    public static final String RSA_SHA2_256 = "rsa-sha2-256";
    public static final String RSA_SHA2_512 = "rsa-sha2-512";

    /** The key type: {@link #ED25519}, {@link #ECDSA_P256} or {@link #RSA}. */
    public final String type;
    private final byte[] blob;

    private byte[] edKey;
    private EcCurve.Point ecPoint;
    private BigInteger rsaE, rsaN;

    private SshHostKey(String type, byte[] blob) {
        this.type = type;
        this.blob = blob.clone();
    }

    /** Parses a public key blob; an SshException for an unsupported or malformed key. */
    public static SshHostKey parse(byte[] blob) throws IOException {
        SshBuf.Reader r = new SshBuf.Reader(blob);
        String type = r.text();
        SshHostKey k = new SshHostKey(type, blob);
        try {
            if (ED25519.equals(type)) {
                k.edKey = r.string();
                if (k.edKey.length != Ed25519.PUBLIC_KEY_LEN) throw new SshException("malformed ssh-ed25519 host key");
            } else if (ECDSA_P256.equals(type)) {
                if (!"nistp256".equals(r.text())) throw new SshException("malformed ecdsa host key");
                k.ecPoint = EcCurve.P256.decodePoint(r.string());
            } else if (RSA.equals(type)) {
                k.rsaE = r.mpint();
                k.rsaN = r.mpint();
                if (k.rsaN.bitLength() < RsaVerifier.MIN_BITS) {
                    throw new SshException("RSA host key of " + k.rsaN.bitLength() + " bits is too short (2048 needed)");
                }
            } else {
                throw new SshException("unsupported host key type " + printable(type));
            }
        } catch (IllegalArgumentException e) {
            throw new SshException("malformed " + type + " host key");
        }
        if (r.remaining() != 0) throw new SshException("malformed " + type + " host key");
        return k;
    }

    public byte[] blob() {
        return blob.clone();
    }

    /** The fingerprint as OpenSSH prints it: "SHA256:" and the unpadded base64 of the blob's SHA-256. */
    public String fingerprint() {
        return fingerprint(blob);
    }

    public static String fingerprint(byte[] keyBlob) {
        try {
            return "SHA256:" + SshBase64.encode(MessageDigest.getInstance("SHA-256").digest(keyBlob), false);
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** The key type for a negotiated host key algorithm name. */
    static String keyTypeOf(String algorithm) {
        return RSA_SHA2_256.equals(algorithm) || RSA_SHA2_512.equals(algorithm) ? RSA : algorithm;
    }

    /**
     * Verifies the signature blob over {@code data} made with the negotiated host key
     * {@code algorithm}. False for a bad signature or one made with another algorithm.
     */
    public boolean verify(String algorithm, byte[] data, byte[] signatureBlob) throws IOException {
        if (!type.equals(keyTypeOf(algorithm)) || RSA.equals(algorithm)) return false;
        SshBuf.Reader r = new SshBuf.Reader(signatureBlob);
        String sigAlg = r.text();
        byte[] sig = r.string();
        if (r.remaining() != 0 || !algorithm.equals(sigAlg)) return false;
        try {
            if (ED25519.equals(algorithm)) {
                return Ed25519.verify(edKey, data, sig);
            }
            if (ECDSA_P256.equals(algorithm)) {
                SshBuf.Reader s = new SshBuf.Reader(sig);
                BigInteger rr = s.mpint();
                BigInteger ss = s.mpint();
                if (s.remaining() != 0) return false;
                return EcCurve.P256.verify(ecPoint, MessageDigest.getInstance("SHA-256").digest(data), rr, ss);
            }
            int k = (rsaN.bitLength() + 7) / 8;
            if (sig.length > k) return false;
            if (sig.length < k) { // RFC 8332: some servers drop leading zero bytes
                byte[] padded = new byte[k];
                System.arraycopy(sig, 0, padded, k - sig.length, sig.length);
                sig = padded;
            }
            return RsaVerifier.verifyPkcs1(rsaN, rsaE, RSA_SHA2_512.equals(algorithm) ? "SHA-512" : "SHA-256", data, sig);
        } catch (IOException e) {
            throw e;
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    public boolean equals(Object o) {
        return o instanceof SshHostKey && Arrays.equals(blob, ((SshHostKey) o).blob);
    }

    @Override
    public int hashCode() {
        return Arrays.hashCode(blob);
    }

    /** Text from the peer made safe to show: printable ASCII only, at most 100 characters. */
    static String printable(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length() && sb.length() < 100; i++) {
            char c = s.charAt(i);
            sb.append(c >= 0x20 && c < 0x7f ? c : '?');
        }
        return sb.toString();
    }
}
