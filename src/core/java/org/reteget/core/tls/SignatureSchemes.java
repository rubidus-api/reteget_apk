package org.reteget.core.tls;

import java.security.MessageDigest;
import java.security.PublicKey;

/**
 * TLS SignatureScheme code points (RFC 8446 section 4.2.3) and verification of a
 * handshake signature against the server certificate's public key.
 */
public final class SignatureSchemes {

    public static final int RSA_PKCS1_SHA256 = 0x0401;
    public static final int RSA_PKCS1_SHA384 = 0x0501;
    public static final int RSA_PKCS1_SHA512 = 0x0601;
    public static final int ECDSA_SECP256R1_SHA256 = 0x0403;
    public static final int ECDSA_SECP384R1_SHA384 = 0x0503;
    public static final int RSA_PSS_RSAE_SHA256 = 0x0804;
    public static final int RSA_PSS_RSAE_SHA384 = 0x0805;
    public static final int RSA_PSS_RSAE_SHA512 = 0x0806;

    /** Offered for TLS 1.3 CertificateVerify, in preference order. */
    public static final int[] TLS13_HANDSHAKE = {
        ECDSA_SECP256R1_SHA256, RSA_PSS_RSAE_SHA256, ECDSA_SECP384R1_SHA384,
        RSA_PSS_RSAE_SHA384, RSA_PSS_RSAE_SHA512
    };

    /** Offered for TLS 1.2 ServerKeyExchange. */
    public static final int[] TLS12_HANDSHAKE = {
        ECDSA_SECP256R1_SHA256, RSA_PSS_RSAE_SHA256, RSA_PKCS1_SHA256, ECDSA_SECP384R1_SHA384,
        RSA_PSS_RSAE_SHA384, RSA_PKCS1_SHA384, RSA_PSS_RSAE_SHA512, RSA_PKCS1_SHA512
    };

    /** Accepted inside certificates (the platform trust manager verifies the chain). */
    public static final int[] CERTIFICATES = TLS12_HANDSHAKE;

    private SignatureSchemes() {}

    public static boolean contains(int[] list, int scheme) {
        for (int s : list) {
            if (s == scheme) return true;
        }
        return false;
    }

    public static String name(int scheme) {
        switch (scheme) {
            case RSA_PKCS1_SHA256: return "rsa_pkcs1_sha256";
            case RSA_PKCS1_SHA384: return "rsa_pkcs1_sha384";
            case RSA_PKCS1_SHA512: return "rsa_pkcs1_sha512";
            case ECDSA_SECP256R1_SHA256: return "ecdsa_secp256r1_sha256";
            case ECDSA_SECP384R1_SHA384: return "ecdsa_secp384r1_sha384";
            case RSA_PSS_RSAE_SHA256: return "rsa_pss_rsae_sha256";
            case RSA_PSS_RSAE_SHA384: return "rsa_pss_rsae_sha384";
            case RSA_PSS_RSAE_SHA512: return "rsa_pss_rsae_sha512";
            default: return String.format("0x%04x", scheme);
        }
    }

    static String hashOf(int scheme) {
        switch (scheme & 0xff00) {
            case 0x0400: return "SHA-256";
            case 0x0500: return "SHA-384";
            case 0x0600: return "SHA-512";
            default: break;
        }
        switch (scheme) {
            case RSA_PSS_RSAE_SHA256: return "SHA-256";
            case RSA_PSS_RSAE_SHA384: return "SHA-384";
            case RSA_PSS_RSAE_SHA512: return "SHA-512";
            default: throw new IllegalArgumentException("unsupported signature scheme " + name(scheme));
        }
    }

    /**
     * Verifies {@code signature} over {@code message}.
     *
     * @param tls13 true for TLS 1.3, where an ECDSA scheme also fixes the curve and
     *              PKCS#1 v1.5 is not allowed in handshake signatures.
     */
    public static boolean verify(int scheme, PublicKeyInfo key, byte[] message, byte[] signature,
                                 boolean tls13) throws Exception {
        return verify(scheme, key, message, signature, tls13, RsaVerifier.MIN_BITS);
    }

    /** Convenience for platform keys (tests, desktop): re-parses the key's SPKI encoding. */
    public static boolean verify(int scheme, PublicKey key, byte[] message, byte[] signature,
                                 boolean tls13) throws Exception {
        return verify(scheme, PublicKeyInfo.parse(key.getEncoded()), message, signature, tls13);
    }

    static boolean verify(int scheme, PublicKeyInfo key, byte[] message, byte[] signature,
                          boolean tls13, int rsaMinBits) throws Exception {
        String hash = hashOf(scheme);
        if (scheme == ECDSA_SECP256R1_SHA256 || scheme == ECDSA_SECP384R1_SHA384) {
            if (!key.isEc()) return false;
            if (tls13) {
                EcCurve required = scheme == ECDSA_SECP256R1_SHA256 ? EcCurve.P256 : EcCurve.P384;
                if (key.curve != required) return false;
            }
            byte[] digest = MessageDigest.getInstance(hash).digest(message);
            return key.curve.verifyDer(key.point, digest, signature);
        }
        if (!key.isRsa()) return false;
        if (scheme == RSA_PSS_RSAE_SHA256 || scheme == RSA_PSS_RSAE_SHA384 || scheme == RSA_PSS_RSAE_SHA512) {
            int saltLen = MessageDigest.getInstance(hash).getDigestLength();
            return RsaVerifier.verifyPss(key.modulus, key.exponent, hash, saltLen, message, signature, rsaMinBits);
        }
        if (tls13) return false;
        return RsaVerifier.verifyPkcs1(key.modulus, key.exponent, hash, message, signature, rsaMinBits);
    }
}
