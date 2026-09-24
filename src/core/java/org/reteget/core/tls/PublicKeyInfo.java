package org.reteget.core.tls;

import java.math.BigInteger;

/**
 * A server public key parsed from SubjectPublicKeyInfo DER by this package itself.
 *
 * Android 2.3's certificate classes cannot represent EC keys (getPublicKey() returns an
 * object whose algorithm is just the OID), so the TLS engine never relies on
 * java.security.PublicKey for signature checks.
 */
public final class PublicKeyInfo {

    static final String OID_RSA = "1.2.840.113549.1.1.1";
    static final String OID_EC = "1.2.840.10045.2.1";
    static final String OID_P256 = "1.2.840.10045.3.1.7";
    static final String OID_P384 = "1.3.132.0.34";

    /** RSA modulus and exponent, or null for EC. */
    public final BigInteger modulus, exponent;
    /** EC curve and point, or null for RSA. */
    public final EcCurve curve;
    public final EcCurve.Point point;

    private PublicKeyInfo(BigInteger n, BigInteger e, EcCurve curve, EcCurve.Point point) {
        this.modulus = n;
        this.exponent = e;
        this.curve = curve;
        this.point = point;
    }

    public boolean isRsa() {
        return modulus != null;
    }

    public boolean isEc() {
        return curve != null;
    }

    /** Parses SubjectPublicKeyInfo; throws IllegalArgumentException for malformed or unsupported keys. */
    public static PublicKeyInfo parse(byte[] spki) {
        DerCursor outer = new DerCursor(spki);
        DerCursor seq = outer.readConstructed(DerCursor.SEQUENCE);
        if (outer.hasRemaining()) throw new IllegalArgumentException("trailing data after SPKI");
        PublicKeyInfo k = parse(seq);
        if (seq.hasRemaining()) throw new IllegalArgumentException("trailing data in SPKI");
        return k;
    }

    /** Parses the contents of a SubjectPublicKeyInfo SEQUENCE. */
    static PublicKeyInfo parse(DerCursor seq) {
        DerCursor alg = seq.readConstructed(DerCursor.SEQUENCE);
        String oid = alg.readOid();
        byte[] key = seq.readBitStringBytes();
        if (OID_RSA.equals(oid)) {
            if (alg.hasRemaining()) {
                alg.readContent(DerCursor.NULL);
            }
            DerCursor rsaOuter = new DerCursor(key);
            DerCursor rsa = rsaOuter.readConstructed(DerCursor.SEQUENCE);
            BigInteger n = rsa.readPositiveInteger();
            BigInteger e = rsa.readPositiveInteger();
            if (rsa.hasRemaining() || rsaOuter.hasRemaining()) throw new IllegalArgumentException("bad RSA key");
            return new PublicKeyInfo(n, e, null, null);
        }
        if (OID_EC.equals(oid)) {
            String curveOid = alg.readOid();
            EcCurve curve = OID_P256.equals(curveOid) ? EcCurve.P256 : OID_P384.equals(curveOid) ? EcCurve.P384 : null;
            if (curve == null) throw new IllegalArgumentException("unsupported EC curve " + curveOid);
            return new PublicKeyInfo(null, null, curve, curve.decodePoint(key));
        }
        throw new IllegalArgumentException("unsupported public key algorithm " + oid);
    }
}
