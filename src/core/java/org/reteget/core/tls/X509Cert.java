package org.reteget.core.tls;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * An X.509 v3 certificate parsed by this package (RFC 5280), independent of the
 * platform's certificate classes. Keeps the exact TBSCertificate bytes for signature
 * checks and the raw issuer/subject Name encodings for chaining.
 */
public final class X509Cert {

    static final String OID_BASIC_CONSTRAINTS = "2.5.29.19";
    static final String OID_KEY_USAGE = "2.5.29.15";
    static final String OID_EXT_KEY_USAGE = "2.5.29.37";
    static final String OID_SUBJECT_ALT_NAME = "2.5.29.17";
    static final String OID_NAME_CONSTRAINTS = "2.5.29.30";
    static final String OID_POLICY_CONSTRAINTS = "2.5.29.36";
    static final String OID_INHIBIT_ANY_POLICY = "2.5.29.54";
    static final String OID_CERTIFICATE_POLICIES = "2.5.29.32";
    static final String OID_AUTHORITY_KEY_ID = "2.5.29.35";
    static final String OID_SUBJECT_KEY_ID = "2.5.29.14";
    static final String OID_EKU_SERVER_AUTH = "1.3.6.1.5.5.7.3.1";
    static final String OID_EKU_ANY = "2.5.29.37.0";

    static final int KU_DIGITAL_SIGNATURE = 1;
    static final int KU_KEY_CERT_SIGN = 1 << 5;

    public static final int MAX_SIZE = 64 * 1024;

    public final byte[] der;
    final byte[] tbs;
    final String signatureAlgorithm;
    final byte[] signature;
    public final byte[] issuer;
    public final byte[] subject;
    public final long notBefore, notAfter;
    public final PublicKeyInfo publicKey;

    boolean isCa;
    int pathLen = -1;
    /** Key usage bit mask, or -1 when the extension is absent. */
    int keyUsage = -1;
    /** Extended key usage OIDs, or null when the extension is absent. */
    List<String> extKeyUsage;
    final List<String> dnsNames = new ArrayList<String>();
    final List<byte[]> ipAddresses = new ArrayList<byte[]>();
    /** Constraints this validator does not implement; a path containing them is refused. */
    boolean hasUnsupportedConstraint;
    String unknownCriticalExtension;

    private X509Cert(byte[] der) {
        if (der.length > MAX_SIZE) throw new IllegalArgumentException("certificate too large");
        this.der = der;
        DerCursor outer = new DerCursor(der);
        DerCursor cert = outer.readConstructed(DerCursor.SEQUENCE);
        if (outer.hasRemaining()) throw new IllegalArgumentException("trailing data after certificate");
        tbs = cert.readRaw(DerCursor.SEQUENCE);
        DerCursor sigAlg = cert.readConstructed(DerCursor.SEQUENCE);
        signatureAlgorithm = sigAlg.readOid();
        byte[] outerParams = sigAlg.hasRemaining() ? sigAlg.readRaw(sigAlg.peekTag()) : null;
        signature = cert.readBitStringBytes();
        if (cert.hasRemaining()) throw new IllegalArgumentException("trailing data in certificate");

        DerCursor t = new DerCursor(tbs).readConstructed(DerCursor.SEQUENCE);
        int version = 1;
        if (t.peekTag() == 0xa0) {
            DerCursor v = t.readConstructed(0xa0);
            version = v.readInteger().intValue() + 1;
        }
        t.readInteger(); // serial
        DerCursor innerAlg = t.readConstructed(DerCursor.SEQUENCE);
        String innerOid = innerAlg.readOid();
        byte[] innerParams = innerAlg.hasRemaining() ? innerAlg.readRaw(innerAlg.peekTag()) : null;
        if (!innerOid.equals(signatureAlgorithm) || !Arrays.equals(innerParams, outerParams)) {
            throw new IllegalArgumentException("inner and outer signature algorithms differ");
        }
        issuer = t.readRaw(DerCursor.SEQUENCE);
        DerCursor validity = t.readConstructed(DerCursor.SEQUENCE);
        notBefore = validity.readTime();
        notAfter = validity.readTime();
        subject = t.readRaw(DerCursor.SEQUENCE);
        publicKey = PublicKeyInfo.parse(t.readConstructed(DerCursor.SEQUENCE));
        while (t.peekTag() == 0x81 || t.peekTag() == 0x82) {
            t.skip(); // issuer/subject unique IDs
        }
        if (t.peekTag() == 0xa3) {
            if (version != 3) throw new IllegalArgumentException("extensions in a non-v3 certificate");
            parseExtensions(t.readConstructed(0xa3).readConstructed(DerCursor.SEQUENCE));
        }
        if (t.hasRemaining()) throw new IllegalArgumentException("trailing data in TBSCertificate");
    }

    public static X509Cert parse(byte[] der) {
        return new X509Cert(der);
    }

    private void parseExtensions(DerCursor exts) {
        List<String> seen = new ArrayList<String>();
        while (exts.hasRemaining()) {
            DerCursor ext = exts.readConstructed(DerCursor.SEQUENCE);
            String oid = ext.readOid();
            if (seen.contains(oid)) throw new IllegalArgumentException("duplicate extension " + oid);
            seen.add(oid);
            boolean critical = ext.peekTag() == DerCursor.BOOLEAN && ext.readBoolean();
            byte[] value = ext.readContent(DerCursor.OCTET_STRING);
            DerCursor v = new DerCursor(value);
            if (OID_BASIC_CONSTRAINTS.equals(oid)) {
                DerCursor bc = v.readConstructed(DerCursor.SEQUENCE);
                if (bc.peekTag() == DerCursor.BOOLEAN) isCa = bc.readBoolean();
                if (bc.peekTag() == DerCursor.INTEGER) {
                    BigInteger p = bc.readPositiveInteger();
                    pathLen = p.bitLength() > 16 ? Integer.MAX_VALUE : p.intValue();
                }
            } else if (OID_KEY_USAGE.equals(oid)) {
                keyUsage = v.readNamedBits();
            } else if (OID_EXT_KEY_USAGE.equals(oid)) {
                extKeyUsage = new ArrayList<String>();
                DerCursor list = v.readConstructed(DerCursor.SEQUENCE);
                while (list.hasRemaining()) extKeyUsage.add(list.readOid());
            } else if (OID_SUBJECT_ALT_NAME.equals(oid)) {
                DerCursor names = v.readConstructed(DerCursor.SEQUENCE);
                while (names.hasRemaining()) {
                    int tag = names.peekTag();
                    if (tag == 0x82) {
                        byte[] name = names.readContent(0x82);
                        char[] c = new char[name.length];
                        for (int i = 0; i < name.length; i++) {
                            if (name[i] < 0x20 || name[i] > 0x7e) throw new IllegalArgumentException("bad dNSName");
                            c[i] = (char) name[i];
                        }
                        dnsNames.add(new String(c));
                    } else if (tag == 0x87) {
                        ipAddresses.add(names.readContent(0x87));
                    } else {
                        names.skip();
                    }
                }
            } else if (OID_NAME_CONSTRAINTS.equals(oid) || OID_POLICY_CONSTRAINTS.equals(oid)
                    || OID_INHIBIT_ANY_POLICY.equals(oid)) {
                hasUnsupportedConstraint = true;
                continue;
            } else if (!OID_CERTIFICATE_POLICIES.equals(oid) && !OID_AUTHORITY_KEY_ID.equals(oid)
                    && !OID_SUBJECT_KEY_ID.equals(oid) && critical && unknownCriticalExtension == null) {
                unknownCriticalExtension = oid;
            }
            if (v.hasRemaining()) {
                // Only checked for extensions decoded above; others were not parsed.
                if (OID_BASIC_CONSTRAINTS.equals(oid) || OID_KEY_USAGE.equals(oid)
                        || OID_EXT_KEY_USAGE.equals(oid) || OID_SUBJECT_ALT_NAME.equals(oid)) {
                    throw new IllegalArgumentException("trailing data in extension " + oid);
                }
            }
        }
    }

    /** True when this certificate's signature verifies under {@code issuerKey}. */
    boolean isSignedBy(PublicKeyInfo issuerKey) {
        try {
            String hash;
            boolean ecdsa;
            if ("1.2.840.113549.1.1.11".equals(signatureAlgorithm)) {
                hash = "SHA-256";
                ecdsa = false;
            } else if ("1.2.840.113549.1.1.12".equals(signatureAlgorithm)) {
                hash = "SHA-384";
                ecdsa = false;
            } else if ("1.2.840.113549.1.1.13".equals(signatureAlgorithm)) {
                hash = "SHA-512";
                ecdsa = false;
            } else if ("1.2.840.10045.4.3.2".equals(signatureAlgorithm)) {
                hash = "SHA-256";
                ecdsa = true;
            } else if ("1.2.840.10045.4.3.3".equals(signatureAlgorithm)) {
                hash = "SHA-384";
                ecdsa = true;
            } else if ("1.2.840.10045.4.3.4".equals(signatureAlgorithm)) {
                hash = "SHA-512";
                ecdsa = true;
            } else {
                return false; // SHA-1, MD5 and RSASSA-PSS certificates are not accepted
            }
            if (ecdsa) {
                if (!issuerKey.isEc()) return false;
                byte[] digest = MessageDigest.getInstance(hash).digest(tbs);
                return issuerKey.curve.verifyDer(issuerKey.point, digest, signature);
            }
            if (!issuerKey.isRsa()) return false;
            return RsaVerifier.verifyPkcs1(issuerKey.modulus, issuerKey.exponent, hash, tbs, signature);
        } catch (Exception e) {
            return false;
        }
    }

    boolean sameCertificate(X509Cert other) {
        return Arrays.equals(der, other.der);
    }
}
