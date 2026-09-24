package org.reteget.core.tls;

import java.math.BigInteger;

/**
 * Short-Weierstrass prime curves (y^2 = x^3 - 3x + b) used by TLS: secp256r1 and secp384r1.
 *
 * Provides SEC1 point decoding with full validation, ECDSA verification (FIPS 186-5) and
 * P-256 ECDH. Arithmetic uses Jacobian coordinates over BigInteger. That is adequate for
 * public-value work (signature verification); for the ECDH secret scalar it is not
 * constant-time, which is why X25519 is the preferred key share and P-256 is only sent
 * when a server asks for it with HelloRetryRequest.
 */
public final class EcCurve {

    public static final EcCurve P256 = new EcCurve("secp256r1", 32,
            "ffffffff00000001000000000000000000000000ffffffffffffffffffffffff",
            "5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b",
            "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296",
            "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5",
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");

    public static final EcCurve P384 = new EcCurve("secp384r1", 48,
            "fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffeffffffff0000000000000000ffffffff",
            "b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef",
            "aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab7",
            "3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f",
            "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973");

    public final String name;
    public final int fieldLen;
    final BigInteger p, b, n;
    final Point g;

    private static final BigInteger THREE = BigInteger.valueOf(3);

    private EcCurve(String name, int fieldLen, String p, String b, String gx, String gy, String n) {
        this.name = name;
        this.fieldLen = fieldLen;
        this.p = new BigInteger(p, 16);
        this.b = new BigInteger(b, 16);
        this.n = new BigInteger(n, 16);
        this.g = new Point(new BigInteger(gx, 16), new BigInteger(gy, 16));
    }

    /** Affine point; the point at infinity is represented by null. */
    public static final class Point {
        public final BigInteger x, y;

        Point(BigInteger x, BigInteger y) {
            this.x = x;
            this.y = y;
        }
    }

    public static EcCurve forFieldPrime(BigInteger prime) {
        if (P256.p.equals(prime)) return P256;
        if (P384.p.equals(prime)) return P384;
        return null;
    }

    public boolean isOnCurve(Point q) {
        if (q == null) return false;
        if (q.x.signum() < 0 || q.x.compareTo(p) >= 0 || q.y.signum() < 0 || q.y.compareTo(p) >= 0) {
            return false;
        }
        BigInteger lhs = q.y.multiply(q.y).mod(p);
        BigInteger rhs = q.x.multiply(q.x).multiply(q.x).subtract(q.x.multiply(THREE)).add(b).mod(p);
        return lhs.equals(rhs);
    }

    /** Decodes an uncompressed SEC1 point (0x04 || X || Y) and validates it. Cofactor is 1. */
    public Point decodePoint(byte[] enc) {
        if (enc == null || enc.length != 1 + 2 * fieldLen || enc[0] != 0x04) {
            throw new IllegalArgumentException("unsupported or malformed EC point");
        }
        BigInteger x = new BigInteger(1, java.util.Arrays.copyOfRange(enc, 1, 1 + fieldLen));
        BigInteger y = new BigInteger(1, java.util.Arrays.copyOfRange(enc, 1 + fieldLen, enc.length));
        Point q = new Point(x, y);
        if (!isOnCurve(q)) {
            throw new IllegalArgumentException("EC point is not on " + name);
        }
        return q;
    }

    public byte[] encodePoint(Point q) {
        byte[] out = new byte[1 + 2 * fieldLen];
        out[0] = 0x04;
        fixed(q.x, out, 1, fieldLen);
        fixed(q.y, out, 1 + fieldLen, fieldLen);
        return out;
    }

    public Point multiplyBase(BigInteger k) {
        return multiply(k, g);
    }

    /** Returns a uniformly random scalar in [1, n-1] by rejection sampling. */
    public BigInteger randomScalar() {
        byte[] buf = new byte[fieldLen];
        while (true) {
            TlsRandom.nextBytes(buf);
            BigInteger k = new BigInteger(1, buf);
            if (k.signum() > 0 && k.compareTo(n) < 0) {
                java.util.Arrays.fill(buf, (byte) 0);
                return k;
            }
        }
    }

    /** ECDH shared secret: the x-coordinate of k*Q, left-padded to the field length. */
    public byte[] ecdh(BigInteger k, Point peer) {
        if (!isOnCurve(peer)) {
            throw new IllegalArgumentException("peer EC point is invalid");
        }
        Point s = multiply(k, peer);
        if (s == null) {
            throw new IllegalArgumentException("ECDH result is the point at infinity");
        }
        byte[] out = new byte[fieldLen];
        fixed(s.x, out, 0, fieldLen);
        return out;
    }

    /**
     * Verifies an ECDSA signature. {@code digest} is the message hash; it is truncated to
     * the bit length of n as FIPS 186-5 requires. {@code r} and {@code s} are the decoded
     * signature integers.
     */
    public boolean verify(Point q, byte[] digest, BigInteger r, BigInteger s) {
        if (!isOnCurve(q)) return false;
        if (r.signum() <= 0 || s.signum() <= 0 || r.compareTo(n) >= 0 || s.compareTo(n) >= 0) {
            return false;
        }
        BigInteger e = new BigInteger(1, digest);
        int excess = digest.length * 8 - n.bitLength();
        if (excess > 0) {
            e = e.shiftRight(excess);
        }
        BigInteger w = s.modInverse(n);
        BigInteger u1 = e.multiply(w).mod(n);
        BigInteger u2 = r.multiply(w).mod(n);
        Point x = add(multiply(u1, g), multiply(u2, q));
        if (x == null) return false;
        return x.x.mod(n).equals(r);
    }

    /** Parses a DER ECDSA-Sig-Value (SEQUENCE { INTEGER r, INTEGER s }) and verifies it. */
    public boolean verifyDer(Point q, byte[] digest, byte[] der) {
        BigInteger[] rs;
        try {
            rs = parseDerSignature(der);
        } catch (RuntimeException e) {
            return false;
        }
        return verify(q, digest, rs[0], rs[1]);
    }

    static BigInteger[] parseDerSignature(byte[] der) {
        DerCursor c = new DerCursor(der);
        DerCursor seq = c.readConstructed(0x30);
        if (c.remaining() != 0) throw new IllegalArgumentException("trailing data after signature");
        BigInteger r = seq.readPositiveInteger();
        BigInteger s = seq.readPositiveInteger();
        if (seq.remaining() != 0) throw new IllegalArgumentException("trailing data in signature");
        return new BigInteger[] { r, s };
    }

    // --- Jacobian arithmetic (X, Y, Z) with x = X/Z^2, y = Y/Z^3 ---

    Point multiply(BigInteger k, Point q) {
        if (q == null || k.signum() == 0) return null;
        BigInteger[] r = null;
        BigInteger[] base = { q.x, q.y, BigInteger.ONE };
        for (int i = k.bitLength() - 1; i >= 0; i--) {
            r = jDouble(r);
            if (k.testBit(i)) {
                r = jAdd(r, base);
            }
        }
        return toAffine(r);
    }

    Point add(Point a, Point b2) {
        if (a == null) return b2;
        if (b2 == null) return a;
        return toAffine(jAdd(new BigInteger[] { a.x, a.y, BigInteger.ONE },
                new BigInteger[] { b2.x, b2.y, BigInteger.ONE }));
    }

    private Point toAffine(BigInteger[] j) {
        if (j == null || j[2].signum() == 0) return null;
        BigInteger zi = j[2].modInverse(p);
        BigInteger zi2 = zi.multiply(zi).mod(p);
        BigInteger x = j[0].multiply(zi2).mod(p);
        BigInteger y = j[1].multiply(zi2).multiply(zi).mod(p);
        return new Point(x, y);
    }

    /** dbl-2001-b for a = -3. */
    private BigInteger[] jDouble(BigInteger[] P1) {
        if (P1 == null || P1[1].signum() == 0) return null;
        BigInteger x = P1[0], y = P1[1], z = P1[2];
        BigInteger delta = z.multiply(z).mod(p);
        BigInteger gamma = y.multiply(y).mod(p);
        BigInteger beta = x.multiply(gamma).mod(p);
        BigInteger alpha = THREE.multiply(x.subtract(delta)).multiply(x.add(delta)).mod(p);
        BigInteger x3 = alpha.multiply(alpha).subtract(beta.shiftLeft(3)).mod(p);
        BigInteger z3 = y.add(z).pow(2).subtract(gamma).subtract(delta).mod(p);
        BigInteger y3 = alpha.multiply(beta.shiftLeft(2).subtract(x3))
                .subtract(gamma.multiply(gamma).shiftLeft(3)).mod(p);
        return new BigInteger[] { x3, y3, z3 };
    }

    /** add-2007-bl, with the equal-point and inverse-point cases handled explicitly. */
    private BigInteger[] jAdd(BigInteger[] P1, BigInteger[] P2) {
        if (P1 == null) return P2;
        if (P2 == null) return P1;
        BigInteger z1z1 = P1[2].multiply(P1[2]).mod(p);
        BigInteger z2z2 = P2[2].multiply(P2[2]).mod(p);
        BigInteger u1 = P1[0].multiply(z2z2).mod(p);
        BigInteger u2 = P2[0].multiply(z1z1).mod(p);
        BigInteger s1 = P1[1].multiply(P2[2]).multiply(z2z2).mod(p);
        BigInteger s2 = P2[1].multiply(P1[2]).multiply(z1z1).mod(p);
        BigInteger h = u2.subtract(u1).mod(p);
        BigInteger rr = s2.subtract(s1).mod(p);
        if (h.signum() == 0) {
            if (rr.signum() == 0) return jDouble(P1);
            return null;
        }
        BigInteger i = h.shiftLeft(1).pow(2).mod(p);
        BigInteger j = h.multiply(i).mod(p);
        BigInteger r = rr.shiftLeft(1);
        BigInteger v = u1.multiply(i).mod(p);
        BigInteger x3 = r.multiply(r).subtract(j).subtract(v.shiftLeft(1)).mod(p);
        BigInteger y3 = r.multiply(v.subtract(x3)).subtract(s1.multiply(j).shiftLeft(1)).mod(p);
        BigInteger z3 = P1[2].add(P2[2]).pow(2).subtract(z1z1).subtract(z2z2).multiply(h).mod(p);
        return new BigInteger[] { x3, y3, z3 };
    }

    static void fixed(BigInteger v, byte[] out, int off, int len) {
        byte[] raw = v.toByteArray();
        int start = 0;
        while (start < raw.length - 1 && raw[start] == 0) start++;
        int n = raw.length - start;
        if (n > len) throw new IllegalArgumentException("integer too large for field");
        java.util.Arrays.fill(out, off, off + len - n, (byte) 0);
        System.arraycopy(raw, start, out, off + len - n, n);
    }
}
