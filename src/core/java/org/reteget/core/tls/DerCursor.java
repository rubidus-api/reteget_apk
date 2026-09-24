package org.reteget.core.tls;

import java.math.BigInteger;
import java.util.Calendar;
import java.util.TimeZone;

/**
 * Strict DER reader for the structures the TLS engine parses itself: X.509 certificates,
 * SubjectPublicKeyInfo, ECDSA signatures and DigestInfo. Definite lengths only, minimal
 * length encodings only, bounded nesting (each cursor is a slice of its parent).
 */
final class DerCursor {

    static final int INTEGER = 0x02;
    static final int BIT_STRING = 0x03;
    static final int OCTET_STRING = 0x04;
    static final int NULL = 0x05;
    static final int OID = 0x06;
    static final int UTC_TIME = 0x17;
    static final int GENERALIZED_TIME = 0x18;
    static final int SEQUENCE = 0x30;
    static final int SET = 0x31;
    static final int BOOLEAN = 0x01;

    final byte[] buf;
    private int pos;
    private final int end;

    DerCursor(byte[] buf) {
        this(buf, 0, buf.length);
    }

    DerCursor(byte[] buf, int start, int end) {
        this.buf = buf;
        this.pos = start;
        this.end = end;
    }

    int remaining() {
        return end - pos;
    }

    boolean hasRemaining() {
        return pos < end;
    }

    int position() {
        return pos;
    }

    /** Tag of the next element without consuming it, or -1 at the end. */
    int peekTag() {
        return pos < end ? buf[pos] & 0xff : -1;
    }

    private int readLength() {
        if (pos >= end) throw new IllegalArgumentException("DER truncated");
        int first = buf[pos++] & 0xff;
        if (first < 0x80) return first;
        int count = first & 0x7f;
        if (count == 0 || count > 3) throw new IllegalArgumentException("DER length form not supported");
        if (end - pos < count) throw new IllegalArgumentException("DER truncated");
        if ((buf[pos] & 0xff) == 0) throw new IllegalArgumentException("DER length not minimal");
        int len = 0;
        for (int i = 0; i < count; i++) {
            len = (len << 8) | (buf[pos++] & 0xff);
        }
        if (len < 0x80) throw new IllegalArgumentException("DER length not minimal");
        return len;
    }

    /**
     * Reads one element with the given tag; returns {headerStart, contentStart, contentLength}.
     * Only single-byte tags occur in the structures parsed here.
     */
    int[] readTlv(int tag) {
        if (pos >= end || (buf[pos] & 0xff) != tag) {
            throw new IllegalArgumentException("DER unexpected tag " + (pos < end ? (buf[pos] & 0xff) : -1)
                    + ", wanted " + tag);
        }
        if ((tag & 0x1f) == 0x1f) throw new IllegalArgumentException("DER multi-byte tag");
        int start = pos;
        pos++;
        int len = readLength();
        if (len > end - pos) throw new IllegalArgumentException("DER length exceeds input");
        int content = pos;
        pos += len;
        return new int[] { start, content, len };
    }

    DerCursor readConstructed(int tag) {
        int[] tl = readTlv(tag);
        return new DerCursor(buf, tl[1], tl[1] + tl[2]);
    }

    /** Reads an element and returns its complete encoding (tag, length and content). */
    byte[] readRaw(int tag) {
        int[] tl = readTlv(tag);
        return copy(tl[0], tl[1] + tl[2]);
    }

    byte[] readContent(int tag) {
        int[] tl = readTlv(tag);
        return copy(tl[1], tl[1] + tl[2]);
    }

    /** Skips any single element. */
    void skip() {
        readTlv(peekTag());
    }

    BigInteger readPositiveInteger() {
        byte[] v = readContent(INTEGER);
        if (v.length == 0) throw new IllegalArgumentException("DER empty integer");
        if ((v[0] & 0x80) != 0) throw new IllegalArgumentException("DER negative integer");
        if (v.length > 1 && v[0] == 0 && (v[1] & 0x80) == 0) {
            throw new IllegalArgumentException("DER integer not minimal");
        }
        return new BigInteger(1, v);
    }

    /** Reads an INTEGER that may be zero or have any sign (certificate serials, version). */
    BigInteger readInteger() {
        byte[] v = readContent(INTEGER);
        if (v.length == 0) throw new IllegalArgumentException("DER empty integer");
        return new BigInteger(v);
    }

    boolean readBoolean() {
        byte[] v = readContent(BOOLEAN);
        if (v.length != 1 || (v[0] != 0 && v[0] != (byte) 0xff)) {
            throw new IllegalArgumentException("DER boolean not canonical");
        }
        return v[0] != 0;
    }

    /** BIT STRING content without the unused-bits byte; requires a whole number of bytes. */
    byte[] readBitStringBytes() {
        byte[] v = readContent(BIT_STRING);
        if (v.length == 0 || v[0] != 0) throw new IllegalArgumentException("DER bit string with unused bits");
        return copyOf(v, 1, v.length);
    }

    /** BIT STRING as a bit mask where bit 0 is the first (most significant) named bit. */
    int readNamedBits() {
        byte[] v = readContent(BIT_STRING);
        if (v.length == 0 || v[0] > 7 || (v.length == 1 && v[0] != 0)) {
            throw new IllegalArgumentException("DER bad named bit string");
        }
        int mask = 0;
        for (int i = 1; i < v.length && i <= 4; i++) {
            for (int b = 0; b < 8; b++) {
                if ((v[i] & (0x80 >>> b)) != 0) mask |= 1 << ((i - 1) * 8 + b);
            }
        }
        return mask;
    }

    String readOid() {
        byte[] v = readContent(OID);
        if (v.length == 0 || (v[v.length - 1] & 0x80) != 0) throw new IllegalArgumentException("DER bad OID");
        StringBuilder sb = new StringBuilder();
        long value = 0;
        boolean first = true;
        for (int i = 0; i < v.length; i++) {
            if (value == 0 && (v[i] & 0xff) == 0x80) throw new IllegalArgumentException("DER OID not minimal");
            value = (value << 7) | (v[i] & 0x7f);
            if (value > (1L << 40)) throw new IllegalArgumentException("DER OID arc too large");
            if ((v[i] & 0x80) == 0) {
                if (first) {
                    int a = value < 40 ? 0 : value < 80 ? 1 : 2;
                    sb.append(a).append('.').append(value - 40L * a);
                    first = false;
                } else {
                    sb.append('.').append(value);
                }
                value = 0;
            }
        }
        return sb.toString();
    }

    /** UTCTime or GeneralizedTime in the X.509 profile (seconds, "Z"); returns epoch millis. */
    long readTime() {
        int tag = peekTag();
        byte[] v = readContent(tag);
        char[] chars = new char[v.length];
        for (int i = 0; i < v.length; i++) {
            chars[i] = (char) (v[i] & 0x7f);
        }
        String s = new String(chars);
        int year;
        String rest;
        if (tag == UTC_TIME && s.length() == 13) {
            int yy = Integer.parseInt(s.substring(0, 2));
            year = yy >= 50 ? 1900 + yy : 2000 + yy;
            rest = s.substring(2);
        } else if (tag == GENERALIZED_TIME && s.length() == 15) {
            year = Integer.parseInt(s.substring(0, 4));
            rest = s.substring(4);
        } else {
            throw new IllegalArgumentException("DER unsupported time format");
        }
        if (rest.charAt(10) != 'Z') throw new IllegalArgumentException("DER time not in UTC");
        for (int i = 0; i < 10; i++) {
            char c = rest.charAt(i);
            if (c < '0' || c > '9') throw new IllegalArgumentException("DER bad time digit");
        }
        Calendar cal = Calendar.getInstance(TimeZone.getTimeZone("UTC"));
        cal.clear();
        cal.setLenient(false);
        cal.set(year, Integer.parseInt(rest.substring(0, 2)) - 1, Integer.parseInt(rest.substring(2, 4)),
                Integer.parseInt(rest.substring(4, 6)), Integer.parseInt(rest.substring(6, 8)),
                Integer.parseInt(rest.substring(8, 10)));
        return cal.getTimeInMillis();
    }

    byte[] copy(int from, int to) {
        return copyOf(buf, from, to);
    }

    private static byte[] copyOf(byte[] b, int from, int to) {
        byte[] out = new byte[to - from];
        System.arraycopy(b, from, out, 0, out.length);
        return out;
    }
}
