package org.reteget.core.ssh;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

/** Readers and writers for the SSH wire types of RFC 4251 section 5. */
final class SshBuf {

    private SshBuf() {}

    /** Builds a packet payload or any other SSH structure. */
    static final class Writer {
        private final ByteArrayOutputStream out = new ByteArrayOutputStream();

        Writer u8(int v) {
            out.write(v);
            return this;
        }

        Writer bool(boolean v) {
            out.write(v ? 1 : 0);
            return this;
        }

        Writer u32(long v) {
            out.write((int) (v >>> 24));
            out.write((int) (v >>> 16));
            out.write((int) (v >>> 8));
            out.write((int) v);
            return this;
        }

        Writer u64(long v) {
            u32(v >>> 32);
            return u32(v);
        }

        Writer raw(byte[] b) {
            out.write(b, 0, b.length);
            return this;
        }

        Writer raw(byte[] b, int off, int len) {
            out.write(b, off, len);
            return this;
        }

        Writer string(byte[] b) {
            u32(b.length);
            return raw(b);
        }

        Writer string(byte[] b, int off, int len) {
            u32(len);
            return raw(b, off, len);
        }

        Writer string(String s) {
            return string(utf8(s));
        }

        /** A non-negative multiple-precision integer. */
        Writer mpint(BigInteger v) {
            return string(v.signum() == 0 ? new byte[0] : v.toByteArray());
        }

        /** An unsigned big-endian number as an mpint. */
        Writer mpint(byte[] unsignedBigEndian) {
            return mpint(new BigInteger(1, unsignedBigEndian));
        }

        Writer nameList(String[] names) {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < names.length; i++) {
                if (i > 0) sb.append(',');
                sb.append(names[i]);
            }
            return string(sb.toString());
        }

        byte[] bytes() {
            return out.toByteArray();
        }

        int size() {
            return out.size();
        }
    }

    /** Reads SSH types from a byte range; every read is bounds-checked. */
    static final class Reader {
        private final byte[] b;
        private int pos;
        private final int end;

        Reader(byte[] b) {
            this(b, 0, b.length);
        }

        Reader(byte[] b, int off, int len) {
            this.b = b;
            this.pos = off;
            this.end = off + len;
        }

        int remaining() {
            return end - pos;
        }

        private void need(int n) throws IOException {
            if (n < 0 || n > end - pos) throw new SshException("SSH message is truncated");
        }

        int u8() throws IOException {
            need(1);
            return b[pos++] & 0xff;
        }

        boolean bool() throws IOException {
            return u8() != 0;
        }

        long u32() throws IOException {
            need(4);
            long v = ((long) (b[pos] & 0xff) << 24) | ((b[pos + 1] & 0xff) << 16) | ((b[pos + 2] & 0xff) << 8) | (b[pos + 3] & 0xff);
            pos += 4;
            return v;
        }

        long u64() throws IOException {
            long hi = u32();
            return (hi << 32) | u32();
        }

        byte[] raw(int n) throws IOException {
            need(n);
            byte[] r = new byte[n];
            System.arraycopy(b, pos, r, 0, n);
            pos += n;
            return r;
        }

        byte[] string() throws IOException {
            long n = u32();
            if (n > remaining()) throw new SshException("SSH message is truncated");
            return raw((int) n);
        }

        String text() throws IOException {
            return fromUtf8(string());
        }

        /** A non-negative mpint; a negative one is a protocol error. */
        BigInteger mpint() throws IOException {
            byte[] s = string();
            if (s.length == 0) return BigInteger.ZERO;
            if ((s[0] & 0x80) != 0) throw new SshException("negative number in an SSH message");
            return new BigInteger(s);
        }

        String[] nameList() throws IOException {
            String s = text();
            return s.length() == 0 ? new String[0] : s.split(",");
        }

        byte[] rest() throws IOException {
            return raw(remaining());
        }
    }

    static byte[] utf8(String s) {
        try {
            return s.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    static String fromUtf8(byte[] b) {
        try {
            return new String(b, "UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }
}
