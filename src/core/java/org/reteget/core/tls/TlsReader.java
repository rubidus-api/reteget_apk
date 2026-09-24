package org.reteget.core.tls;

/**
 * Bounded cursor over TLS wire bytes. Every read checks the remaining length first and
 * fails with decode_error instead of reading past the end of its slice.
 */
final class TlsReader {

    private final byte[] buf;
    private int pos;
    private final int end;

    TlsReader(byte[] buf) {
        this(buf, 0, buf.length);
    }

    TlsReader(byte[] buf, int off, int len) {
        this.buf = buf;
        this.pos = off;
        this.end = off + len;
    }

    int remaining() {
        return end - pos;
    }

    boolean hasRemaining() {
        return pos < end;
    }

    private void need(int n) throws TlsException {
        if (n < 0 || end - pos < n) {
            throw new TlsException(TlsException.DECODE_ERROR, "truncated TLS structure");
        }
    }

    int u8() throws TlsException {
        need(1);
        return buf[pos++] & 0xff;
    }

    int u16() throws TlsException {
        need(2);
        int v = ((buf[pos] & 0xff) << 8) | (buf[pos + 1] & 0xff);
        pos += 2;
        return v;
    }

    int u24() throws TlsException {
        need(3);
        int v = ((buf[pos] & 0xff) << 16) | ((buf[pos + 1] & 0xff) << 8) | (buf[pos + 2] & 0xff);
        pos += 3;
        return v;
    }

    byte[] bytes(int n) throws TlsException {
        need(n);
        byte[] out = new byte[n];
        System.arraycopy(buf, pos, out, 0, n);
        pos += n;
        return out;
    }

    byte[] vec8() throws TlsException {
        return bytes(u8());
    }

    byte[] vec16() throws TlsException {
        return bytes(u16());
    }

    byte[] vec24() throws TlsException {
        return bytes(u24());
    }

    TlsReader sub(int n) throws TlsException {
        need(n);
        TlsReader r = new TlsReader(buf, pos, n);
        pos += n;
        return r;
    }

    TlsReader subVec16() throws TlsException {
        return sub(u16());
    }

    TlsReader subVec24() throws TlsException {
        return sub(u24());
    }

    void expectEnd() throws TlsException {
        if (pos != end) {
            throw new TlsException(TlsException.DECODE_ERROR, "trailing bytes in TLS structure");
        }
    }
}
