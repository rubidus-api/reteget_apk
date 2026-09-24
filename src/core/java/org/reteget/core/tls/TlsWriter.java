package org.reteget.core.tls;

import java.io.ByteArrayOutputStream;

/** Builder for TLS wire structures with explicit length prefixes. */
final class TlsWriter {

    private final ByteArrayOutputStream out = new ByteArrayOutputStream();

    TlsWriter u8(int v) {
        out.write(v);
        return this;
    }

    TlsWriter u16(int v) {
        out.write(v >>> 8);
        out.write(v);
        return this;
    }

    TlsWriter u24(int v) {
        out.write(v >>> 16);
        out.write(v >>> 8);
        out.write(v);
        return this;
    }

    TlsWriter raw(byte[] b) {
        out.write(b, 0, b.length);
        return this;
    }

    TlsWriter vec8(byte[] b) {
        if (b.length > 0xff) throw new IllegalArgumentException("vector too long");
        return u8(b.length).raw(b);
    }

    TlsWriter vec16(byte[] b) {
        if (b.length > 0xffff) throw new IllegalArgumentException("vector too long");
        return u16(b.length).raw(b);
    }

    TlsWriter vec24(byte[] b) {
        if (b.length > 0xffffff) throw new IllegalArgumentException("vector too long");
        return u24(b.length).raw(b);
    }

    /** Appends an extension: uint16 type || opaque data<0..2^16-1>. */
    TlsWriter extension(int type, byte[] data) {
        return u16(type).vec16(data);
    }

    byte[] toByteArray() {
        return out.toByteArray();
    }

    /** Wraps a body as a handshake message: HandshakeType || uint24 length || body. */
    static byte[] handshake(int type, byte[] body) {
        return new TlsWriter().u8(type).vec24(body).toByteArray();
    }
}
