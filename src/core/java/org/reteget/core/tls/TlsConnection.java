package org.reteget.core.tls;

import java.io.Closeable;
import java.io.InputStream;
import java.io.OutputStream;

/** An established client TLS connection from this package's own engines. */
public interface TlsConnection extends Closeable {

    InputStream getInputStream();

    OutputStream getOutputStream();

    /** "TLSv1.3" or "TLSv1.2". */
    String getProtocol();

    /** IANA cipher suite name, e.g. "TLS_AES_128_GCM_SHA256". */
    String getCipherSuite();

    /** Short human-readable summary: protocol, suite, key exchange group, signature scheme. */
    String getSummary();
}
