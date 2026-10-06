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

    /**
     * The session a second connection to the same server can resume, or null when there is none
     * (the connection was not opened for that, or the server issued nothing resumable yet).
     */
    TlsSession session();

    /** True when this connection resumed an earlier session instead of a full handshake. */
    boolean wasResumed();

    /** True once the peer ended the connection with close_notify (not just a TCP close). */
    boolean closedCleanly();
}
