package org.reteget.core.tls;

/**
 * The server did not accept TLS 1.3, and nothing had been authenticated yet.
 *
 * This is the only failure after which {@link TlsClient} opens a new TLS 1.2 connection.
 * The TLS 1.2 engine then checks the RFC 8446 downgrade sentinel, so an attacker who
 * forges this condition against a TLS 1.3 server still cannot force the older protocol.
 */
public class TlsVersionException extends TlsException {

    public TlsVersionException(String message) {
        super(PROTOCOL_VERSION, message);
    }
}
