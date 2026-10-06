package org.reteget.core.tls;

import java.security.cert.CertificateException;

/**
 * The server's certificate needs the user's decision: it did not validate and nothing is on
 * record for this server, or it is not the certificate on record.
 */
public final class TlsPinException extends CertificateException {

    /** True when a certificate is on record for the server and this is another one. */
    public final boolean changed;
    /** SHA-256 of the certificate presented, upper-case hex with colons. */
    public final String fingerprint;
    /** Why it did not validate (not changed), for the user. */
    public final String reason;

    TlsPinException(boolean changed, String fingerprint, String reason) {
        super(changed ? "the server's certificate is not the one on record" : "the server's certificate is not trusted: " + reason);
        this.changed = changed;
        this.fingerprint = fingerprint;
        this.reason = reason;
    }
}
