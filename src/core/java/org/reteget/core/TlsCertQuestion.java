package org.reteget.core;

import java.io.IOException;

/**
 * An FTPS server's certificate that the user has to decide about: it does not validate and the
 * server is new, or it differs from the certificate recorded for the server.
 */
public final class TlsCertQuestion extends IOException implements UserQuestion {

    public static final String UNKNOWN = "tlscert";
    public static final String CHANGED = "tlscert-changed";

    public final String kind;
    public final String hostPort;
    /** SHA-256 of the certificate presented now. */
    public final String fingerprint;
    /** The fingerprint on record (CHANGED), or null. */
    public final String oldFingerprint;
    /** Why the certificate did not validate (UNKNOWN). */
    public final String reason;

    TlsCertQuestion(String kind, String hostPort, String fingerprint, String oldFingerprint, String reason) {
        super(CHANGED.equals(kind)
                ? "The certificate of " + hostPort + " has changed: it was " + oldFingerprint + " and is now " + fingerprint
                        + ". The server may have renewed it, or someone may be intercepting the connection"
                : "The certificate of " + hostPort + " is not trusted (" + reason + "); its SHA-256 fingerprint is "
                        + fingerprint + "; confirm it to continue");
        this.kind = kind;
        this.hostPort = hostPort;
        this.fingerprint = fingerprint;
        this.oldFingerprint = oldFingerprint;
        this.reason = reason == null ? "" : reason.replace('\t', ' ').replace('\n', ' ');
    }

    public String token() {
        return kind + "\t" + hostPort + "\t" + fingerprint + "\t" + (oldFingerprint == null ? "" : oldFingerprint) + "\t" + reason;
    }

    /** The question a token stands for, or null when it is not one. */
    public static TlsCertQuestion fromToken(String token) {
        if (token == null) return null;
        String[] f = token.split("\t", -1);
        if (f.length != 5 || (!UNKNOWN.equals(f[0]) && !CHANGED.equals(f[0]))) return null;
        if (f[1].length() == 0 || f[2].length() != 95) return null;
        return new TlsCertQuestion(f[0], f[1], f[2], f[3].length() == 0 ? null : f[3], f[4]);
    }
}
