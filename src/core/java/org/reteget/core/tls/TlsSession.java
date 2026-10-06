package org.reteget.core.tls;

import java.util.Arrays;

/**
 * What a finished handshake leaves for resuming on a second connection to the same server: a
 * TLS 1.2 session (id and master secret) or a TLS 1.3 ticket with its pre-shared key.
 *
 * Used for one purpose: the data connection of FTPS, where servers require the session of the
 * control connection to be reused (RFC 4217 section 10.2). It lives in memory only, for as
 * long as the control connection does; {@link #wipe} clears the secrets.
 */
public final class TlsSession {

    final int version;
    final String host;

    // TLS 1.2
    final byte[] sessionId;
    final byte[] masterSecret;
    final int cipherSuite;
    final boolean extendedMasterSecret;

    // TLS 1.3
    final byte[] ticket;
    final byte[] psk;
    final long ticketAgeAdd;
    final long receivedAtMillis;
    final long lifetimeMillis;

    /** A TLS 1.2 session. */
    TlsSession(String host, byte[] sessionId, byte[] masterSecret, int cipherSuite, boolean extendedMasterSecret) {
        this.version = Tls13Socket.VERSION_TLS12;
        this.host = host;
        this.sessionId = sessionId;
        this.masterSecret = masterSecret;
        this.cipherSuite = cipherSuite;
        this.extendedMasterSecret = extendedMasterSecret;
        this.ticket = null;
        this.psk = null;
        this.ticketAgeAdd = 0;
        this.receivedAtMillis = 0;
        this.lifetimeMillis = 0;
    }

    /** A TLS 1.3 ticket. */
    TlsSession(String host, byte[] ticket, byte[] psk, long ticketAgeAdd, long receivedAtMillis, long lifetimeMillis) {
        this.version = Tls13Socket.VERSION_TLS13;
        this.host = host;
        this.ticket = ticket;
        this.psk = psk;
        this.ticketAgeAdd = ticketAgeAdd;
        this.receivedAtMillis = receivedAtMillis;
        this.lifetimeMillis = lifetimeMillis;
        this.sessionId = null;
        this.masterSecret = null;
        this.cipherSuite = Tls13Socket.TLS_AES_128_GCM_SHA256;
        this.extendedMasterSecret = false;
    }

    public boolean isTls13() {
        return version == Tls13Socket.VERSION_TLS13;
    }

    /** Overwrites the secrets; the session cannot be resumed afterwards. */
    public void wipe() {
        if (masterSecret != null) Arrays.fill(masterSecret, (byte) 0);
        if (psk != null) Arrays.fill(psk, (byte) 0);
    }
}
