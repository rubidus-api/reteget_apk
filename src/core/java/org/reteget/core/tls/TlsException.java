package org.reteget.core.tls;

import java.io.IOException;

/** A TLS failure, carrying the alert that was sent or received when there was one. */
public class TlsException extends IOException {

    public static final int CLOSE_NOTIFY = 0;
    public static final int UNEXPECTED_MESSAGE = 10;
    public static final int BAD_RECORD_MAC = 20;
    public static final int RECORD_OVERFLOW = 22;
    public static final int HANDSHAKE_FAILURE = 40;
    public static final int BAD_CERTIFICATE = 42;
    public static final int UNSUPPORTED_CERTIFICATE = 43;
    public static final int CERTIFICATE_UNKNOWN = 46;
    public static final int ILLEGAL_PARAMETER = 47;
    public static final int DECODE_ERROR = 50;
    public static final int DECRYPT_ERROR = 51;
    public static final int PROTOCOL_VERSION = 70;
    public static final int INSUFFICIENT_SECURITY = 71;
    public static final int INTERNAL_ERROR = 80;
    public static final int MISSING_EXTENSION = 109;
    public static final int UNSUPPORTED_EXTENSION = 110;
    public static final int UNRECOGNIZED_NAME = 112;
    public static final int CERTIFICATE_REQUIRED = 116;
    public static final int NO_APPLICATION_PROTOCOL = 120;

    public final int alert;
    public final boolean received;

    public TlsException(int alert, String message) {
        this(alert, false, message, null);
    }

    public TlsException(int alert, String message, Throwable cause) {
        this(alert, false, message, cause);
    }

    public TlsException(int alert, boolean received, String message, Throwable cause) {
        super(message);
        this.alert = alert;
        this.received = received;
        if (cause != null) {
            initCause(cause);
        }
    }
}
