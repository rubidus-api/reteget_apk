package org.reteget.core.ssh;

import java.io.IOException;

/** A failure of the SSH or SFTP protocol, or a refusal by this client (never a plain I/O error). */
public class SshException extends IOException {

    public SshException(String message) {
        super(message);
    }

    public SshException(String message, Throwable cause) {
        super(message);
        initCause(cause);
    }
}
