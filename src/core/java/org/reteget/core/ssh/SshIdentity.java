package org.reteget.core.ssh;

import java.io.IOException;

/** A private key the user chose for public-key authentication (RFC 4252 section 7). */
public interface SshIdentity {

    /** The public key blob, as it stands in authorized_keys after base64 decoding. */
    byte[] publicBlob();

    /**
     * Signature algorithm names to try, best first, given what the server announced it accepts
     * (null when it announced nothing): "ssh-ed25519", or "rsa-sha2-512" and "rsa-sha2-256".
     */
    String[] algorithms(String[] serverSigAlgs);

    /** The raw signature of {@code data} for {@code algorithm} (not yet wrapped in a signature blob). */
    byte[] sign(String algorithm, byte[] data) throws IOException;
}
