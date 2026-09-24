package org.reteget.core.tls;

import java.io.IOException;
import java.net.IDN;
import javax.net.ssl.X509TrustManager;

/**
 * Entry point for the in-tree TLS engines.
 *
 * Tries TLS 1.3 first. Only when the server shows, before anything was authenticated,
 * that it does not speak TLS 1.3 ({@link TlsVersionException}) does it open a second
 * connection with the TLS 1.2 engine. Certificate, signature and Finished failures are
 * never retried with another version.
 */
public final class TlsClient {

    private TlsClient() {}

    /**
     * @param trustManager platform trust manager for chain validation, or null to skip
     *                     certificate verification entirely (the app's insecure mode).
     */
    public static TlsConnection connect(String host, int port, int timeoutMs, X509TrustManager trustManager)
            throws IOException {
        String asciiHost = IDN.toASCII(host).toLowerCase(java.util.Locale.US);
        CertificatePolicy policy = trustManager == null
                ? CertificatePolicy.insecure() : CertificatePolicy.trusting(trustManager);
        try {
            return Tls13Socket.connect(asciiHost, port, timeoutMs, policy);
        } catch (TlsVersionException e) {
            return Tls12Socket.connect(asciiHost, port, timeoutMs, policy);
        }
    }
}
