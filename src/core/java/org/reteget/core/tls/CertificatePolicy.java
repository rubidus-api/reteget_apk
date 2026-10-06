package org.reteget.core.tls;

import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.WeakHashMap;
import javax.net.ssl.X509TrustManager;

/**
 * Decides whether a server certificate chain identifies the host we connected to.
 *
 * The host name is matched against the leaf's subjectAltName by {@link HostnameChecker}.
 * The chain is first given to the platform X509TrustManager (system and bundled roots);
 * if the platform rejects it or cannot process it (Android 2.3 has no ECDSA certificate
 * support), {@link PathValidator} checks it against the same roots with this package's
 * own signature verifiers.
 */
public abstract class CertificatePolicy {

    /**
     * @param chain         the server chain parsed by this package, leaf first
     * @param platformChain the same chain as platform objects, or null if the platform
     *                      could not parse it
     */
    public abstract void check(String host, X509Cert[] chain, X509Certificate[] platformChain)
            throws CertificateException;

    /** True when this policy skips verification (the app's explicit "insecure" switch). */
    public boolean isInsecure() {
        return false;
    }

    public static CertificatePolicy trusting(final X509TrustManager trustManager) {
        if (trustManager == null) {
            throw new IllegalArgumentException("trust manager required; use insecure() explicitly");
        }
        return new CertificatePolicy() {
            @Override
            public void check(String host, X509Cert[] chain, X509Certificate[] platformChain)
                    throws CertificateException {
                if (!HostnameChecker.matches(host, chain[0])) {
                    throw new CertificateException("certificate does not match host " + host);
                }
                String authType = chain[0].publicKey.isRsa() ? "ECDHE_RSA" : "ECDHE_ECDSA";
                String platformProblem = "platform could not parse the chain";
                if (platformChain != null) {
                    try {
                        trustManager.checkServerTrusted(platformChain, authType);
                        return;
                    } catch (CertificateException e) {
                        platformProblem = String.valueOf(e.getMessage());
                    } catch (RuntimeException e) {
                        platformProblem = e.toString();
                    }
                }
                String reason = PathValidator.validate(chain, anchors(trustManager), System.currentTimeMillis());
                if (reason != null) {
                    throw new CertificateException(reason + " (platform: " + platformProblem + ")");
                }
            }
        };
    }

    /**
     * Validation with a per-server record, for servers whose certificates no authority signed
     * (a NAS, a private FTPS server). With a fingerprint on record, exactly that certificate is
     * accepted and any other is refused; without one, the chain is validated as usual and a
     * failure is reported as a {@link TlsPinException} carrying the fingerprint to confirm.
     *
     * @param recorded the SHA-256 fingerprint on record for this server (see {@link #fingerprint}), or null
     */
    public static CertificatePolicy pinned(final X509TrustManager trustManager, final String recorded) {
        final CertificatePolicy usual = trusting(trustManager);
        return new CertificatePolicy() {
            @Override
            public void check(String host, X509Cert[] chain, X509Certificate[] platformChain)
                    throws CertificateException {
                String fp = fingerprint(chain[0].der);
                if (recorded != null) {
                    if (!recorded.equals(fp)) throw new TlsPinException(true, fp, null);
                    return;
                }
                try {
                    usual.check(host, chain, platformChain);
                } catch (TlsPinException e) {
                    throw e;
                } catch (CertificateException e) {
                    throw new TlsPinException(false, fp, String.valueOf(e.getMessage()));
                }
            }
        };
    }

    /** SHA-256 of a certificate as tools print it: upper-case hex pairs joined by colons. */
    public static String fingerprint(byte[] der) {
        try {
            byte[] d = java.security.MessageDigest.getInstance("SHA-256").digest(der);
            StringBuilder sb = new StringBuilder(95);
            for (int i = 0; i < d.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(Character.toUpperCase(Character.forDigit((d[i] >> 4) & 0xf, 16)));
                sb.append(Character.toUpperCase(Character.forDigit(d[i] & 0xf, 16)));
            }
            return sb.toString();
        } catch (java.security.NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    /** Accepts any certificate. Used only when the user turned verification off. */
    public static CertificatePolicy insecure() {
        return new CertificatePolicy() {
            @Override
            public void check(String host, X509Cert[] chain, X509Certificate[] platformChain) {}

            @Override
            public boolean isInsecure() {
                return true;
            }
        };
    }

    private static final Map<X509TrustManager, List<X509Cert>> ANCHORS =
            new WeakHashMap<X509TrustManager, List<X509Cert>>();

    /** The trust manager's roots, parsed once; roots with unsupported keys are skipped. */
    static List<X509Cert> anchors(X509TrustManager tm) {
        synchronized (ANCHORS) {
            List<X509Cert> list = ANCHORS.get(tm);
            if (list == null) {
                list = new ArrayList<X509Cert>();
                X509Certificate[] roots = tm.getAcceptedIssuers();
                if (roots != null) {
                    for (X509Certificate root : roots) {
                        try {
                            list.add(X509Cert.parse(root.getEncoded()));
                        } catch (Exception ignored) {
                            // e.g. DSA roots: they cannot anchor a path we can verify anyway
                        }
                    }
                }
                ANCHORS.put(tm, list);
            }
            return list;
        }
    }
}
