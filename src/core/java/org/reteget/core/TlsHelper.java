package org.reteget.core;

import java.io.BufferedInputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.security.KeyStore;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Manages modern TLS configuration, bundled Root CA verification,
 * and optional insecure SSL bypass for legacy Android devices.
 */
public final class TlsHelper {

    private static SSLSocketFactory compatSocketFactory;
    private static SSLSocketFactory insecureSocketFactory;
    private static X509TrustManager systemTrustManager;
    private static X509TrustManager bundledTrustManager;
    private static X509TrustManager compositeTm;
    private static X509TrustManager trustAllTm;

    private static final HostnameVerifier ALLOW_ALL_HOSTNAME_VERIFIER = new HostnameVerifier() {
        @Override
        public boolean verify(String hostname, SSLSession session) {
            return true;
        }
    };

    private TlsHelper() {}

    /**
     * Initializes the custom TLS trust store with bundled PEM certificates.
     * Safe to call multiple times; ignores null stream.
     */
    public static synchronized void init(InputStream pemInputStream) {
        try {
            // 1. Locate system default X509TrustManager
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
            tmf.init((KeyStore) null);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    systemTrustManager = (X509TrustManager) tm;
                    break;
                }
            }

            // 2. Parse bundled Root CAs if provided
            if (pemInputStream != null) {
                try {
                    KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
                    keyStore.load(null, null);

                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    InputStream bis = new BufferedInputStream(pemInputStream);
                    Collection<? extends Certificate> certs = cf.generateCertificates(bis);

                    int count = 0;
                    for (Certificate cert : certs) {
                        if (cert instanceof X509Certificate) {
                            X509Certificate x509 = (X509Certificate) cert;
                            String alias = "bundled_root_" + (++count) + "_" + x509.getSubjectX500Principal().getName();
                            keyStore.setCertificateEntry(alias, cert);
                        }
                    }

                    if (count > 0) {
                        TrustManagerFactory customTmf =
                                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
                        customTmf.init(keyStore);
                        for (TrustManager tm : customTmf.getTrustManagers()) {
                            if (tm instanceof X509TrustManager) {
                                bundledTrustManager = (X509TrustManager) tm;
                                break;
                            }
                        }
                    }
                } catch (Exception e) {
                    // Fall back to system trust manager if parsing fails
                    System.err.println("TlsHelper: failed to parse bundled certificates: " + e.getMessage());
                } finally {
                    try {
                        pemInputStream.close();
                    } catch (Exception ignored) {}
                }
            }

            // 3. Build composite trust manager
            compositeTm = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType)
                        throws CertificateException {
                    if (systemTrustManager != null) {
                        systemTrustManager.checkClientTrusted(chain, authType);
                    }
                }

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType)
                        throws CertificateException {
                    // Try system trust manager first
                    if (systemTrustManager != null) {
                        try {
                            systemTrustManager.checkServerTrusted(chain, authType);
                            return; // System accepted
                        } catch (CertificateException sysEx) {
                            // System failed; fall back to bundled roots
                            if (bundledTrustManager != null) {
                                bundledTrustManager.checkServerTrusted(chain, authType);
                                return; // Bundled roots accepted
                            }
                            throw sysEx;
                        }
                    } else if (bundledTrustManager != null) {
                        bundledTrustManager.checkServerTrusted(chain, authType);
                    }
                }

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    // Union of both stores: the in-tree TLS engine uses these as its trust anchors.
                    java.util.List<X509Certificate> all = new java.util.ArrayList<X509Certificate>();
                    if (bundledTrustManager != null) {
                        all.addAll(java.util.Arrays.asList(bundledTrustManager.getAcceptedIssuers()));
                    }
                    if (systemTrustManager != null) {
                        all.addAll(java.util.Arrays.asList(systemTrustManager.getAcceptedIssuers()));
                    }
                    return all.toArray(new X509Certificate[all.size()]);
                }
            };

            // 4. Initialize standard compat SSLSocketFactory
            SSLContext sslContext = createSslContext();
            sslContext.init(null, new TrustManager[] { compositeTm }, new SecureRandom());
            compatSocketFactory = new TlsSocketFactoryCompat(sslContext.getSocketFactory());

            // 5. Initialize insecure trust-all SSLSocketFactory
            trustAllTm = new X509TrustManager() {
                @Override
                public void checkClientTrusted(X509Certificate[] chain, String authType) {}

                @Override
                public void checkServerTrusted(X509Certificate[] chain, String authType) {}

                @Override
                public X509Certificate[] getAcceptedIssuers() {
                    return new X509Certificate[0];
                }
            };
            SSLContext insecureContext = createSslContext();
            insecureContext.init(null, new TrustManager[] { trustAllTm }, new SecureRandom());
            insecureSocketFactory = new TlsSocketFactoryCompat(insecureContext.getSocketFactory());

        } catch (Exception e) {
            System.err.println("TlsHelper.init error: " + e.getMessage());
        }
    }

    public static X509TrustManager getTrustManager(boolean insecure) {
        if (insecure) {
            if (trustAllTm == null) {
                init(null);
            }
            return trustAllTm;
        }
        if (compositeTm == null) {
            init(null);
        }
        return compositeTm;
    }

    private static SSLContext createSslContext() {
        try {
            return SSLContext.getInstance("TLSv1.2");
        } catch (Exception ignored) {
            try {
                return SSLContext.getInstance("TLS");
            } catch (Exception e) {
                throw new RuntimeException("No TLS provider available", e);
            }
        }
    }

    public static SSLSocketFactory getSocketFactory(boolean insecure) {
        if (insecure) {
            if (insecureSocketFactory == null) {
                init(null);
            }
            return insecureSocketFactory;
        }
        if (compatSocketFactory == null) {
            init(null);
        }
        return compatSocketFactory;
    }

    public static HostnameVerifier getHostnameVerifier(boolean insecure) {
        if (insecure) {
            return ALLOW_ALL_HOSTNAME_VERIFIER;
        }
        return HttpsURLConnection.getDefaultHostnameVerifier();
    }

    /**
     * Configures an HttpURLConnection with compatibility SSLSocketFactory and HostnameVerifier.
     */
    public static void configureConnection(HttpURLConnection conn, boolean insecure) {
        if (conn instanceof HttpsURLConnection) {
            HttpsURLConnection https = (HttpsURLConnection) conn;
            SSLSocketFactory sf = getSocketFactory(insecure);
            if (sf != null) {
                https.setSSLSocketFactory(sf);
            }
            if (insecure) {
                https.setHostnameVerifier(ALLOW_ALL_HOSTNAME_VERIFIER);
            }
        }
    }
}
