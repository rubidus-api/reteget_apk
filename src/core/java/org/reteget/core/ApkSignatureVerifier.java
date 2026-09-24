package org.reteget.core;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

/**
 * Parses and verifies APK signing certificates and author continuity.
 * Compatible with pure Java (JRE) and Android 2.3+ (API 9+).
 */
public class ApkSignatureVerifier {

    public enum Status {
        MATCH_INSTALLED,      // Matches currently installed application signature
        MATCH_PREVIOUS,       // Matches previously recorded download signature
        FIRST_TIME,           // No prior record found, first time seen
        MISMATCH_INSTALLED,   // Conflicts with currently installed app!
        MISMATCH_PREVIOUS,    // Author signature changed compared to previous download!
        UNSIGNED,             // File is not signed or cannot be read
        ERROR                 // Parsing error
    }

    public static class CertInfo {
        public final String sha256Fingerprint; // "AA:BB:CC:..."
        public final String sha1Fingerprint;   // "11:22:33:..."
        public final String subjectDN;
        public final String issuerDN;
        public final String commonName;
        public final Date notBefore;
        public final Date notAfter;

        public CertInfo(String sha256Fingerprint, String sha1Fingerprint,
                        String subjectDN, String issuerDN, String commonName,
                        Date notBefore, Date notAfter) {
            this.sha256Fingerprint = sha256Fingerprint;
            this.sha1Fingerprint = sha1Fingerprint;
            this.subjectDN = subjectDN;
            this.issuerDN = issuerDN;
            this.commonName = commonName;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
        }

        public String getDisplayAuthor() {
            if (commonName != null && !commonName.trim().isEmpty()) {
                return commonName.trim();
            }
            if (subjectDN != null && !subjectDN.trim().isEmpty()) {
                return subjectDN.trim();
            }
            return "Unknown Signer";
        }

        @Override
        public String toString() {
            return "CertInfo[CN=" + getDisplayAuthor() + ", SHA256=" + sha256Fingerprint + "]";
        }
    }

    public static class VerificationResult {
        public final Status status;
        public final CertInfo currentCert;
        public final String existingFingerprint;
        public final String existingSource; // "Installed App" or "Previous Download"
        public final String message;
        public final boolean isMismatch;

        public VerificationResult(Status status, CertInfo currentCert,
                                  String existingFingerprint, String existingSource,
                                  String message, boolean isMismatch) {
            this.status = status;
            this.currentCert = currentCert;
            this.existingFingerprint = existingFingerprint;
            this.existingSource = existingSource;
            this.message = message;
            this.isMismatch = isMismatch;
        }
    }

    /**
     * Parses DER-encoded X.509 certificate bytes into a CertInfo object.
     */
    public static CertInfo fromDerBytes(byte[] derBytes) throws CertificateException, NoSuchAlgorithmException {
        if (derBytes == null || derBytes.length == 0) {
            return null;
        }
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derBytes));
        return fromX509Certificate(cert, derBytes);
    }

    /**
     * Extracts CertInfo from an X509Certificate instance.
     */
    public static CertInfo fromX509Certificate(X509Certificate cert, byte[] optionalDerBytes)
            throws CertificateEncodingException, NoSuchAlgorithmException {
        if (cert == null) {
            return null;
        }
        byte[] der = (optionalDerBytes != null) ? optionalDerBytes : cert.getEncoded();
        String sha256 = formatFingerprint(MessageDigest.getInstance("SHA-256").digest(der));
        String sha1 = formatFingerprint(MessageDigest.getInstance("SHA-1").digest(der));
        String subject = cert.getSubjectDN() != null ? cert.getSubjectDN().getName() : "";
        String issuer = cert.getIssuerDN() != null ? cert.getIssuerDN().getName() : "";
        String cn = extractCommonName(subject);
        return new CertInfo(sha256, sha1, subject, issuer, cn, cert.getNotBefore(), cert.getNotAfter());
    }

    /**
     * Pure-Java inspection of APK signing certificates by reading PKCS#7 / JAR signatures.
     */
    public static CertInfo fromApkFile(File apkFile) {
        if (apkFile == null || !apkFile.exists() || !apkFile.canRead()) {
            return null;
        }

        // Method 1: Direct inspection of PKCS#7 block in META-INF/*.RSA, *.DSA, *.EC
        ZipFile zip = null;
        try {
            zip = new ZipFile(apkFile);
            Enumeration<? extends ZipEntry> en = zip.entries();
            while (en.hasMoreElements()) {
                ZipEntry ze = en.nextElement();
                String name = ze.getName().toUpperCase();
                if (name.startsWith("META-INF/") && (name.endsWith(".RSA") || name.endsWith(".DSA") || name.endsWith(".EC"))) {
                    InputStream is = zip.getInputStream(ze);
                    try {
                        CertificateFactory cf = CertificateFactory.getInstance("X.509");
                        Collection<? extends Certificate> certs = cf.generateCertificates(is);
                        if (certs != null && !certs.isEmpty()) {
                            for (Certificate c : certs) {
                                if (c instanceof X509Certificate) {
                                    return fromX509Certificate((X509Certificate) c, null);
                                }
                            }
                        }
                    } finally {
                        is.close();
                    }
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (zip != null) {
                try {
                    zip.close();
                } catch (Exception ignored) {}
            }
        }

        // Method 2: Fallback to JarFile entry verification
        JarFile jar = null;
        try {
            jar = new JarFile(apkFile, true);
            JarEntry entry = jar.getJarEntry("AndroidManifest.xml");
            if (entry == null) {
                Enumeration<JarEntry> entries = jar.entries();
                while (entries.hasMoreElements()) {
                    JarEntry e = entries.nextElement();
                    if (!e.isDirectory() && !e.getName().startsWith("META-INF/")) {
                        entry = e;
                        break;
                    }
                }
            }
            if (entry != null) {
                InputStream is = jar.getInputStream(entry);
                byte[] buf = new byte[8192];
                while (is.read(buf) != -1) {
                    // Drain stream to trigger entry verification
                }
                is.close();
                Certificate[] certs = entry.getCertificates();
                if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                    return fromX509Certificate((X509Certificate) certs[0], null);
                }
            }
        } catch (Exception ignored) {
        } finally {
            if (jar != null) {
                try {
                    jar.close();
                } catch (Exception ignored) {}
            }
        }
        return null;
    }

    /**
     * Verifies author and signature continuity against an installed app or previous download.
     */
    public static VerificationResult verifyContinuity(
            CertInfo currentCert,
            CertInfo installedCert,
            String savedFingerprint,
            String savedAuthor) {
        if (currentCert == null) {
            return new VerificationResult(Status.UNSIGNED, null, null, null,
                    "File has no signing certificate.", false);
        }

        // 1. Highest priority: Compare against installed app on device
        if (installedCert != null) {
            boolean match = normalizeFingerprint(currentCert.sha256Fingerprint)
                    .equals(normalizeFingerprint(installedCert.sha256Fingerprint));
            if (match) {
                return new VerificationResult(Status.MATCH_INSTALLED, currentCert,
                        installedCert.sha256Fingerprint, "Installed App",
                        "Signature matches installed application (" + installedCert.getDisplayAuthor() + ").",
                        false);
            } else {
                return new VerificationResult(Status.MISMATCH_INSTALLED, currentCert,
                        installedCert.sha256Fingerprint, "Installed App",
                        "Signature does NOT match installed application (" + installedCert.getDisplayAuthor() + ")!",
                        true);
            }
        }

        // 2. Next: Compare against recorded previous download (TOFU)
        if (savedFingerprint != null && !savedFingerprint.trim().isEmpty()) {
            String normSaved = normalizeFingerprint(savedFingerprint);
            boolean match = normalizeFingerprint(currentCert.sha256Fingerprint).equals(normSaved);
            if (match) {
                return new VerificationResult(Status.MATCH_PREVIOUS, currentCert,
                        normSaved, "Previous Download",
                        "Signature matches previously downloaded version.",
                        false);
            } else {
                String authorHint = (savedAuthor != null && !savedAuthor.trim().isEmpty())
                        ? " (" + savedAuthor.trim() + ")" : "";
                return new VerificationResult(Status.MISMATCH_PREVIOUS, currentCert,
                        normSaved, "Previous Download",
                        "Author signature changed compared to previous download" + authorHint + "!",
                        true);
            }
        }

        // 3. First time seeing this package/URL
        return new VerificationResult(Status.FIRST_TIME, currentCert, null, null,
                "First time downloaded. Author: " + currentCert.getDisplayAuthor(),
                false);
    }

    /**
     * Extracts Common Name (CN) from a DN string like "CN=Rubidus, O=Company, C=KR".
     */
    public static String extractCommonName(String dn) {
        if (dn == null) return "";
        int cnIndex = dn.toUpperCase().indexOf("CN=");
        if (cnIndex == -1) {
            return dn;
        }
        int start = cnIndex + 3;
        if (start >= dn.length()) return "";

        if (dn.charAt(start) == '"') {
            int endQuote = dn.indexOf('"', start + 1);
            if (endQuote != -1) {
                return dn.substring(start + 1, endQuote).trim();
            }
        }

        int end = dn.indexOf(',', start);
        if (end == -1) {
            end = dn.length();
        }
        String val = dn.substring(start, end).trim();
        if (val.startsWith("\"") && val.endsWith("\"") && val.length() >= 2) {
            val = val.substring(1, val.length() - 1);
        }
        return val;
    }

    /**
     * Normalizes a fingerprint by removing colons, spaces, and converting to uppercase.
     */
    public static String normalizeFingerprint(String fp) {
        if (fp == null) return "";
        return fp.replaceAll("[^0-9a-fA-F]", "").toUpperCase();
    }

    /**
     * Formats raw bytes into standard colon-separated uppercase hex fingerprint (e.g. 2A:4F:91:...).
     */
    public static String formatFingerprint(byte[] bytes) {
        if (bytes == null || bytes.length == 0) return "";
        StringBuilder sb = new StringBuilder(bytes.length * 3);
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(':');
            int b = bytes[i] & 0xFF;
            if (b < 16) sb.append('0');
            sb.append(Integer.toHexString(b).toUpperCase());
        }
        return sb.toString();
    }
}
