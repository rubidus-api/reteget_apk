package org.reteget.core;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Universal checksum calculator and verifier supporting SHA-256, SHA-1, MD5, and SHA-512.
 * Fully compatible with standard GitHub / GitLab checksum formats and Linux sha256sum outputs.
 * Compatible with pure Java 6/7/8 without external dependencies.
 */
public class ChecksumVerifier {

    public static final String ALGO_SHA256 = "SHA-256";
    public static final String ALGO_SHA1 = "SHA-1";
    public static final String ALGO_MD5 = "MD5";
    public static final String ALGO_SHA512 = "SHA-512";

    private static final Pattern PREFIX_PATTERN = Pattern.compile(
            "^(sha256|sha1|md5|sha512|sha-256|sha-1|sha-512)\\s*[:=]\\s*(.*)$",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern BSD_FORMAT_PATTERN = Pattern.compile(
            "^(SHA256|SHA1|MD5|SHA512)\\s*\\([^)]+\\)\\s*=\\s*([0-9a-fA-F]+)$",
            Pattern.CASE_INSENSITIVE);

    public static class Result {
        public final boolean matched;
        public final String algorithm;
        public final String expectedHash;
        public final String actualHash;
        public final String error;

        private Result(boolean matched, String algorithm, String expectedHash, String actualHash, String error) {
            this.matched = matched;
            this.algorithm = algorithm;
            this.expectedHash = expectedHash;
            this.actualHash = actualHash;
            this.error = error;
        }

        public static Result match(String algo, String expected, String actual) {
            return new Result(true, algo, expected, actual, null);
        }

        public static Result mismatch(String algo, String expected, String actual) {
            return new Result(false, algo, expected, actual, null);
        }

        public static Result error(String message) {
            return new Result(false, null, null, null, message);
        }
    }

    /**
     * Normalizes algorithm name to standard Java MessageDigest algorithm identifier.
     */
    public static String normalizeAlgorithm(String name) {
        if (name == null) return null;
        String clean = name.trim().toUpperCase().replace("-", "");
        if ("SHA256".equals(clean)) return ALGO_SHA256;
        if ("SHA1".equals(clean)) return ALGO_SHA1;
        if ("MD5".equals(clean)) return ALGO_MD5;
        if ("SHA512".equals(clean)) return ALGO_SHA512;
        return null;
    }

    /**
     * Extracts raw hex digest string from various checksum text formats (e.g. GitHub release notes,
     * GNU coreutils sha256sum line "hash  filename", BSD style "SHA256 (file) = hash",
     * or "sha256:hash").
     */
    public static String extractHash(String rawInput) {
        if (rawInput == null) return "";
        String s = rawInput.trim();
        if (s.isEmpty()) return "";

        // BSD format: SHA256 (filename) = <hash>
        Matcher bsdMatcher = BSD_FORMAT_PATTERN.matcher(s);
        if (bsdMatcher.matches()) {
            return bsdMatcher.group(2).trim().toLowerCase();
        }

        // Prefix format: sha256: <hash> or sha256=<hash>
        Matcher prefixMatcher = PREFIX_PATTERN.matcher(s);
        if (prefixMatcher.matches()) {
            s = prefixMatcher.group(2).trim();
        }

        // GNU format: "<hash>  <filename>" or "<hash> *<filename>"
        String[] tokens = s.split("\\s+");
        for (String token : tokens) {
            String candidate = token.trim();
            if (isHex(candidate)) {
                return candidate.toLowerCase();
            }
        }

        return isHex(s) ? s.toLowerCase() : "";
    }

    /**
     * Detects hash algorithm from prefix or hexadecimal string length:
     * - 32 hex chars -> MD5
     * - 40 hex chars -> SHA-1
     * - 64 hex chars -> SHA-256
     * - 128 hex chars -> SHA-512
     */
    public static String detectAlgorithm(String rawInput) {
        if (rawInput == null) return null;
        String s = rawInput.trim();
        if (s.isEmpty()) return null;

        // Check BSD format
        Matcher bsdMatcher = BSD_FORMAT_PATTERN.matcher(s);
        if (bsdMatcher.matches()) {
            return normalizeAlgorithm(bsdMatcher.group(1));
        }

        // Check prefix
        Matcher prefixMatcher = PREFIX_PATTERN.matcher(s);
        if (prefixMatcher.matches()) {
            String algo = normalizeAlgorithm(prefixMatcher.group(1));
            if (algo != null) return algo;
        }

        // Fall back to hex string length
        String hex = extractHash(s);
        if (hex.length() == 64) return ALGO_SHA256;
        if (hex.length() == 40) return ALGO_SHA1;
        if (hex.length() == 32) return ALGO_MD5;
        if (hex.length() == 128) return ALGO_SHA512;

        return null;
    }

    private static boolean isHex(String s) {
        if (s == null || s.isEmpty()) return false;
        int len = s.length();
        if (len != 32 && len != 40 && len != 64 && len != 128) {
            return false;
        }
        for (int i = 0; i < len; i++) {
            char c = s.charAt(i);
            boolean valid = (c >= '0' && c <= '9') ||
                            (c >= 'a' && c <= 'f') ||
                            (c >= 'A' && c <= 'F');
            if (!valid) return false;
        }
        return true;
    }

    /**
     * Computes the checksum of a file using the given algorithm (SHA-256, SHA-1, MD5, SHA-512).
     */
    public static String computeHash(File file, String algorithm) throws IOException {
        String normAlgo = normalizeAlgorithm(algorithm);
        if (normAlgo == null) {
            throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
        }

        MessageDigest md;
        try {
            md = MessageDigest.getInstance(normAlgo);
        } catch (NoSuchAlgorithmException e) {
            throw new IOException("Algorithm not available: " + normAlgo, e);
        }

        InputStream is = new BufferedInputStream(new FileInputStream(file));
        try {
            byte[] buf = new byte[8192];
            int read;
            while ((read = is.read(buf)) != -1) {
                md.update(buf, 0, read);
            }
        } finally {
            is.close();
        }

        return bytesToHex(md.digest());
    }

    /**
     * Computes multiple checksums (e.g. SHA-256, SHA-1, MD5) in a single streaming pass
     * over the file to minimize disk read operations on slower storage.
     */
    public static Map<String, String> computeMultiHashes(File file, String[] algorithms) throws IOException {
        if (file == null || !file.exists() || !file.isFile()) {
            throw new IOException("File does not exist: " + file);
        }

        Map<String, MessageDigest> digests = new LinkedHashMap<String, MessageDigest>();
        for (String algo : algorithms) {
            String norm = normalizeAlgorithm(algo);
            if (norm != null && !digests.containsKey(norm)) {
                try {
                    digests.put(norm, MessageDigest.getInstance(norm));
                } catch (NoSuchAlgorithmException ignored) {}
            }
        }

        if (digests.isEmpty()) {
            return Collections.emptyMap();
        }

        InputStream is = new BufferedInputStream(new FileInputStream(file));
        try {
            byte[] buf = new byte[8192];
            int read;
            while ((read = is.read(buf)) != -1) {
                for (MessageDigest md : digests.values()) {
                    md.update(buf, 0, read);
                }
            }
        } finally {
            is.close();
        }

        Map<String, String> results = new LinkedHashMap<String, String>();
        for (Map.Entry<String, MessageDigest> entry : digests.entrySet()) {
            results.put(entry.getKey(), bytesToHex(entry.getValue().digest()));
        }
        return results;
    }

    /**
     * Verifies a file against an expected hash string.
     * Automatically identifies algorithm from prefix or hex length, computes file hash,
     * and performs case-insensitive verification.
     */
    public static Result verify(File file, String rawExpectedInput) {
        if (file == null || !file.exists() || !file.isFile()) {
            return Result.error("File does not exist or is not readable");
        }

        String expectedHash = extractHash(rawExpectedInput);
        if (expectedHash.isEmpty()) {
            return Result.error("Invalid checksum format. Provide a 32 (MD5), 40 (SHA-1), 64 (SHA-256), or 128 (SHA-512) hex digest.");
        }

        String algorithm = detectAlgorithm(rawExpectedInput);
        if (algorithm == null) {
            return Result.error("Unable to determine hash algorithm for input: " + rawExpectedInput);
        }

        try {
            String actualHash = computeHash(file, algorithm);
            if (expectedHash.equalsIgnoreCase(actualHash)) {
                return Result.match(algorithm, expectedHash, actualHash);
            } else {
                return Result.mismatch(algorithm, expectedHash, actualHash);
            }
        } catch (Exception e) {
            return Result.error("Failed to compute " + algorithm + ": " + e.getMessage());
        }
    }

    public static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            int v = b & 0xFF;
            if (v < 16) sb.append('0');
            sb.append(Integer.toHexString(v));
        }
        return sb.toString();
    }
}
