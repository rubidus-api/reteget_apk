package org.reteget.core;

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;

/**
 * Represents a saved download preset with historical metadata (download time, file size,
 * version, filename, SHA-256 checksum, and signing certificate fingerprint).
 * Pure Java, single-dex, zero external dependencies.
 */
public class PresetItem {

    public String name;
    public String url;
    public String lastFileName;
    public long lastFileSize = -1;
    public String lastVersion;
    public long lastDownloadedAt = 0;
    public String lastSha256;
    public String lastSigFingerprint;
    public String lastAuthor;

    // Transient UI selection state
    public boolean isSelected = false;

    public PresetItem(String url) {
        this("", url);
    }

    public PresetItem(String name, String url) {
        this.name = (name != null) ? name.trim() : "";
        this.url = (url != null) ? url.trim() : "";
    }

    public PresetItem(String url, String lastFileName, long lastFileSize,
                      String lastVersion, long lastDownloadedAt,
                      String lastSha256, String lastSigFingerprint, String lastAuthor) {
        this("", url, lastFileName, lastFileSize, lastVersion, lastDownloadedAt,
                lastSha256, lastSigFingerprint, lastAuthor);
    }

    public PresetItem(String name, String url, String lastFileName, long lastFileSize,
                      String lastVersion, long lastDownloadedAt,
                      String lastSha256, String lastSigFingerprint, String lastAuthor) {
        this.name = (name != null) ? name.trim() : "";
        this.url = (url != null) ? url.trim() : "";
        this.lastFileName = lastFileName;
        this.lastFileSize = lastFileSize;
        this.lastVersion = lastVersion;
        this.lastDownloadedAt = lastDownloadedAt;
        this.lastSha256 = lastSha256;
        this.lastSigFingerprint = lastSigFingerprint;
        this.lastAuthor = lastAuthor;
    }

    public String getDisplayName() {
        if (name != null && !name.trim().isEmpty()) {
            return name.trim();
        }
        if (lastFileName != null && !lastFileName.trim().isEmpty()) {
            return lastFileName.trim();
        }
        int lastSlash = url.lastIndexOf('/');
        if (lastSlash >= 0 && lastSlash < url.length() - 1) {
            return url.substring(lastSlash + 1);
        }
        return url;
    }

    public boolean hasMetadata() {
        return (lastFileName != null && !lastFileName.trim().isEmpty())
                || (lastVersion != null && !lastVersion.trim().isEmpty())
                || (lastFileSize >= 0)
                || (lastDownloadedAt > 0)
                || (lastSha256 != null && !lastSha256.trim().isEmpty())
                || (lastSigFingerprint != null && !lastSigFingerprint.trim().isEmpty());
    }

    public String getFormattedDate() {
        if (lastDownloadedAt <= 0) return "";
        try {
            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.US);
            return sdf.format(new Date(lastDownloadedAt));
        } catch (Exception e) {
            return "";
        }
    }

    public String getFormattedSize() {
        if (lastFileSize < 0) return "";
        if (lastFileSize < 1024) return lastFileSize + " B";
        int exp = (int) (Math.log(lastFileSize) / Math.log(1024));
        char unit = "KMGTPE".charAt(exp - 1);
        return String.format(Locale.US, "%.1f %cB", lastFileSize / Math.pow(1024, exp), unit);
    }

    public String getMetadataSummary() {
        if (!hasMetadata()) {
            return "No download record yet";
        }
        StringBuilder sb = new StringBuilder();
        if (lastFileName != null && !lastFileName.trim().isEmpty()) {
            sb.append(lastFileName.trim());
        } else if (lastVersion != null && !lastVersion.trim().isEmpty()) {
            sb.append("v").append(lastVersion.trim());
        }
        if (lastFileSize >= 0) {
            if (sb.length() > 0) sb.append(" (").append(getFormattedSize()).append(")");
            else sb.append(getFormattedSize());
        }
        if (lastDownloadedAt > 0) {
            if (sb.length() > 0) sb.append(" · ");
            sb.append(getFormattedDate());
        }
        if (lastSha256 != null && lastSha256.trim().length() >= 8) {
            if (sb.length() > 0) sb.append("\n");
            String trimmed = lastSha256.trim();
            sb.append("SHA-256: ").append(trimmed.substring(0, Math.min(12, trimmed.length()))).append("…");
        }
        if (lastAuthor != null && !lastAuthor.trim().isEmpty()) {
            if (lastSha256 != null && !lastSha256.trim().isEmpty()) sb.append(" · ");
            else if (sb.length() > 0) sb.append("\n");
            sb.append("Sig: ").append(lastAuthor.trim());
        } else if (lastSigFingerprint != null && lastSigFingerprint.trim().length() >= 8) {
            if (lastSha256 != null && !lastSha256.trim().isEmpty()) sb.append(" · ");
            else if (sb.length() > 0) sb.append("\n");
            String trimmed = lastSigFingerprint.trim();
            sb.append("Sig: ").append(trimmed.substring(0, Math.min(11, trimmed.length()))).append("…");
        }
        return sb.toString();
    }

    public String toJson() {
        StringBuilder sb = new StringBuilder();
        sb.append("{");
        sb.append("\"url\":").append(escapeJson(url));
        if (name != null && !name.trim().isEmpty()) {
            sb.append(",\"name\":").append(escapeJson(name.trim()));
        }
        if (lastFileName != null && !lastFileName.trim().isEmpty()) {
            sb.append(",\"filename\":").append(escapeJson(lastFileName.trim()));
        }
        if (lastFileSize >= 0) {
            sb.append(",\"size\":").append(lastFileSize);
        }
        if (lastVersion != null && !lastVersion.trim().isEmpty()) {
            sb.append(",\"version\":").append(escapeJson(lastVersion.trim()));
        }
        if (lastDownloadedAt > 0) {
            sb.append(",\"time\":").append(lastDownloadedAt);
        }
        if (lastSha256 != null && !lastSha256.trim().isEmpty()) {
            sb.append(",\"sha256\":").append(escapeJson(lastSha256.trim()));
        }
        if (lastSigFingerprint != null && !lastSigFingerprint.trim().isEmpty()) {
            sb.append(",\"sig\":").append(escapeJson(lastSigFingerprint.trim()));
        }
        if (lastAuthor != null && !lastAuthor.trim().isEmpty()) {
            sb.append(",\"author\":").append(escapeJson(lastAuthor.trim()));
        }
        sb.append("}");
        return sb.toString();
    }

    public static PresetItem fromJson(String jsonOrUrl) {
        if (jsonOrUrl == null) return null;
        String trimmed = jsonOrUrl.trim();
        if (trimmed.isEmpty()) return null;

        // Backwards compatibility with legacy plain URL strings
        if (!trimmed.startsWith("{")) {
            return new PresetItem(trimmed);
        }

        PresetItem item = new PresetItem("");
        item.url = extractJsonString(trimmed, "url");
        item.name = extractJsonString(trimmed, "name");
        if (item.name == null) item.name = "";
        item.lastFileName = extractJsonString(trimmed, "filename");
        item.lastVersion = extractJsonString(trimmed, "version");
        item.lastSha256 = extractJsonString(trimmed, "sha256");
        item.lastSigFingerprint = extractJsonString(trimmed, "sig");
        item.lastAuthor = extractJsonString(trimmed, "author");
        item.lastFileSize = extractJsonLong(trimmed, "size", -1);
        item.lastDownloadedAt = extractJsonLong(trimmed, "time", 0);

        if (item.url == null || item.url.trim().isEmpty()) {
            return null;
        }
        return item;
    }

    private static String extractJsonString(String json, String key) {
        String pattern = "\"" + key + "\":\"";
        int idx = json.indexOf(pattern);
        if (idx == -1) {
            pattern = "\"" + key + "\": \"";
            idx = json.indexOf(pattern);
            if (idx == -1) return null;
        }
        int start = idx + pattern.length();
        StringBuilder sb = new StringBuilder();
        boolean escape = false;
        for (int i = start; i < json.length(); i++) {
            char c = json.charAt(i);
            if (escape) {
                if (c == 'n') sb.append('\n');
                else if (c == 'r') sb.append('\r');
                else if (c == 't') sb.append('\t');
                else sb.append(c);
                escape = false;
            } else if (c == '\\') {
                escape = true;
            } else if (c == '"') {
                return sb.toString();
            } else {
                sb.append(c);
            }
        }
        return null;
    }

    private static long extractJsonLong(String json, String key, long def) {
        String pattern = "\"" + key + "\":";
        int idx = json.indexOf(pattern);
        if (idx == -1) {
            pattern = "\"" + key + "\": ";
            idx = json.indexOf(pattern);
            if (idx == -1) return def;
        }
        int start = idx + pattern.length();
        int end = start;
        while (end < json.length() && (Character.isDigit(json.charAt(end)) || json.charAt(end) == '-')) {
            end++;
        }
        try {
            return Long.parseLong(json.substring(start, end).trim());
        } catch (Exception e) {
            return def;
        }
    }

    private static String escapeJson(String s) {
        if (s == null) return "\"\"";
        StringBuilder sb = new StringBuilder("\"");
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '"') sb.append("\\\"");
            else if (c == '\\') sb.append("\\\\");
            else if (c == '\n') sb.append("\\n");
            else if (c == '\r') sb.append("\\r");
            else if (c == '\t') sb.append("\\t");
            else sb.append(c);
        }
        sb.append("\"");
        return sb.toString();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        PresetItem that = (PresetItem) o;
        return url != null && url.equals(that.url);
    }

    @Override
    public int hashCode() {
        return url != null ? url.hashCode() : 0;
    }
}
