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
    /**
     * Optional page to look for the newest download on (see {@link IndexMatcher}); then
     * {@link #url} is the pattern the addresses on that page must fit. Empty when unused.
     */
    public String index = "";
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

    public boolean hasIndex() {
        return index != null && index.trim().length() > 0;
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
            sb.append("SHA-256 ").append(trimmed.substring(0, Math.min(8, trimmed.length()))).append("…");
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
        if (hasIndex()) {
            sb.append(",\"index\":").append(escapeJson(index.trim()));
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
        item.index = extractJsonString(trimmed, "index");
        if (item.index == null) item.index = "";
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

    static String extractJsonString(String json, String key) {
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

    static long extractJsonLong(String json, String key, long def) {
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

    static String escapeJson(String s) {
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

    /** Version of the built-in preset list; raising it merges the defaults again on upgrade. */
    public static final int DEFAULTS_VERSION = 10;

    /** URL prefix shared by every built-in preset (the rete series on GitHub Releases). */
    public static final String RETE_RELEASES = "https://github.com/rubidus-api/";

    /**
     * Built-in presets: the rete series apps, as version templates on GitHub Releases, each
     * with the release list as its index page so Latest finds the newest version.
     * Metadata is that of the latest release when this list was written, so the checksum
     * and signing-key continuity checks work from the first download. ReteGet's own entry
     * carries only the signing key: a build cannot know its own checksum.
     */
    public static java.util.List<PresetItem> defaults() {
        java.util.List<PresetItem> list = new java.util.ArrayList<PresetItem>();
        list.add(rete("ReteGet", "reteget_apk",
                "reteget_apk/releases/download/v{1}/reteget-{1}.apk",
                "reteget-0.4.0.apk", -1, "0.4.0", 0L, "",
                "9F:98:92:2B:44:4F:3C:51:88:D7:F7:8C:F7:3C:4C:F8:36:0B:DB:B3:98:89:7C:3A:25:58:BF:28:DB:A6:4D:52",
                "ReteGet"));
        list.add(rete("ReteClock", "reteclock_apk",
                "reteclock_apk/releases/download/v{1}/reteclock-{1}.apk",
                "reteclock-0.51.0.apk", 612580, "0.51.0", 1790304417000L,
                "169cc7dd5bfa25fc175873a6d05342147ce9b46e3ef4595d6db98e3a574d84f8",
                "90:44:6B:52:80:AA:4C:E3:4B:FE:8B:33:25:2E:F6:BE:90:2C:74:4D:4F:5A:F2:03:A5:99:5A:4B:BD:4C:64:1D",
                "reteclock"));
        list.add(rete("ReteKey (Android 4.0+)", "retekey_apk",
                "retekey_apk/releases/download/v{1}/retekey-{1}-legacy.apk",
                "retekey-0.2.0-legacy.apk", 573025, "0.2.0", 1790308592000L,
                "a53d0b460fe20838dbdc272e2b8173a521dfe0360dcf550284ed1ce10781ccf7",
                "9E:DF:10:F8:08:8E:6E:EE:CE:98:31:68:7F:DE:92:DC:B7:37:C7:74:F1:D3:9E:C3:7C:59:69:05:AE:02:0C:35",
                "ReteKey"));
        list.add(rete("ReteKey (Android 9+)", "retekey_apk",
                "retekey_apk/releases/download/v{1}/retekey-{1}.apk",
                "retekey-0.2.0.apk", 713865, "0.2.0", 1790308592000L,
                "9d63f8df6e8683241c781a68d2d88be095f9784e5171c002e46b303a9ffc5b16",
                "9E:DF:10:F8:08:8E:6E:EE:CE:98:31:68:7F:DE:92:DC:B7:37:C7:74:F1:D3:9E:C3:7C:59:69:05:AE:02:0C:35",
                "ReteKey"));
        return list;
    }

    /** GitHub's releases API lists every asset's full address; the release pages load them later. */
    static String releasesIndex(String repo) {
        return "https://api.github.com/repos/rubidus-api/" + repo + "/releases?per_page=20";
    }

    private static PresetItem rete(String name, String repo, String path, String file, long size,
                                   String version, long time, String sha256, String signer, String author) {
        PresetItem p = new PresetItem(name, RETE_RELEASES + path, file, size, version, time, sha256, signer, author);
        p.index = releasesIndex(repo);
        return p;
    }

    /**
     * Upgrades a stored preset list to the current defaults: built-in rete presets are
     * replaced by the current ones and listed first; every preset the user added is kept,
     * in its original order.
     */
    public static java.util.List<PresetItem> mergeDefaults(java.util.List<PresetItem> stored) {
        java.util.List<PresetItem> merged = defaults();
        for (PresetItem p : stored) {
            if (p == null || isBuiltIn(p) || merged.contains(p)) {
                continue;
            }
            merged.add(p);
        }
        return merged;
    }

    /** True for presets written by an earlier built-in list (GitHub rete release templates). */
    static boolean isBuiltIn(PresetItem p) {
        String u = p.url == null ? "" : p.url;
        return u.startsWith(RETE_RELEASES) && u.contains("{1}")
                && (u.contains("/reteget_apk/") || u.contains("/reteclock_apk/") || u.contains("/retekey_apk/"));
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
