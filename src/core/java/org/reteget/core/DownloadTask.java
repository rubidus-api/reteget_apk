package org.reteget.core;

/**
 * One entry of the download queue: what to fetch, how, and what happened.
 * Fields are written by {@link DownloadQueue} under its lock; the UI reads snapshots.
 */
public final class DownloadTask {

    public enum State { QUEUED, RUNNING, DONE, FAILED, CANCELLED }

    public final long id;
    public final String url;
    public final String destDir;
    public final boolean insecure;
    public final boolean forceBuiltInTls;
    /** Checksum the user expected when queueing (may be empty). */
    public final String expectedChecksum;
    public final long createdAt;
    /** URL template (or plain URL) and version the user had entered, for preset records. */
    public String template;
    public String version;
    /** After completion: whether the checks ran, the file's SHA-256, and what they found. */
    public boolean verified;
    public String sha256;
    /** Null when the checks passed; otherwise WARN_* values joined by ','. */
    public String warning;

    public static final String WARN_CHECKSUM = "checksum";
    public static final String WARN_SIGNATURE = "signature";
    public static final String WARN_MISSING = "missing";

    public State state = State.QUEUED;
    public String fileName;
    public String filePath;
    public long bytesDone;
    public long bytesTotal = -1;
    public long bytesPerSec;
    public String error;
    public String tlsSummary;
    public long finishedAt;

    public DownloadTask(long id, String url, String destDir, boolean insecure, boolean forceBuiltInTls,
                        String expectedChecksum, long createdAt) {
        this.id = id;
        this.url = url;
        this.destDir = destDir;
        this.insecure = insecure;
        this.forceBuiltInTls = forceBuiltInTls;
        this.expectedChecksum = expectedChecksum == null ? "" : expectedChecksum;
        this.createdAt = createdAt;
    }

    public boolean hasWarning(String kind) {
        return warning != null && ("," + warning + ",").contains("," + kind + ",");
    }

    public boolean isActive() {
        return state == State.QUEUED || state == State.RUNNING;
    }

    /** Progress in percent, or -1 when the size is unknown. */
    public int percent() {
        if (state == State.DONE) return 100;
        if (bytesTotal <= 0) return -1;
        return (int) Math.min(100, bytesDone * 100 / bytesTotal);
    }

    /** Name to show: the file name once known, otherwise the last path segment of the URL. */
    public String displayName() {
        if (fileName != null && !fileName.isEmpty()) return fileName;
        String u = url;
        int q = u.indexOf('?');
        if (q >= 0) u = u.substring(0, q);
        int slash = u.lastIndexOf('/');
        return slash >= 0 && slash < u.length() - 1 ? u.substring(slash + 1) : url;
    }

    DownloadTask copy() {
        DownloadTask t = new DownloadTask(id, url, destDir, insecure, forceBuiltInTls, expectedChecksum, createdAt);
        t.state = state;
        t.fileName = fileName;
        t.filePath = filePath;
        t.bytesDone = bytesDone;
        t.bytesTotal = bytesTotal;
        t.bytesPerSec = bytesPerSec;
        t.error = error;
        t.tlsSummary = tlsSummary;
        t.finishedAt = finishedAt;
        t.template = template;
        t.version = version;
        t.verified = verified;
        t.sha256 = sha256;
        t.warning = warning;
        return t;
    }

    String toJson() {
        StringBuilder sb = new StringBuilder("{");
        sb.append("\"id\":").append(id);
        sb.append(",\"url\":").append(PresetItem.escapeJson(url));
        sb.append(",\"dir\":").append(PresetItem.escapeJson(destDir));
        sb.append(",\"insecure\":").append(insecure ? 1 : 0);
        sb.append(",\"tls\":").append(forceBuiltInTls ? 1 : 0);
        sb.append(",\"expected\":").append(PresetItem.escapeJson(expectedChecksum));
        sb.append(",\"created\":").append(createdAt);
        sb.append(",\"state\":").append(PresetItem.escapeJson(state.name()));
        if (fileName != null) sb.append(",\"file\":").append(PresetItem.escapeJson(fileName));
        if (filePath != null) sb.append(",\"path\":").append(PresetItem.escapeJson(filePath));
        sb.append(",\"done\":").append(bytesDone);
        sb.append(",\"total\":").append(bytesTotal);
        if (error != null) sb.append(",\"error\":").append(PresetItem.escapeJson(error));
        if (tlsSummary != null) sb.append(",\"tlsinfo\":").append(PresetItem.escapeJson(tlsSummary));
        sb.append(",\"finished\":").append(finishedAt);
        if (template != null) sb.append(",\"template\":").append(PresetItem.escapeJson(template));
        if (version != null) sb.append(",\"version\":").append(PresetItem.escapeJson(version));
        sb.append(",\"verified\":").append(verified ? 1 : 0);
        if (sha256 != null) sb.append(",\"sha\":").append(PresetItem.escapeJson(sha256));
        if (warning != null) sb.append(",\"warn\":").append(PresetItem.escapeJson(warning));
        return sb.append("}").toString();
    }

    static DownloadTask fromJson(String json) {
        if (json == null || !json.trim().startsWith("{")) return null;
        String url = PresetItem.extractJsonString(json, "url");
        String dir = PresetItem.extractJsonString(json, "dir");
        long id = PresetItem.extractJsonLong(json, "id", -1);
        if (url == null || dir == null || id < 0) return null;
        DownloadTask t = new DownloadTask(id, url, dir,
                PresetItem.extractJsonLong(json, "insecure", 0) == 1,
                PresetItem.extractJsonLong(json, "tls", 0) == 1,
                PresetItem.extractJsonString(json, "expected"),
                PresetItem.extractJsonLong(json, "created", 0));
        String state = PresetItem.extractJsonString(json, "state");
        try {
            t.state = State.valueOf(state);
        } catch (Exception e) {
            t.state = State.FAILED;
        }
        t.fileName = PresetItem.extractJsonString(json, "file");
        t.filePath = PresetItem.extractJsonString(json, "path");
        t.bytesDone = PresetItem.extractJsonLong(json, "done", 0);
        t.bytesTotal = PresetItem.extractJsonLong(json, "total", -1);
        t.error = PresetItem.extractJsonString(json, "error");
        t.tlsSummary = PresetItem.extractJsonString(json, "tlsinfo");
        t.finishedAt = PresetItem.extractJsonLong(json, "finished", 0);
        t.template = PresetItem.extractJsonString(json, "template");
        t.version = PresetItem.extractJsonString(json, "version");
        t.verified = PresetItem.extractJsonLong(json, "verified", 0) == 1;
        t.sha256 = PresetItem.extractJsonString(json, "sha");
        t.warning = PresetItem.extractJsonString(json, "warn");
        return t;
    }
}
