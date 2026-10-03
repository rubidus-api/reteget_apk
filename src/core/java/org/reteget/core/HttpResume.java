package org.reteget.core;

/**
 * Decisions for continuing a download from a partial file (RFC 9110 sections 13.1.5 and 14).
 * Pure functions; the engine does the I/O.
 *
 * <p>A resume is a GET with {@code Range: bytes=N-} and {@code If-Range: <validator>}. The
 * validator is the strong ETag of the first response, or its Last-Modified date. Without either
 * there is no resume: two different files could be spliced together.
 */
final class HttpResume {

    private HttpResume() {}

    /** Append the body to the partial file. */
    static final int APPEND = 1;
    /** The body is the whole file (the server ignored the range or the file changed): start over with it. */
    static final int FULL = 2;
    /** Nothing left to fetch: the partial file already holds the whole file. */
    static final int COMPLETE = 3;
    /** The response cannot be used; drop the partial file and ask again without a range. */
    static final int REREQUEST = 4;

    /** The If-Range value for a response: a strong ETag, else Last-Modified, else null. */
    static String validator(String etag, String lastModified) {
        if (etag != null) {
            String e = etag.trim();
            if (e.length() > 0 && !e.startsWith("W/") && !e.startsWith("w/")) return e;
        }
        if (lastModified != null && lastModified.trim().length() > 0) return lastModified.trim();
        return null;
    }

    /**
     * {@code {first, last, total}} from a Content-Range value such as {@code bytes 100-199/1000};
     * total is -1 for {@code *}. Null when the value is not a byte range.
     */
    static long[] parseContentRange(String v) {
        if (v == null) return null;
        String s = v.trim();
        if (!s.regionMatches(true, 0, "bytes", 0, 5)) return null;
        s = s.substring(5).trim();
        int dash = s.indexOf('-');
        int slash = s.indexOf('/');
        if (dash <= 0 || slash < dash) return null;
        try {
            long first = Long.parseLong(s.substring(0, dash).trim());
            long last = Long.parseLong(s.substring(dash + 1, slash).trim());
            String t = s.substring(slash + 1).trim();
            long total = t.equals("*") ? -1 : Long.parseLong(t);
            if (first < 0 || last < first || (total >= 0 && last >= total)) return null;
            return new long[] { first, last, total };
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * What to do with the response to a range request for bytes from {@code offset} of a file
     * whose size was {@code storedTotal} (-1 when unknown). Returns 0 for any other status, which
     * the caller treats as it would without a range.
     */
    static int decide(long offset, long storedTotal, int code, String contentRange) {
        if (code == 200) return FULL;
        if (code == 206) {
            long[] r = parseContentRange(contentRange);
            if (r == null || r[0] != offset) return REREQUEST;
            if (r[2] < 0) return storedTotal < 0 ? APPEND : REREQUEST;
            if (storedTotal >= 0 && r[2] != storedTotal) return REREQUEST;
            return APPEND;
        }
        if (code == 416) {
            return storedTotal > 0 && offset == storedTotal ? COMPLETE : REREQUEST;
        }
        return 0;
    }
}
