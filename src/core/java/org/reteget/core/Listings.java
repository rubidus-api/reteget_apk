package org.reteget.core;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Reads folder listings into {@link RemoteEntry} lists: FTP MLSD (RFC 3659) and LIST (Unix
 * {@code ls -l} and Windows/IIS styles), WebDAV PROPFIND answers (RFC 4918, 207 Multi-Status) and
 * the HTML index pages of nginx, Apache and the like. Entries are always direct children of the
 * folder; "." and ".." and anything pointing elsewhere are left out.
 */
public final class Listings {

    private Listings() {}

    /** Most entries one listing may give; longer listings are an error (old phones have little memory). */
    public static final int MAX_ENTRIES = 10000;

    // --- addresses ---

    /** A folder address ends in '/'. */
    public static String asFolder(String url) {
        return url.endsWith("/") ? url : url + "/";
    }

    /** The address of the folder an address is in (for a folder: the folder itself). */
    public static String folderOf(String url) {
        if (url.endsWith("/")) return url;
        int q = url.indexOf('?');
        String base = q >= 0 ? url.substring(0, q) : url;
        int slash = base.lastIndexOf('/');
        int scheme = base.indexOf("://");
        if (slash < 0 || slash < scheme + 3) return base + "/";
        return base.substring(0, slash + 1);
    }

    /** The parent folder of a folder address, or null at the top. */
    public static String parentOf(String folderUrl) {
        int scheme = folderUrl.indexOf("://");
        int pathStart = folderUrl.indexOf('/', scheme < 0 ? 0 : scheme + 3);
        if (pathStart < 0) return null;
        String path = folderUrl.substring(pathStart);
        if (path.equals("/") || path.equals("/~/")) return null;
        String trimmed = folderUrl.substring(0, folderUrl.length() - 1);
        return trimmed.substring(0, trimmed.lastIndexOf('/') + 1);
    }

    /** The address of {@code name} in {@code folderUrl} (which ends in '/'). */
    public static String child(String folderUrl, String name, boolean directory) {
        return folderUrl + encodeSegment(name) + (directory ? "/" : "");
    }

    /** A path segment percent-encoded as UTF-8 (RFC 3986 unreserved characters stay). */
    public static String encodeSegment(String name) {
        byte[] b;
        try {
            b = name.getBytes("UTF-8");
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
        StringBuilder sb = new StringBuilder();
        for (byte x : b) {
            int c = x & 0xff;
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
                    || c == '-' || c == '.' || c == '_' || c == '~' || c == '+' || c == '(' || c == ')'
                    || c == '!' || c == '\'' || c == '*' || c == ',' || c == ';' || c == '=' || c == '@' || c == '&' || c == '$') {
                sb.append((char) c);
            } else {
                sb.append('%').append(Character.toUpperCase(Character.forDigit(c >> 4, 16)))
                        .append(Character.toUpperCase(Character.forDigit(c & 15, 16)));
            }
        }
        return sb.toString();
    }

    /** A name that can be a file or folder name here: not empty, not "." or "..", no '/' or control characters. */
    static boolean usableName(String name) {
        if (name == null || name.length() == 0 || name.equals(".") || name.equals("..")) return false;
        for (int i = 0; i < name.length(); i++) {
            char c = name.charAt(i);
            if (c == '/' || c < 0x20 || c == 0x7f) return false;
        }
        return true;
    }

    private static void add(List<RemoteEntry> out, Set<String> seen, String folderUrl, String name, boolean dir,
                            long size, long modified) throws java.io.IOException {
        if (!usableName(name) || !seen.add(name)) return;
        if (out.size() >= MAX_ENTRIES) throw new java.io.IOException("The folder lists more than " + MAX_ENTRIES + " entries");
        out.add(new RemoteEntry(name, dir, dir ? -1 : size, modified, child(folderUrl, name, dir)));
    }

    // --- FTP ---

    private static final Pattern MLSD_TIME = Pattern.compile("(\\d{14})");

    /** MLSD lines ("type=file;size=12;modify=20260101120000; name"). */
    public static List<RemoteEntry> parseMlsd(String text, String folderUrl) throws java.io.IOException {
        List<RemoteEntry> out = new ArrayList<RemoteEntry>();
        Set<String> seen = new HashSet<String>();
        for (String line : text.split("\r?\n")) {
            int sp = line.indexOf(' ');
            if (sp < 0) continue;
            String facts = line.substring(0, sp).toLowerCase(Locale.US);
            String name = line.substring(sp + 1);
            String type = null;
            long size = -1;
            long modified = 0;
            for (String f : facts.split(";")) {
                int eq = f.indexOf('=');
                if (eq < 0) continue;
                String k = f.substring(0, eq);
                String v = f.substring(eq + 1);
                if (k.equals("type")) {
                    type = v;
                } else if (k.equals("size") || (k.equals("sizd") && size < 0)) {
                    size = parseLong(v);
                } else if (k.equals("modify")) {
                    Matcher m = MLSD_TIME.matcher(v);
                    if (m.find()) modified = parseUtc(m.group(1), "yyyyMMddHHmmss");
                }
            }
            if (type == null || type.equals("cdir") || type.equals("pdir")) continue;
            boolean dir = type.equals("dir") || type.endsWith("=dir");
            boolean link = type.contains("symlink") || type.contains("slink");
            if (!dir && !type.equals("file") && !link) continue; // devices, sockets
            add(out, seen, folderUrl, name, dir, size, modified);
        }
        return out;
    }

    private static final String MONTHS = "jan feb mar apr may jun jul aug sep oct nov dec";
    private static final Pattern UNIX_LIST = Pattern.compile(
            "^([-dlDL])[-rwxsStTlL]{9}\\S*\\s+.*?(\\d+)\\s+(\\w{3})\\s+(\\d{1,2})\\s+(\\d{1,2}:\\d{2}|\\d{4})\\s(.+)$");
    private static final Pattern WINDOWS_LIST = Pattern.compile(
            "^(\\d{2})-(\\d{2})-(\\d{2}|\\d{4})\\s+(\\d{1,2}):(\\d{2})\\s*([AaPp][Mm])?\\s+(<DIR>|\\d+)\\s+(.+)$");

    /**
     * LIST lines in the Unix ("-rw-r--r-- 1 user group 123 Jan 02 2026 name") or Windows
     * ("01-02-26  03:04PM  &lt;DIR&gt;  name") style; other lines are left out.
     *
     * @param now the time to complete Unix dates without a year with (they are within the last year)
     */
    public static List<RemoteEntry> parseList(String text, String folderUrl, long now) throws java.io.IOException {
        List<RemoteEntry> out = new ArrayList<RemoteEntry>();
        Set<String> seen = new HashSet<String>();
        for (String line : text.split("\r?\n")) {
            Matcher m = UNIX_LIST.matcher(line);
            if (m.matches()) {
                int month = MONTHS.indexOf(m.group(3).toLowerCase(Locale.US));
                if (month < 0 || month % 4 != 0) continue;
                char type = Character.toLowerCase(m.group(1).charAt(0));
                String name = m.group(6);
                if (type == 'l') {
                    int arrow = name.indexOf(" -> ");
                    if (arrow > 0) name = name.substring(0, arrow);
                }
                add(out, seen, folderUrl, name, type == 'd', parseLong(m.group(2)),
                        unixTime(month / 4, Integer.parseInt(m.group(4)), m.group(5), now));
                continue;
            }
            m = WINDOWS_LIST.matcher(line);
            if (m.matches()) {
                int year = Integer.parseInt(m.group(3));
                if (year < 100) year += year < 70 ? 2000 : 1900;
                int hour = Integer.parseInt(m.group(4)) % 12;
                if (m.group(6) == null) hour = Integer.parseInt(m.group(4));
                else if (m.group(6).toLowerCase(Locale.US).equals("pm")) hour += 12;
                Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"), Locale.US);
                c.clear();
                c.set(year, Integer.parseInt(m.group(1)) - 1, Integer.parseInt(m.group(2)), hour, Integer.parseInt(m.group(5)));
                boolean dir = m.group(7).equals("<DIR>");
                add(out, seen, folderUrl, m.group(8), dir, dir ? -1 : parseLong(m.group(7)), c.getTimeInMillis());
            }
        }
        return out;
    }

    private static long unixTime(int month, int day, String yearOrTime, long now) {
        Calendar c = Calendar.getInstance(TimeZone.getTimeZone("UTC"), Locale.US);
        c.clear();
        if (yearOrTime.indexOf(':') < 0) {
            c.set(Integer.parseInt(yearOrTime), month, day);
            return c.getTimeInMillis();
        }
        int colon = yearOrTime.indexOf(':');
        Calendar n = Calendar.getInstance(TimeZone.getTimeZone("UTC"), Locale.US);
        n.setTimeInMillis(now);
        c.set(n.get(Calendar.YEAR), month, day, Integer.parseInt(yearOrTime.substring(0, colon)),
                Integer.parseInt(yearOrTime.substring(colon + 1)));
        if (c.getTimeInMillis() > now + 24L * 3600 * 1000) c.add(Calendar.YEAR, -1);
        return c.getTimeInMillis();
    }

    // --- WebDAV ---

    /** The PROPFIND request body: the four properties a listing needs. */
    public static final String PROPFIND_BODY = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            + "<D:propfind xmlns:D=\"DAV:\"><D:prop><D:resourcetype/><D:getcontentlength/>"
            + "<D:getlastmodified/></D:prop></D:propfind>\n";

    /** A 207 Multi-Status answer to PROPFIND with Depth 1 on {@code folderUrl}. */
    public static List<RemoteEntry> parseDav(String xml, String folderUrl) throws java.io.IOException {
        List<RemoteEntry> out = new ArrayList<RemoteEntry>();
        Set<String> seen = new HashSet<String>();
        String fp = pathOf(stripUserInfo(folderUrl));
        String folderPath = trimSlash(fp == null ? "" : HttpAuth.percentDecode(fp));
        MiniXml x = new MiniXml(xml);
        String href = null;
        boolean collection = false;
        long size = -1;
        long modified = 0;
        boolean inResponse = false;
        StringBuilder text = new StringBuilder();
        int ev;
        while ((ev = x.next()) != MiniXml.END_DOCUMENT) {
            if (ev == MiniXml.START) {
                String n = x.name();
                text.setLength(0);
                if (n.equals("response")) {
                    inResponse = true;
                    href = null;
                    collection = false;
                    size = -1;
                    modified = 0;
                } else if (n.equals("collection") && inResponse) {
                    collection = true;
                }
            } else if (ev == MiniXml.TEXT) {
                text.append(x.text());
            } else if (ev == MiniXml.END) {
                String n = x.name();
                String t = text.toString().trim();
                if (!inResponse) continue;
                if (n.equals("href") && href == null) {
                    href = t;
                } else if (n.equals("getcontentlength")) {
                    size = parseLong(t);
                } else if (n.equals("getlastmodified")) {
                    modified = parseHttpDate(t);
                } else if (n.equals("response")) {
                    inResponse = false;
                    if (href == null) continue;
                    String path = pathOf(href);
                    if (path == null) continue;
                    String p = trimSlash(HttpAuth.percentDecode(path));
                    if (p.equals(folderPath) || p.length() <= folderPath.length() || !p.startsWith(folderPath + "/")) continue;
                    String name = p.substring(folderPath.length() + 1);
                    if (name.indexOf('/') >= 0) continue; // not a direct child
                    add(out, seen, folderUrl, name, collection || path.endsWith("/"), size, modified);
                }
                text.setLength(0);
            }
        }
        return out;
    }

    /** The decoded path of an absolute address or of a path; null when there is none. */
    private static String pathOf(String urlOrPath) {
        if (urlOrPath.startsWith("/")) {
            int q = urlOrPath.indexOf('?');
            return q >= 0 ? urlOrPath.substring(0, q) : urlOrPath;
        }
        try {
            String p = new URI(urlOrPath).getRawPath();
            return p == null || p.length() == 0 ? "/" : p;
        } catch (Exception e) {
            return null;
        }
    }

    private static String trimSlash(String p) {
        if (p == null) return "";
        while (p.endsWith("/")) p = p.substring(0, p.length() - 1);
        return p;
    }

    // --- HTML index pages ---

    /** The links of an HTML index page that name entries of {@code folderUrl}. */
    public static List<RemoteEntry> parseHtmlIndex(String page, String folderUrl) throws java.io.IOException {
        List<RemoteEntry> out = new ArrayList<RemoteEntry>();
        Set<String> seen = new HashSet<String>();
        URI base;
        try {
            base = new URI(stripUserInfo(folderUrl));
        } catch (Exception e) {
            return out;
        }
        String folderPath = trimSlash(HttpAuth.percentDecode(base.getRawPath() == null ? "/" : base.getRawPath()));
        Matcher m = IndexMatcher.LINK.matcher(page);
        while (m.find()) {
            String href = m.group(1) != null ? m.group(1) : m.group(2) != null ? m.group(2) : m.group(3);
            href = unescapeHtml(href.trim());
            if (href.length() == 0 || href.startsWith("?") || href.startsWith("#")) continue;
            URI u;
            try {
                u = base.resolve(new URI(href.replace(" ", "%20")));
            } catch (Exception e) {
                continue;
            }
            if (u.getRawQuery() != null || u.getScheme() == null || !u.getScheme().equalsIgnoreCase(base.getScheme())
                    || u.getHost() == null || !u.getHost().equalsIgnoreCase(base.getHost()) || port(u) != port(base)) {
                continue;
            }
            String raw = u.getRawPath();
            if (raw == null) continue;
            String p = trimSlash(HttpAuth.percentDecode(raw));
            if (!p.startsWith(folderPath + "/")) continue;
            String name = p.substring(folderPath.length() + 1);
            if (name.indexOf('/') >= 0) continue;
            add(out, seen, folderUrl, name, raw.endsWith("/"), -1, 0);
        }
        return out;
    }

    private static int port(URI u) {
        if (u.getPort() >= 0) return u.getPort();
        return "https".equalsIgnoreCase(u.getScheme()) ? 443 : 80;
    }

    static String stripUserInfo(String url) {
        int scheme = url.indexOf("://");
        if (scheme < 0) return url;
        int end = url.indexOf('/', scheme + 3);
        String authority = end < 0 ? url.substring(scheme + 3) : url.substring(scheme + 3, end);
        int at = authority.lastIndexOf('@');
        if (at < 0) return url;
        return url.substring(0, scheme + 3) + authority.substring(at + 1) + (end < 0 ? "" : url.substring(end));
    }

    private static String unescapeHtml(String s) {
        return s.replace("&amp;", "&").replace("&quot;", "\"").replace("&#39;", "'").replace("&lt;", "<").replace("&gt;", ">");
    }

    // --- shared ---

    private static long parseLong(String s) {
        try {
            return Long.parseLong(s.trim());
        } catch (Exception e) {
            return -1;
        }
    }

    private static long parseUtc(String s, String pattern) {
        try {
            SimpleDateFormat f = new SimpleDateFormat(pattern, Locale.US);
            f.setTimeZone(TimeZone.getTimeZone("UTC"));
            return f.parse(s).getTime();
        } catch (ParseException e) {
            return 0;
        }
    }

    /** An RFC 1123 date ("Sun, 06 Nov 1994 08:49:37 GMT"), 0 when it is not one. */
    static long parseHttpDate(String s) {
        long t = parseUtc(s, "EEE, dd MMM yyyy HH:mm:ss zzz");
        return t != 0 ? t : parseUtc(s, "dd MMM yyyy HH:mm:ss zzz");
    }

    /**
     * Just enough XML for a WebDAV answer: elements (namespace prefixes dropped), text with the
     * predefined and numeric entities, CDATA; comments, processing instructions and DOCTYPE are
     * skipped. Not a validating parser: it never fails, it reads what it can.
     */
    static final class MiniXml {
        static final int START = 1;
        static final int END = 2;
        static final int TEXT = 3;
        static final int END_DOCUMENT = 4;

        private final String s;
        private int pos;
        private String name;
        private String text;
        private String pendingEnd;

        MiniXml(String s) {
            this.s = s;
        }

        String name() {
            return name;
        }

        String text() {
            return text;
        }

        int next() {
            if (pendingEnd != null) {
                name = pendingEnd;
                pendingEnd = null;
                return END;
            }
            while (pos < s.length()) {
                if (s.charAt(pos) != '<') {
                    int lt = s.indexOf('<', pos);
                    if (lt < 0) lt = s.length();
                    text = entities(s.substring(pos, lt));
                    pos = lt;
                    return TEXT;
                }
                if (s.startsWith("<!--", pos)) {
                    pos = skipPast("-->", pos + 4);
                } else if (s.startsWith("<![CDATA[", pos)) {
                    int end = s.indexOf("]]>", pos + 9);
                    if (end < 0) end = s.length();
                    text = s.substring(pos + 9, end);
                    pos = Math.min(s.length(), end + 3);
                    return TEXT;
                } else if (s.startsWith("<?", pos)) {
                    pos = skipPast("?>", pos + 2);
                } else if (s.startsWith("<!", pos)) {
                    pos = skipPast(">", pos + 2);
                } else {
                    int gt = s.indexOf('>', pos);
                    if (gt < 0) {
                        pos = s.length();
                        break;
                    }
                    String tag = s.substring(pos + 1, gt).trim();
                    pos = gt + 1;
                    boolean end = tag.startsWith("/");
                    boolean empty = tag.endsWith("/");
                    if (end) tag = tag.substring(1);
                    if (empty) tag = tag.substring(0, tag.length() - 1);
                    int sp = 0;
                    while (sp < tag.length() && !Character.isWhitespace(tag.charAt(sp))) sp++;
                    String qname = tag.substring(0, sp);
                    int colon = qname.indexOf(':');
                    name = (colon >= 0 ? qname.substring(colon + 1) : qname).toLowerCase(Locale.US);
                    if (end) return END;
                    if (empty) pendingEnd = name;
                    return START;
                }
            }
            return END_DOCUMENT;
        }

        private int skipPast(String end, int from) {
            int i = s.indexOf(end, from);
            return i < 0 ? s.length() : i + end.length();
        }

        private static String entities(String t) {
            if (t.indexOf('&') < 0) return t;
            StringBuilder sb = new StringBuilder();
            int i = 0;
            while (i < t.length()) {
                char c = t.charAt(i);
                int semi = c == '&' ? t.indexOf(';', i) : -1;
                if (semi < 0 || semi - i > 10) {
                    sb.append(c);
                    i++;
                    continue;
                }
                String e = t.substring(i + 1, semi);
                if (e.equals("amp")) sb.append('&');
                else if (e.equals("lt")) sb.append('<');
                else if (e.equals("gt")) sb.append('>');
                else if (e.equals("quot")) sb.append('"');
                else if (e.equals("apos")) sb.append('\'');
                else if (e.startsWith("#")) {
                    try {
                        int cp = e.startsWith("#x") || e.startsWith("#X") ? Integer.parseInt(e.substring(2), 16) : Integer.parseInt(e.substring(1));
                        sb.append(new String(Character.toChars(cp)));
                    } catch (Exception ex) {
                        sb.append(t, i, semi + 1);
                    }
                } else {
                    sb.append(t, i, semi + 1);
                }
                i = semi + 1;
            }
            return sb.toString();
        }
    }
}
