package org.reteget.core;

import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Finds the newest download on an index page: every address on the page that fits a URL pattern,
 * sorted the way Windows Explorer sorts names, and the last one taken.
 *
 * <p><b>Pattern.</b> The preset's URL, where {@code {1}} (or any {@code {name}}) stands for a
 * version: a run of digits, letters, dots and underscores that begins with a digit. A dash ends
 * it, so {@code app-{1}.apk} does not take {@code app-1.0-legacy.apk}. A name used twice must be
 * the same text both times. {@code *} stands for any text within one path segment.
 *
 * <p><b>Page.</b> Any text: an HTML directory listing (relative links are resolved against the
 * page address), or JSON such as the GitHub releases API, whose {@code browser_download_url}
 * values are absolute addresses.
 */
public final class IndexMatcher {

    private static final Pattern TOKEN = Pattern.compile("\\{([A-Za-z0-9_]+)\\}|\\*");
    private static final Pattern LINK = Pattern.compile(
            "(?:href|src)\\s*=\\s*(?:\"([^\"]*)\"|'([^']*)'|([^\\s>]+))", Pattern.CASE_INSENSITIVE);
    /** What may follow the end of an address in running text. */
    private static final String END = "(?=$|[\\s\"'<>)\\],;])";

    public static final class Match {
        public final String url;
        /** Text taken by the first placeholder, or null when the pattern has none. */
        public final String version;

        Match(String url, String version) {
            this.url = url;
            this.version = version;
        }
    }

    private IndexMatcher() {}

    /** Regex for a whole address matching the pattern. */
    static Pattern compile(String urlPattern) {
        StringBuilder re = new StringBuilder();
        Map<String, Integer> groups = new LinkedHashMap<String, Integer>();
        Matcher m = TOKEN.matcher(urlPattern);
        int last = 0;
        while (m.find()) {
            re.append(Pattern.quote(urlPattern.substring(last, m.start())));
            String name = m.group(1);
            if (name == null) {
                re.append("[^/\\s\"'<>?#]*");
            } else if (groups.containsKey(name)) {
                re.append('\\').append(groups.get(name));
            } else {
                groups.put(name, groups.size() + 1);
                re.append("([0-9][0-9A-Za-z._]*)");
            }
            last = m.end();
        }
        re.append(Pattern.quote(urlPattern.substring(last)));
        return Pattern.compile(re.toString());
    }

    /** Every distinct address on the page that fits the pattern, in page order. */
    public static List<Match> findAll(String page, String pageUrl, String urlPattern) {
        List<Match> out = new ArrayList<Match>();
        if (page == null || urlPattern == null || urlPattern.trim().length() == 0) return out;
        Pattern whole = compile(urlPattern.trim());
        // JSON may write "/" as "\/", HTML writes "&" as "&amp;".
        String text = page.replace("\\/", "/");
        Map<String, Match> seen = new LinkedHashMap<String, Match>();

        Matcher m = Pattern.compile(whole.pattern() + END).matcher(text);
        while (m.find()) {
            add(seen, m.group().replace("&amp;", "&"), whole);
        }

        URL base = null;
        try {
            base = pageUrl == null ? null : new URL(pageUrl);
        } catch (Exception ignored) {
        }
        Matcher link = LINK.matcher(text);
        while (link.find()) {
            String href = link.group(1) != null ? link.group(1)
                    : link.group(2) != null ? link.group(2) : link.group(3);
            href = href.replace("&amp;", "&").trim();
            if (href.length() == 0) continue;
            try {
                add(seen, base != null ? new URL(base, href).toString() : href, whole);
            } catch (Exception ignored) {
            }
        }
        out.addAll(seen.values());
        return out;
    }

    private static void add(Map<String, Match> seen, String url, Pattern whole) {
        if (seen.containsKey(url)) return;
        Matcher m = whole.matcher(url);
        if (!m.matches()) return;
        seen.put(url, new Match(url, m.groupCount() > 0 ? m.group(1) : null));
    }

    /** The address that sorts last (Windows order), or null when nothing on the page fits. */
    public static Match latest(String page, String pageUrl, String urlPattern) {
        List<Match> all = findAll(page, pageUrl, urlPattern);
        if (all.isEmpty()) return null;
        Collections.sort(all, new Comparator<Match>() {
            @Override
            public int compare(Match a, Match b) {
                return naturalCompare(a.url, b.url);
            }
        });
        return all.get(all.size() - 1);
    }

    /**
     * Windows Explorer order (StrCmpLogicalW): runs of digits compare by value, everything else
     * by character, ignoring case. So 0.3.9 comes before 0.3.10, and file2 before File10.
     */
    public static int naturalCompare(String a, String b) {
        int i = 0, j = 0;
        while (i < a.length() && j < b.length()) {
            char ca = a.charAt(i), cb = b.charAt(j);
            if (isDigit(ca) && isDigit(cb)) {
                int si = i, sj = j;
                while (i < a.length() && isDigit(a.charAt(i))) i++;
                while (j < b.length() && isDigit(b.charAt(j))) j++;
                String da = stripZeros(a.substring(si, i));
                String db = stripZeros(b.substring(sj, j));
                if (da.length() != db.length()) return da.length() < db.length() ? -1 : 1;
                int c = da.compareTo(db);
                if (c != 0) return c;
                // Same value: fewer leading zeros first, as Explorer does.
                if (i - si != j - sj) return (i - si) < (j - sj) ? -1 : 1;
                continue;
            }
            char la = Character.toLowerCase(ca), lb = Character.toLowerCase(cb);
            if (la != lb) return la < lb ? -1 : 1;
            i++;
            j++;
        }
        int restA = a.length() - i, restB = b.length() - j;
        return restA == restB ? 0 : restA < restB ? -1 : 1;
    }

    private static boolean isDigit(char c) {
        return c >= '0' && c <= '9';
    }

    private static String stripZeros(String d) {
        int k = 0;
        while (k < d.length() - 1 && d.charAt(k) == '0') k++;
        return d.substring(k);
    }
}
