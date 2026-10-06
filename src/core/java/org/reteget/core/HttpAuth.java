package org.reteget.core;

import java.io.ByteArrayOutputStream;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * HTTP authentication for the download engine: Basic (RFC 7617) and Digest (RFC 7616, MD5 and
 * SHA-256, plain and -sess, qop=auth or none), answered only after a 401 challenge. Also the
 * handling of credentials written into a URL ({@code http://user:pass@host/...}): reading them,
 * removing them before a request, and masking the password wherever a URL is shown.
 *
 * <p>Pure functions with no Android dependency, so they run in the JVM tests. No
 * {@code java.util.Base64} (API 26) and nothing else newer than Android 2.3.
 */
public final class HttpAuth {

    private HttpAuth() {}

    /** A user name and password taken from a URL. */
    public static final class Credentials {
        public final String user;
        public final String password;

        public Credentials(String user, String password) {
            this.user = user;
            this.password = password;
        }
    }

    private static final Pattern URL_PASSWORD =
            Pattern.compile("([a-zA-Z][a-zA-Z0-9+.-]*://[^/?#@\\s:]*):[^/?#@\\s]*@");

    /** {@code text} with the password of every URL in it replaced by {@code ***}. */
    public static String mask(String text) {
        if (text == null || text.indexOf('@') < 0) return text;
        return URL_PASSWORD.matcher(text).replaceAll("$1:***@");
    }

    /** {@code text} with the password of every URL in it removed (the user name stays). */
    public static String stripPasswords(String text) {
        if (text == null || text.indexOf('@') < 0) return text;
        return URL_PASSWORD.matcher(text).replaceAll("$1@");
    }

    /** The credentials in {@code url}'s user info, percent-decoded, or null when there are none. */
    public static Credentials credentials(URL url) {
        return credentials(url.getUserInfo());
    }

    /** The credentials in a raw (still percent-encoded) user info, or null when it is empty. */
    public static Credentials credentials(String info) {
        if (info == null || info.length() == 0) return null;
        int colon = info.indexOf(':');
        String user = colon >= 0 ? info.substring(0, colon) : info;
        String pass = colon >= 0 ? info.substring(colon + 1) : "";
        return new Credentials(percentDecode(user), percentDecode(pass));
    }

    /** {@code url} without user info or fragment; what goes on the wire. */
    public static URL withoutUserInfo(URL url) throws MalformedURLException {
        if (url.getUserInfo() == null && url.getRef() == null) return url;
        return new URL(url.getProtocol(), url.getHost(), url.getPort(), url.getFile());
    }

    /** scheme://host:port with the default port spelled out, lower case; credentials stay within one. */
    public static String origin(URL url) {
        int port = url.getPort() >= 0 ? url.getPort() : url.getDefaultPort();
        return url.getProtocol().toLowerCase(Locale.US) + "://" + url.getHost().toLowerCase(Locale.US) + ":" + port;
    }

    /** The request-target of a GET for {@code url}: path and query, "/" when empty. */
    public static String requestTarget(URL url) {
        String file = url.getFile();
        return file == null || file.length() == 0 ? "/" : file;
    }

    /** %XX sequences decoded as UTF-8; '+' stays '+' (unlike URLDecoder). */
    public static String percentDecode(String s) {
        if (s.indexOf('%') < 0) return s;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            for (int i = 0; i < s.length(); i++) {
                char c = s.charAt(i);
                if (c == '%' && i + 2 < s.length() && hexVal(s.charAt(i + 1)) >= 0 && hexVal(s.charAt(i + 2)) >= 0) {
                    out.write(hexVal(s.charAt(i + 1)) * 16 + hexVal(s.charAt(i + 2)));
                    i += 2;
                } else {
                    byte[] b = String.valueOf(c).getBytes("UTF-8");
                    out.write(b, 0, b.length);
                }
            }
            return new String(out.toByteArray(), "UTF-8");
        } catch (UnsupportedEncodingException e) {
            return s;
        }
    }

    private static int hexVal(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    }

    // --- Challenges ---

    /** One challenge of a WWW-Authenticate header: the scheme (lower case) and its parameters. */
    static final class Challenge {
        final String scheme;
        final Map<String, String> params = new HashMap<String, String>();

        Challenge(String scheme) {
            this.scheme = scheme;
        }

        String param(String name) {
            return params.get(name);
        }
    }

    /** Every challenge in the given WWW-Authenticate header values (RFC 7235 section 4.1). */
    static List<Challenge> parseChallenges(List<String> headerValues) {
        List<Challenge> out = new ArrayList<Challenge>();
        if (headerValues == null) return out;
        for (String h : headerValues) {
            if (h != null) parseInto(h, out);
        }
        return out;
    }

    private static void parseInto(String s, List<Challenge> out) {
        int n = s.length();
        int i = 0;
        Challenge current = null;
        while (true) {
            i = skipSpacesAndCommas(s, i);
            if (i >= n) return;
            int start = i;
            while (i < n && isTokenChar(s.charAt(i))) i++;
            if (i == start) {
                i++; // stray character
                continue;
            }
            String token = s.substring(start, i);
            int j = skipSpaces(s, i);
            if (current != null && j < n && s.charAt(j) == '=' && hasValueAfter(s, j)) {
                // auth-param: name = token / quoted-string
                j = skipSpaces(s, j + 1);
                String value;
                if (s.charAt(j) == '"') {
                    StringBuilder sb = new StringBuilder();
                    j++;
                    while (j < n && s.charAt(j) != '"') {
                        char c = s.charAt(j);
                        if (c == '\\' && j + 1 < n) c = s.charAt(++j);
                        sb.append(c);
                        j++;
                    }
                    j++; // closing quote
                    value = sb.toString();
                } else {
                    int vs = j;
                    while (j < n && s.charAt(j) != ',' && s.charAt(j) != ' ' && s.charAt(j) != '\t') j++;
                    value = s.substring(vs, j);
                }
                current.params.put(token.toLowerCase(Locale.US), value);
                i = j;
                continue;
            }
            // A new challenge; the token is its scheme. Skip a token68 (e.g. "Bearer abc==") after it.
            current = new Challenge(token.toLowerCase(Locale.US));
            out.add(current);
            i = j;
            int t = i;
            while (t < n && (isTokenChar(s.charAt(t)) || s.charAt(t) == '/')) t++;
            int wordEnd = t;
            while (t < n && s.charAt(t) == '=') t++;
            int after = skipSpaces(s, t);
            if (wordEnd > i && (after >= n || s.charAt(after) == ',')) i = after;
        }
    }

    private static boolean hasValueAfter(String s, int eq) {
        int k = skipSpaces(s, eq + 1);
        return k < s.length() && s.charAt(k) != ',' && s.charAt(k) != '=';
    }

    private static int skipSpaces(String s, int i) {
        while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == '\t')) i++;
        return i;
    }

    private static int skipSpacesAndCommas(String s, int i) {
        while (i < s.length() && (s.charAt(i) == ' ' || s.charAt(i) == '\t' || s.charAt(i) == ',')) i++;
        return i;
    }

    private static boolean isTokenChar(char c) {
        if (c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9') return true;
        return "!#$%&'*+-.^_`|~".indexOf(c) >= 0;
    }

    // --- Answers ---

    /** Result of {@link #answer}: the Authorization header value and whether it was Basic. */
    public static final class Answer {
        public final String header;
        public final boolean basic;

        Answer(String header, boolean basic) {
            this.header = header;
            this.basic = basic;
        }
    }

    private static final SecureRandom RANDOM = new SecureRandom();

    /**
     * The Authorization value for a GET of {@code requestTarget} answering the challenges, or null
     * when none of them is a scheme this engine supports. Digest is preferred to Basic, and
     * SHA-256 to MD5.
     */
    public static Answer answer(List<String> wwwAuthenticate, Credentials c, String requestTarget) {
        byte[] r = new byte[16];
        RANDOM.nextBytes(r);
        return answer(parseChallenges(wwwAuthenticate), c, "GET", requestTarget, hex(r));
    }

    static Answer answer(List<Challenge> challenges, Credentials c, String method, String uri, String cnonce) {
        Challenge best = null;
        int bestRank = 0;
        for (Challenge ch : challenges) {
            int rank = rank(ch);
            if (rank > bestRank) {
                best = ch;
                bestRank = rank;
            }
        }
        if (best == null) return null;
        if (best.scheme.equals("basic")) return new Answer(basic(c.user, c.password), true);
        return new Answer(digest(best, c, method, uri, cnonce, 1), false);
    }

    /** 0 = unsupported, 1 = Basic, 2 = Digest MD5, 3 = Digest SHA-256. */
    private static int rank(Challenge ch) {
        if (ch.scheme.equals("basic")) return 1;
        if (!ch.scheme.equals("digest") || ch.param("nonce") == null) return 0;
        String qop = ch.param("qop");
        if (qop != null && !hasToken(qop, "auth")) return 0; // auth-int only
        String alg = digestAlgorithm(ch);
        if (alg.equals("MD5") || alg.equals("MD5-SESS")) return 2;
        if (alg.equals("SHA-256") || alg.equals("SHA-256-SESS")) return 3;
        return 0;
    }

    private static String digestAlgorithm(Challenge ch) {
        String alg = ch.param("algorithm");
        return alg == null ? "MD5" : alg.trim().toUpperCase(Locale.US);
    }

    private static boolean hasToken(String list, String token) {
        for (String part : list.split(",")) {
            if (part.trim().equalsIgnoreCase(token)) return true;
        }
        return false;
    }

    static String basic(String user, String password) {
        try {
            return "Basic " + base64((user + ":" + password).getBytes("UTF-8"));
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    static String digest(Challenge ch, Credentials c, String method, String uri, String cnonce, int count) {
        String alg = digestAlgorithm(ch);
        boolean sess = alg.endsWith("-SESS");
        String hashName = alg.startsWith("SHA-256") ? "SHA-256" : "MD5";
        String realm = ch.param("realm") == null ? "" : ch.param("realm");
        String nonce = ch.param("nonce");
        boolean qopAuth = ch.param("qop") != null;
        String nc = String.format(Locale.US, "%08x", count);

        String ha1 = h(hashName, c.user + ":" + realm + ":" + c.password);
        if (sess) ha1 = h(hashName, ha1 + ":" + nonce + ":" + cnonce);
        String ha2 = h(hashName, method + ":" + uri);
        String response = qopAuth
                ? h(hashName, ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
                : h(hashName, ha1 + ":" + nonce + ":" + ha2);

        StringBuilder sb = new StringBuilder("Digest ");
        sb.append("username=").append(quote(c.user));
        sb.append(", realm=").append(quote(realm));
        sb.append(", uri=").append(quote(uri));
        if (ch.param("algorithm") != null) sb.append(", algorithm=").append(ch.param("algorithm").trim());
        sb.append(", nonce=").append(quote(nonce));
        if (qopAuth) {
            sb.append(", nc=").append(nc);
            sb.append(", cnonce=").append(quote(cnonce));
            sb.append(", qop=auth");
        }
        sb.append(", response=").append(quote(response));
        if (ch.param("opaque") != null) sb.append(", opaque=").append(quote(ch.param("opaque")));
        return sb.toString();
    }

    private static String quote(String v) {
        return "\"" + v.replace("\\", "\\\\").replace("\"", "\\\"") + "\"";
    }

    private static String h(String alg, String s) {
        try {
            return hex(MessageDigest.getInstance(alg).digest(s.getBytes("UTF-8")));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        } catch (UnsupportedEncodingException e) {
            throw new IllegalStateException(e);
        }
    }

    private static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) {
            sb.append(Character.forDigit((x >> 4) & 0xF, 16)).append(Character.forDigit(x & 0xF, 16));
        }
        return sb.toString();
    }

    private static final char[] B64 =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".toCharArray();

    static String base64(byte[] in) {
        StringBuilder sb = new StringBuilder((in.length + 2) / 3 * 4);
        for (int i = 0; i < in.length; i += 3) {
            int b0 = in[i] & 0xFF;
            int b1 = i + 1 < in.length ? in[i + 1] & 0xFF : 0;
            int b2 = i + 2 < in.length ? in[i + 2] & 0xFF : 0;
            sb.append(B64[b0 >> 2]);
            sb.append(B64[((b0 & 3) << 4) | (b1 >> 4)]);
            sb.append(i + 1 < in.length ? B64[((b1 & 0xF) << 2) | (b2 >> 6)] : '=');
            sb.append(i + 2 < in.length ? B64[b2 & 0x3F] : '=');
        }
        return sb.toString();
    }
}
