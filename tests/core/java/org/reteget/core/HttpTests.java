package org.reteget.core;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * HTTP resume (Range / If-Range) and Basic / Digest authentication: the pure functions in
 * {@link HttpAuth} and {@link HttpResume}, then whole downloads against an in-process server,
 * once through HttpURLConnection and once through the engine's own socket code.
 */
public final class HttpTests {

    public static int passed = 0;
    public static int failed = 0;

    private HttpTests() {}

    public static void run() {
        System.out.println("\n[HTTP resume and authentication]");
        testBase64AndBasic();
        testDigestRfc7616();
        testChallengeParsing();
        testAnswerSelection();
        testCredentialsAndMasking();
        testResumeDecisions();
        for (int own = 0; own < 2; own++) {
            boolean ownSocket = own == 1;
            String p = ownSocket ? "[own socket] " : "[system] ";
            testAutoResume(p, ownSocket);
            testNoValidatorNoResume(p, ownSocket);
            testRetryWithResume(p, ownSocket);
            testServerIgnoresRange(p, ownSocket);
            testChangedFileRestarts(p, ownSocket);
            testAlreadyComplete(p, ownSocket);
            testWrongRangeRerequests(p, ownSocket);
            testCancelDeletesPart(p, ownSocket);
            testBasicAuth(p, ownSocket);
            testDigestAuth(p, ownSocket, "SHA-256");
            testDigestAuth(p, ownSocket, null);
            testWrongPassword(p, ownSocket);
            testNoCredentials(p, ownSocket);
            testCredentialsStayWithOrigin(p, ownSocket);
        }
        testQueueResumeRecords();
        testSettingsExportDropsPasswords();
    }

    private static void testSettingsExportDropsPasswords() {
        SettingsBundle b = new SettingsBundle();
        PresetItem p = new PresetItem("NAS", "http://me:hunter2@nas.local/apk/{1}.apk");
        p.index = "https://me:hunter2@nas.local/apk/";
        b.presets.add(p);
        String text = b.write();
        check("settings export drops the password", !text.contains("hunter2"));
        check("settings export keeps the user name", text.contains("http://me@nas.local/apk/{1}.apk")
                && text.contains("https://me@nas.local/apk/"));
        checkEq("the preset itself keeps the password", "http://me:hunter2@nas.local/apk/{1}.apk", p.url);
    }

    private static void check(String msg, boolean ok) {
        if (ok) {
            passed++;
            System.out.println("  PASS: " + msg);
        } else {
            failed++;
            System.err.println("  FAIL: " + msg);
        }
    }

    private static void checkEq(String msg, Object expected, Object actual) {
        boolean ok = expected == null ? actual == null : expected.equals(actual);
        if (ok) {
            passed++;
            System.out.println("  PASS: " + msg);
        } else {
            failed++;
            System.err.println("  FAIL: " + msg + " (expected [" + expected + "], got [" + actual + "])");
        }
    }

    // --- Pure functions ---

    private static void testBase64AndBasic() {
        checkEq("RFC 7617 Basic example", "Basic QWxhZGRpbjpvcGVuIHNlc2FtZQ==", HttpAuth.basic("Aladdin", "open sesame"));
        checkEq("base64 one byte", "YQ==", HttpAuth.base64(new byte[] { 'a' }));
        checkEq("base64 two bytes", "YWI=", HttpAuth.base64(new byte[] { 'a', 'b' }));
        checkEq("base64 empty", "", HttpAuth.base64(new byte[0]));
        checkEq("Basic is UTF-8", "Basic dGVzdDoxMjPCow==", HttpAuth.basic("test", "123\u00a3"));
    }

    private static final String RFC_CNONCE = "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ";

    private static HttpAuth.Challenge rfc7616Challenge(String alg) {
        List<HttpAuth.Challenge> list = HttpAuth.parseChallenges(Collections.singletonList(
                "Digest realm=\"http-auth@example.org\", qop=\"auth, auth-int\", algorithm=" + alg
                        + ", nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\""
                        + ", opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\""));
        return list.get(0);
    }

    private static void testDigestRfc7616() {
        HttpAuth.Credentials c = new HttpAuth.Credentials("Mufasa", "Circle of Life");
        String md5 = HttpAuth.digest(rfc7616Challenge("MD5"), c, "GET", "/dir/index.html", RFC_CNONCE, 1);
        checkEq("RFC 7616 3.9.1 MD5 header", "Digest username=\"Mufasa\", realm=\"http-auth@example.org\", "
                + "uri=\"/dir/index.html\", algorithm=MD5, nonce=\"7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v\", "
                + "nc=00000001, cnonce=\"" + RFC_CNONCE + "\", qop=auth, response=\"8ca523f5e9506fed4657c9700eebdbec\", "
                + "opaque=\"FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS\"", md5);
        String sha = HttpAuth.digest(rfc7616Challenge("SHA-256"), c, "GET", "/dir/index.html", RFC_CNONCE, 1);
        check("RFC 7616 3.9.1 SHA-256 response",
                sha.contains("response=\"753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1\""));
        check("SHA-256 header names the algorithm", sha.contains("algorithm=SHA-256,"));

        // RFC 2069 style (no qop): response = H(HA1:nonce:HA2), no nc/cnonce.
        HttpAuth.Challenge old = HttpAuth.parseChallenges(Collections.singletonList(
                "Digest realm=\"r\", nonce=\"n\"")).get(0);
        String noQop = HttpAuth.digest(old, new HttpAuth.Credentials("u", "p"), "GET", "/f", "c", 1);
        String expect = md5Hex(md5Hex("u:r:p") + ":n:" + md5Hex("GET:/f"));
        check("Digest without qop", noQop.contains("response=\"" + expect + "\"") && !noQop.contains("nc="));

        HttpAuth.Challenge sess = HttpAuth.parseChallenges(Collections.singletonList(
                "Digest realm=\"r\", nonce=\"n\", qop=auth, algorithm=MD5-sess")).get(0);
        String s = HttpAuth.digest(sess, new HttpAuth.Credentials("u", "p"), "GET", "/f", "c", 1);
        String ha1 = md5Hex(md5Hex("u:r:p") + ":n:c");
        check("Digest MD5-sess", s.contains("response=\"" + md5Hex(ha1 + ":n:00000001:c:auth:" + md5Hex("GET:/f")) + "\""));
        String quoted = HttpAuth.digest(old, new HttpAuth.Credentials("a\"b", "p"), "GET", "/f", "c", 1);
        check("Digest escapes a quote in the user name", quoted.startsWith("Digest username=\"a\\\"b\""));
    }

    private static void testChallengeParsing() {
        List<HttpAuth.Challenge> l = HttpAuth.parseChallenges(Collections.singletonList(
                "Newauth realm=\"apps\", type=1, title=\"Login to \\\"apps\\\"\", Basic realm=\"simple\""));
        checkEq("RFC 7235 example: two challenges", 2, l.size());
        checkEq("first scheme", "newauth", l.get(0).scheme);
        checkEq("escaped quotes in a quoted value", "Login to \"apps\"", l.get(0).param("title"));
        checkEq("token value", "1", l.get(0).param("type"));
        checkEq("second challenge's realm", "simple", l.get(1).param("realm"));
        List<HttpAuth.Challenge> t = HttpAuth.parseChallenges(Arrays.asList("Bearer abc==, Basic realm=x", "Digest nonce=\"n\""));
        checkEq("token68 skipped; challenges from two headers", 3, t.size());
        checkEq("token68 does not swallow the next scheme", "basic", t.get(1).scheme);
        checkEq("unquoted value", "x", t.get(1).param("realm"));
        checkEq("bare scheme", 1, HttpAuth.parseChallenges(Collections.singletonList("Basic")).size());
    }

    private static void testAnswerSelection() {
        HttpAuth.Credentials c = new HttpAuth.Credentials("u", "p");
        List<String> all = Arrays.asList("Basic realm=\"r\"", "Digest realm=\"r\", nonce=\"n\", qop=auth",
                "Digest realm=\"r\", nonce=\"n\", qop=auth, algorithm=SHA-256");
        HttpAuth.Answer a = HttpAuth.answer(all, c, "/f");
        check("Digest SHA-256 preferred", a != null && a.header.startsWith("Digest ") && a.header.contains("algorithm=SHA-256"));
        check("not marked Basic", a != null && !a.basic);
        HttpAuth.Answer b = HttpAuth.answer(Collections.singletonList("Basic realm=\"r\""), c, "/f");
        check("Basic when only Basic is offered", b != null && b.basic && b.header.equals(HttpAuth.basic("u", "p")));
        checkEq("auth-int only is unsupported", null,
                HttpAuth.answer(Collections.singletonList("Digest realm=\"r\", nonce=\"n\", qop=\"auth-int\""), c, "/f"));
        checkEq("unknown algorithm is unsupported", null,
                HttpAuth.answer(Collections.singletonList("Digest realm=\"r\", nonce=\"n\", algorithm=SHA-512-256"), c, "/f"));
        checkEq("unknown scheme is unsupported", null,
                HttpAuth.answer(Collections.singletonList("Negotiate"), c, "/f"));
        HttpAuth.Answer r1 = HttpAuth.answer(Collections.singletonList("Digest realm=\"r\", nonce=\"n\", qop=auth"), c, "/f");
        HttpAuth.Answer r2 = HttpAuth.answer(Collections.singletonList("Digest realm=\"r\", nonce=\"n\", qop=auth"), c, "/f");
        check("cnonce differs between answers", !r1.header.equals(r2.header));
    }

    private static void testCredentialsAndMasking() {
        try {
            java.net.URL u = new java.net.URL("http://us%20er:p%40ss+w%3Ard@Example.org/a/b?q=1#frag");
            HttpAuth.Credentials c = HttpAuth.credentials(u);
            checkEq("user percent-decoded", "us er", c.user);
            checkEq("password percent-decoded, '+' kept", "p@ss+w:rd", c.password);
            checkEq("user info and fragment stripped", "http://Example.org/a/b?q=1", HttpAuth.withoutUserInfo(u).toString());
            checkEq("origin has the default port, lower case", "http://example.org:80", HttpAuth.origin(u));
            checkEq("request target keeps the query", "/a/b?q=1", HttpAuth.requestTarget(u));
            checkEq("no user info: no credentials", null, HttpAuth.credentials(new java.net.URL("https://h/f")));
            HttpAuth.Credentials onlyUser = HttpAuth.credentials(new java.net.URL("ftp://anon@h/f"));
            checkEq("user without password", "", onlyUser.password);
            checkEq("UTF-8 percent-decoding", "\u00e9", HttpAuth.percentDecode("%C3%A9"));
            checkEq("https origin", "https://h:8443", HttpAuth.origin(new java.net.URL("https://h:8443/x")));
            checkEq("root target", "/", HttpAuth.requestTarget(new java.net.URL("http://h")));
        } catch (Exception e) {
            check("credentials: " + e, false);
        }
        checkEq("mask a password", "http://u:***@h/x", HttpAuth.mask("http://u:secret@h/x"));
        checkEq("mask inside a message", "Invalid FTP URL: ftp://a:***@c/d", HttpAuth.mask("Invalid FTP URL: ftp://a:b@c/d"));
        checkEq("no password: unchanged", "http://u@h/x and http://h/y@z", HttpAuth.mask("http://u@h/x and http://h/y@z"));
        checkEq("strip a password", "http://u@h/x", HttpAuth.stripPasswords("http://u:secret@h/x"));
        checkEq("mask null", null, HttpAuth.mask(null));
        checkEq("displayName masks a bare URL", "x", new DownloadTask(1, "http://u:pw@h/x", "/d", false, false, "", 0).displayName());
        String bare = new DownloadTask(1, "http://u:pw@h/", "/d", false, false, "", 0).displayName();
        check("displayName of a URL ending in / hides the password", !bare.contains("pw"));
        check("preset display name of a URL ending in / hides the password",
                !new PresetItem("", "http://u:pw@h/").getDisplayName().contains("pw"));
    }

    private static void testResumeDecisions() {
        checkEq("strong ETag is the validator", "\"abc\"", HttpResume.validator("\"abc\"", "Mon, 01 Jan 2024 00:00:00 GMT"));
        checkEq("weak ETag falls back to Last-Modified", "Mon, 01 Jan 2024 00:00:00 GMT",
                HttpResume.validator("W/\"abc\"", "Mon, 01 Jan 2024 00:00:00 GMT"));
        checkEq("weak ETag alone: no validator", null, HttpResume.validator("W/\"abc\"", null));
        checkEq("nothing: no validator", null, HttpResume.validator(null, " "));
        long[] r = HttpResume.parseContentRange("bytes 100-199/1000");
        check("Content-Range parsed", r != null && r[0] == 100 && r[1] == 199 && r[2] == 1000);
        long[] star = HttpResume.parseContentRange("bytes 5-9/*");
        check("Content-Range with unknown total", star != null && star[2] == -1);
        checkEq("Content-Range not bytes", null, HttpResume.parseContentRange("items 1-2/3"));
        checkEq("Content-Range past the end", null, HttpResume.parseContentRange("bytes 0-10/10"));
        checkEq("Content-Range unsatisfied form", null, HttpResume.parseContentRange("bytes */1000"));
        checkEq("206 at the offset appends", HttpResume.APPEND, HttpResume.decide(100, 1000, 206, "bytes 100-999/1000"));
        checkEq("206 elsewhere re-requests", HttpResume.REREQUEST, HttpResume.decide(100, 1000, 206, "bytes 0-999/1000"));
        checkEq("206 with another size re-requests", HttpResume.REREQUEST, HttpResume.decide(100, 1000, 206, "bytes 100-1999/2000"));
        checkEq("206 without Content-Range re-requests", HttpResume.REREQUEST, HttpResume.decide(100, 1000, 206, null));
        checkEq("206 total * with a known size re-requests", HttpResume.REREQUEST, HttpResume.decide(100, 1000, 206, "bytes 100-999/*"));
        checkEq("206 total * with unknown size appends", HttpResume.APPEND, HttpResume.decide(100, -1, 206, "bytes 100-999/*"));
        checkEq("200 is the full file", HttpResume.FULL, HttpResume.decide(100, 1000, 200, null));
        checkEq("416 with the whole file is complete", HttpResume.COMPLETE, HttpResume.decide(1000, 1000, 416, "bytes */1000"));
        checkEq("416 otherwise re-requests", HttpResume.REREQUEST, HttpResume.decide(500, 1000, 416, "bytes */900"));
        checkEq("404 left to the caller", 0, HttpResume.decide(100, 1000, 404, null));
    }

    // --- In-process server ---

    /** One request as the server saw it: the request line and headers (names lower case). */
    static final class Request {
        final String line;
        final Map<String, String> headers;

        Request(String line, Map<String, String> headers) {
            this.line = line;
            this.headers = headers;
        }

        String h(String name) {
            return headers.get(name);
        }
    }

    interface Handler {
        /** Writes the whole response for request number {@code n} (0-based). */
        void handle(int n, Request r, OutputStream out, Server s) throws IOException;
    }

    /** A one-request-per-connection HTTP server on 127.0.0.1. */
    static final class Server implements Runnable {
        final ServerSocket ss;
        final Handler handler;
        final List<Request> requests = Collections.synchronizedList(new ArrayList<Request>());
        private volatile boolean closed;

        Server(Handler handler) throws IOException {
            this.ss = new ServerSocket(0, 50, java.net.InetAddress.getByName("127.0.0.1"));
            this.handler = handler;
            Thread t = new Thread(this, "HttpTests-server");
            t.setDaemon(true);
            t.start();
        }

        int port() {
            return ss.getLocalPort();
        }

        String url(String path) {
            return "http://127.0.0.1:" + port() + path;
        }

        public void run() {
            while (!closed) {
                Socket s;
                try {
                    s = ss.accept();
                } catch (IOException e) {
                    return;
                }
                try {
                    s.setSoTimeout(5000);
                    InputStream in = new BufferedInputStream(s.getInputStream());
                    String line = readLine(in);
                    if (line == null) continue;
                    Map<String, String> h = new HashMap<String, String>();
                    String hl;
                    while ((hl = readLine(in)) != null && hl.length() > 0) {
                        int c = hl.indexOf(':');
                        if (c > 0) h.put(hl.substring(0, c).trim().toLowerCase(Locale.US), hl.substring(c + 1).trim());
                    }
                    Request r = new Request(line, h);
                    int n = requests.size();
                    requests.add(r);
                    OutputStream out = s.getOutputStream();
                    handler.handle(n, r, out, this);
                    out.flush();
                } catch (IOException ignored) {
                } finally {
                    try { s.close(); } catch (IOException ignored) {}
                }
            }
        }

        void close() {
            closed = true;
            try { ss.close(); } catch (IOException ignored) {}
        }

        private static String readLine(InputStream in) throws IOException {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            int c;
            while ((c = in.read()) != -1) {
                if (c == '\r') continue;
                if (c == '\n') return b.toString("ISO-8859-1");
                b.write(c);
            }
            return b.size() == 0 ? null : b.toString("ISO-8859-1");
        }
    }

    static void respond(OutputStream out, String status, String[] headers, byte[] body, int from, int len) throws IOException {
        StringBuilder sb = new StringBuilder("HTTP/1.1 ").append(status).append("\r\n");
        for (String h : headers) sb.append(h).append("\r\n");
        sb.append("Connection: close\r\n\r\n");
        out.write(sb.toString().getBytes("ISO-8859-1"));
        if (body != null && len > 0) out.write(body, from, len);
    }

    static final byte[] CONTENT = content(300000, 7);
    static final byte[] CONTENT2 = content(250000, 11);

    private static byte[] content(int n, int seed) {
        byte[] b = new byte[n];
        long x = seed;
        for (int i = 0; i < n; i++) {
            x = x * 6364136223846793005L + 1442695040888963407L;
            b[i] = (byte) (x >>> 56);
        }
        return b;
    }

    /**
     * A file server honouring Range with If-Range against {@code etag}. {@code breakAt} >= 0 cuts
     * the first full response after that many bytes (Content-Length still says the whole size).
     */
    static Handler fileServer(final byte[] body, final String etag, final int breakAt) {
        return new Handler() {
            public void handle(int n, Request r, OutputStream out, Server s) throws IOException {
                String range = r.h("range");
                String ifRange = r.h("if-range");
                String[] base = etag != null
                        ? new String[] { "ETag: " + etag, "Accept-Ranges: bytes" }
                        : new String[] { "Accept-Ranges: bytes" };
                if (range != null && etag != null && etag.equals(ifRange) && range.startsWith("bytes=") && range.endsWith("-")) {
                    int from = Integer.parseInt(range.substring(6, range.length() - 1));
                    if (from >= body.length) {
                        respond(out, "416 Range Not Satisfiable", new String[] { "Content-Range: bytes */" + body.length }, null, 0, 0);
                        return;
                    }
                    respond(out, "206 Partial Content", concat(base, "Content-Length: " + (body.length - from),
                            "Content-Range: bytes " + from + "-" + (body.length - 1) + "/" + body.length), body, from, body.length - from);
                    return;
                }
                int len = n == 0 && breakAt >= 0 ? breakAt : body.length;
                respond(out, "200 OK", concat(base, "Content-Length: " + body.length), body, 0, len);
            }
        };
    }

    static String[] concat(String[] a, String... b) {
        String[] r = new String[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    /** Records what the engine reported. */
    static final class Recorder implements DownloadEngine.ResumeListener {
        File completed;
        Exception error;
        boolean cancelledCalled;
        String partPath;
        String validator;
        long total = -2;
        final List<String> notices = new ArrayList<String>();
        long resumedAt = -1;
        DownloadEngine cancelOnPartial;

        public void onStart(String filename, long totalBytes) {}

        public void onProgress(long bytesRead, long totalBytes, int percent, long bytesPerSec) {}

        public void onComplete(File destinationFile) {
            completed = destinationFile;
        }

        public void onError(Exception ex) {
            error = ex;
        }

        public void onCancel() {
            cancelledCalled = true;
        }

        public void onPartial(String partPath, String validator, long totalBytes) {
            this.partPath = partPath;
            this.validator = validator;
            this.total = totalBytes;
            if (cancelOnPartial != null) cancelOnPartial.cancel();
        }

        public void onNotice(String notice, long value) {
            notices.add(notice);
            if (DownloadEngine.NOTICE_RESUMED.equals(notice)) resumedAt = value;
        }
    }

    private static File tempDir() {
        try {
            File f = File.createTempFile("httptests", "");
            f.delete();
            f.mkdirs();
            return f;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] read(File f) {
        try {
            InputStream in = new FileInputStream(f);
            try {
                ByteArrayOutputStream b = new ByteArrayOutputStream();
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) > 0) b.write(buf, 0, n);
                return b.toByteArray();
            } finally {
                in.close();
            }
        } catch (IOException e) {
            return null;
        }
    }

    private static DownloadEngine engine(long... backoff) {
        DownloadEngine e = new DownloadEngine();
        e.backoffMs = backoff;
        return e;
    }

    private static boolean noPartLeft(File dir) {
        String[] names = dir.list();
        if (names == null) return true;
        for (String n : names) {
            if (n.endsWith(DownloadEngine.PART_SUFFIX)) return false;
        }
        return true;
    }

    // --- Resume over the wire ---

    private static void testAutoResume(String p, boolean own) {
        Server s = null;
        try {
            s = new Server(fileServer(CONTENT, "\"v1\"", 100000));
            File dir = tempDir();
            Recorder rec = new Recorder();
            engine(1, 1, 1).execute(s.url("/files/app.apk"), dir, false, false, own, null, rec);
            check(p + "auto resume completes: " + rec.error, rec.completed != null && rec.error == null);
            check(p + "auto resume: file identical", rec.completed != null && Arrays.equals(CONTENT, read(rec.completed)));
            checkEq(p + "auto resume: final name", "app.apk", rec.completed == null ? null : rec.completed.getName());
            checkEq(p + "auto resume: two requests", 2, s.requests.size());
            checkEq(p + "auto resume: Range from the break", "bytes=100000-", s.requests.get(1).h("range"));
            checkEq(p + "auto resume: If-Range is the ETag", "\"v1\"", s.requests.get(1).h("if-range"));
            checkEq(p + "auto resume: first request has no Range", null, s.requests.get(0).h("range"));
            checkEq(p + "auto resume: notice at the offset", 100000L, rec.resumedAt);
            check(p + "auto resume: no .part left", noPartLeft(dir));
            checkEq(p + "Host header carries the port", "127.0.0.1:" + s.port(), s.requests.get(0).h("host"));
        } catch (Exception e) {
            check(p + "auto resume: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    private static void testNoValidatorNoResume(String p, boolean own) {
        Server s = null;
        try {
            s = new Server(fileServer(CONTENT, null, 100000));
            File dir = tempDir();
            Recorder rec = new Recorder();
            engine(1, 1, 1).execute(s.url("/f.bin"), dir, false, false, own, null, rec);
            check(p + "no validator: the cut body is an error", rec.error != null && rec.completed == null);
            checkEq(p + "no validator: no second request", 1, s.requests.size());
            check(p + "no validator: .part deleted", noPartLeft(dir));
            checkEq(p + "no validator: reported as null", null, rec.validator);
        } catch (Exception e) {
            check(p + "no validator: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    private static void testRetryWithResume(String p, boolean own) {
        Server s = null;
        try {
            s = new Server(fileServer(CONTENT, "\"v1\"", 120000));
            File dir = tempDir();
            Recorder first = new Recorder();
            engine().execute(s.url("/dl/f.bin"), dir, false, false, own, null, first);
            check(p + "retry: first run fails without automatic resumes", first.error != null);
            File part = first.partPath == null ? null : new File(first.partPath);
            check(p + "retry: .part kept", part != null && part.isFile() && part.length() == 120000);
            checkEq(p + "retry: part file name", "f.bin.part", part == null ? null : part.getName());
            checkEq(p + "retry: total reported", (long) CONTENT.length, first.total);

            Recorder second = new Recorder();
            engine().execute(s.url("/dl/f.bin"), dir, false, false, own,
                    new DownloadEngine.Resume("f.bin", first.validator, first.total), second);
            check(p + "retry: resumed run completes: " + second.error, second.completed != null);
            check(p + "retry: file identical", second.completed != null && Arrays.equals(CONTENT, read(second.completed)));
            checkEq(p + "retry: Range from the part's length", "bytes=120000-", s.requests.get(1).h("range"));
            checkEq(p + "retry: resumed notice", 120000L, second.resumedAt);
            check(p + "retry: .part gone", noPartLeft(dir));
        } catch (Exception e) {
            check(p + "retry: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    private static void testServerIgnoresRange(String p, boolean own) {
        Server s = null;
        try {
            final Handler cut = fileServer(CONTENT, "\"v1\"", 50000);
            s = new Server(new Handler() {
                public void handle(int n, Request r, OutputStream out, Server sv) throws IOException {
                    if (n == 0) {
                        cut.handle(n, r, out, sv);
                    } else { // ignores Range: always the whole file
                        respond(out, "200 OK", new String[] { "ETag: \"v1\"", "Content-Length: " + CONTENT.length },
                                CONTENT, 0, CONTENT.length);
                    }
                }
            });
            File dir = tempDir();
            Recorder rec = new Recorder();
            engine(1).execute(s.url("/f.bin"), dir, false, false, own, null, rec);
            check(p + "range ignored: completes", rec.completed != null && Arrays.equals(CONTENT, read(rec.completed)));
            check(p + "range ignored: restarted notice", rec.notices.contains(DownloadEngine.NOTICE_RESTARTED));
            checkEq(p + "range ignored: no resumed notice", -1L, rec.resumedAt);
        } catch (Exception e) {
            check(p + "range ignored: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    private static void testChangedFileRestarts(String p, boolean own) {
        Server s = null;
        try {
            final Handler v1 = fileServer(CONTENT, "\"v1\"", 60000);
            final Handler v2 = fileServer(CONTENT2, "\"v2\"", -1);
            s = new Server(new Handler() {
                public void handle(int n, Request r, OutputStream out, Server sv) throws IOException {
                    (n == 0 ? v1 : v2).handle(n, r, out, sv);
                }
            });
            File dir = tempDir();
            Recorder rec = new Recorder();
            engine(1).execute(s.url("/f.bin"), dir, false, false, own, null, rec);
            check(p + "changed file: completes with the new file",
                    rec.completed != null && Arrays.equals(CONTENT2, read(rec.completed)));
            checkEq(p + "changed file: If-Range sent the old ETag", "\"v1\"", s.requests.get(1).h("if-range"));
            check(p + "changed file: restarted notice", rec.notices.contains(DownloadEngine.NOTICE_RESTARTED));
            checkEq(p + "changed file: new validator", "\"v2\"", rec.validator);
        } catch (Exception e) {
            check(p + "changed file: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    private static void testAlreadyComplete(String p, boolean own) {
        Server s = null;
        try {
            s = new Server(fileServer(CONTENT, "\"v1\"", -1));
            File dir = tempDir();
            FileOutputStream o = new FileOutputStream(new File(dir, "f.bin.part"));
            o.write(CONTENT);
            o.close();
            Recorder rec = new Recorder();
            engine().execute(s.url("/f.bin"), dir, false, false, own,
                    new DownloadEngine.Resume("f.bin", "\"v1\"", CONTENT.length), rec);
            check(p + "416 with the whole part: complete", rec.completed != null && Arrays.equals(CONTENT, read(rec.completed)));
            checkEq(p + "416: one request", 1, s.requests.size());
        } catch (Exception e) {
            check(p + "416: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    private static void testWrongRangeRerequests(String p, boolean own) {
        Server s = null;
        try {
            s = new Server(new Handler() {
                public void handle(int n, Request r, OutputStream out, Server sv) throws IOException {
                    if (r.h("range") != null) { // answers a different range than asked
                        respond(out, "206 Partial Content", new String[] { "ETag: \"v1\"", "Content-Length: 10",
                                "Content-Range: bytes 0-9/" + CONTENT.length }, CONTENT, 0, 10);
                    } else {
                        respond(out, "200 OK", new String[] { "ETag: \"v1\"", "Content-Length: " + CONTENT.length },
                                CONTENT, 0, CONTENT.length);
                    }
                }
            });
            File dir = tempDir();
            FileOutputStream o = new FileOutputStream(new File(dir, "f.bin.part"));
            o.write(CONTENT, 0, 1000);
            o.close();
            Recorder rec = new Recorder();
            engine().execute(s.url("/f.bin"), dir, false, false, own,
                    new DownloadEngine.Resume("f.bin", "\"v1\"", CONTENT.length), rec);
            check(p + "wrong 206: completes after asking again", rec.completed != null && Arrays.equals(CONTENT, read(rec.completed)));
            checkEq(p + "wrong 206: second request without Range", null, s.requests.get(1).h("range"));
        } catch (Exception e) {
            check(p + "wrong 206: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    private static void testCancelDeletesPart(String p, boolean own) {
        Server s = null;
        try {
            s = new Server(fileServer(CONTENT, "\"v1\"", -1));
            File dir = tempDir();
            Recorder rec = new Recorder();
            DownloadEngine e = engine();
            rec.cancelOnPartial = e;
            e.execute(s.url("/f.bin"), dir, false, false, own, null, rec);
            check(p + "cancel: onCancel", rec.cancelledCalled && rec.completed == null && rec.error == null);
            check(p + "cancel: .part deleted", noPartLeft(dir) && !new File(dir, "f.bin").exists());
        } catch (Exception e) {
            check(p + "cancel: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    // --- Authentication over the wire ---

    private static void testBasicAuth(String p, boolean own) {
        Server s = null;
        try {
            final String expected = HttpAuth.basic("user", "p@ss+word");
            s = new Server(new Handler() {
                public void handle(int n, Request r, OutputStream out, Server sv) throws IOException {
                    if (!expected.equals(r.h("authorization"))) {
                        respond(out, "401 Unauthorized", new String[] { "WWW-Authenticate: Basic realm=\"test\"",
                                "Content-Length: 0" }, null, 0, 0);
                    } else {
                        respond(out, "200 OK", new String[] { "Content-Length: " + CONTENT.length }, CONTENT, 0, CONTENT.length);
                    }
                }
            });
            File dir = tempDir();
            Recorder rec = new Recorder();
            String url = "http://user:p%40ss+word@127.0.0.1:" + s.port() + "/secret/f.bin";
            engine().execute(url, dir, false, false, own, null, rec);
            check(p + "Basic: completes: " + rec.error, rec.completed != null && Arrays.equals(CONTENT, read(rec.completed)));
            checkEq(p + "Basic: two requests", 2, s.requests.size());
            checkEq(p + "Basic: nothing sent before the challenge", null, s.requests.get(0).h("authorization"));
            check(p + "Basic: request line without user info", s.requests.get(0).line.startsWith("GET /secret/f.bin HTTP/1.1"));
            checkEq(p + "Basic: Host without user info", "127.0.0.1:" + s.port(), s.requests.get(1).h("host"));
            check(p + "Basic over http: cleartext notice", rec.notices.contains(DownloadEngine.NOTICE_CLEARTEXT_PASSWORD));
        } catch (Exception e) {
            check(p + "Basic: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    /** A server checking Digest itself (independent of HttpAuth's code). {@code alg} null = no algorithm parameter (MD5). */
    private static void testDigestAuth(String p, boolean own, final String alg) {
        Server s = null;
        final String name = p + "Digest " + (alg == null ? "MD5 (default)" : alg) + ": ";
        try {
            s = new Server(new Handler() {
                public void handle(int n, Request r, OutputStream out, Server sv) throws IOException {
                    String a = r.h("authorization");
                    if (a == null || !digestValid(a, alg == null ? "MD5" : alg, "user", "pw", "/d/f.bin?x=1")) {
                        respond(out, "401 Unauthorized", new String[] {
                                "WWW-Authenticate: Basic realm=\"realm\"",
                                "WWW-Authenticate: Digest realm=\"realm\", qop=\"auth\", nonce=\"abc123\", opaque=\"op\""
                                        + (alg != null ? ", algorithm=" + alg : ""),
                                "Content-Length: 0" }, null, 0, 0);
                    } else {
                        respond(out, "200 OK", new String[] { "Content-Length: " + CONTENT.length }, CONTENT, 0, CONTENT.length);
                    }
                }
            });
            File dir = tempDir();
            Recorder rec = new Recorder();
            engine().execute("http://user:pw@127.0.0.1:" + s.port() + "/d/f.bin?x=1", dir, false, false, own, null, rec);
            check(name + "completes: " + rec.error, rec.completed != null && Arrays.equals(CONTENT, read(rec.completed)));
            check(name + "chosen over Basic", s.requests.size() == 2 && s.requests.get(1).h("authorization").startsWith("Digest "));
            check(name + "no cleartext notice", !rec.notices.contains(DownloadEngine.NOTICE_CLEARTEXT_PASSWORD));
        } catch (Exception e) {
            check(name + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    static boolean digestValid(String header, String alg, String user, String pass, String uri) {
        if (!header.startsWith("Digest ")) return false;
        Map<String, String> m = new HashMap<String, String>();
        for (HttpAuth.Challenge c : HttpAuth.parseChallenges(Collections.singletonList(header))) m.putAll(c.params);
        String hn = alg.startsWith("SHA-256") ? "SHA-256" : "MD5";
        if (!uri.equals(m.get("uri")) || !user.equals(m.get("username")) || !"op".equals(m.get("opaque"))
                || !"auth".equals(m.get("qop")) || !"00000001".equals(m.get("nc"))) return false;
        String ha1 = hash(hn, user + ":realm:" + pass);
        String ha2 = hash(hn, "GET:" + uri);
        String expect = hash(hn, ha1 + ":abc123:" + m.get("nc") + ":" + m.get("cnonce") + ":auth:" + ha2);
        return expect.equals(m.get("response"));
    }

    private static void testWrongPassword(String p, boolean own) {
        Server s = null;
        try {
            s = new Server(new Handler() {
                public void handle(int n, Request r, OutputStream out, Server sv) throws IOException {
                    respond(out, "401 Unauthorized", new String[] { "WWW-Authenticate: Basic realm=\"r\"", "Content-Length: 0" }, null, 0, 0);
                }
            });
            File dir = tempDir();
            Recorder rec = new Recorder();
            engine().execute("http://u:wrong@127.0.0.1:" + s.port() + "/f", dir, false, false, own, null, rec);
            check(p + "wrong password: fails", rec.error != null && rec.error.getMessage().contains("Authentication failed"));
            checkEq(p + "wrong password: only one retry", 2, s.requests.size());
        } catch (Exception e) {
            check(p + "wrong password: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    private static void testNoCredentials(String p, boolean own) {
        Server s = null;
        try {
            s = new Server(new Handler() {
                public void handle(int n, Request r, OutputStream out, Server sv) throws IOException {
                    respond(out, "401 Unauthorized", new String[] { "WWW-Authenticate: Basic realm=\"r\"", "Content-Length: 0" }, null, 0, 0);
                }
            });
            Recorder rec = new Recorder();
            engine().execute(s.url("/f"), tempDir(), false, false, own, null, rec);
            check(p + "401 without credentials: hint", rec.error != null
                    && rec.error.getMessage().contains("needs a user name and password"));
            checkEq(p + "401 without credentials: one request", 1, s.requests.size());
        } catch (Exception e) {
            check(p + "no credentials: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    private static void testCredentialsStayWithOrigin(String p, boolean own) {
        Server a = null;
        Server b = null;
        try {
            b = new Server(new Handler() {
                public void handle(int n, Request r, OutputStream out, Server sv) throws IOException {
                    respond(out, "401 Unauthorized", new String[] { "WWW-Authenticate: Basic realm=\"r\"", "Content-Length: 0" }, null, 0, 0);
                }
            });
            final String target = b.url("/other");
            a = new Server(new Handler() {
                public void handle(int n, Request r, OutputStream out, Server sv) throws IOException {
                    respond(out, "302 Found", new String[] { "Location: " + target, "Content-Length: 0" }, null, 0, 0);
                }
            });
            Recorder rec = new Recorder();
            engine().execute("http://u:pw@127.0.0.1:" + a.port() + "/f", tempDir(), false, false, own, null, rec);
            check(p + "other origin: fails", rec.error != null && rec.error.getMessage().contains("only sent to"));
            check(p + "other origin: never got the password", b.requests.size() == 1 && b.requests.get(0).h("authorization") == null);
        } catch (Exception e) {
            check(p + "other origin: " + e, false);
        } finally {
            if (a != null) a.close();
            if (b != null) b.close();
        }
    }

    // --- Queue records ---

    private static void testQueueResumeRecords() {
        try {
            File dir = tempDir();
            File part = new File(dir, "big.iso.part");
            FileOutputStream o = new FileOutputStream(part);
            o.write(new byte[777]);
            o.close();
            final String[] saved = { "{\"id\":4,\"url\":\"http://h/big.iso\",\"dir\":" + PresetItem.escapeJson(dir.getPath())
                    + ",\"insecure\":0,\"tls\":0,\"expected\":\"\",\"created\":1,\"state\":\"RUNNING\",\"file\":\"big.iso\","
                    + "\"done\":500,\"total\":5000,\"finished\":0,\"verified\":0,\"part\":" + PresetItem.escapeJson(part.getPath())
                    + ",\"validator\":\"\\\"e1\\\"\"}\n"
                    + "{\"id\":2,\"url\":\"http://h/old\",\"dir\":\"/d\",\"insecure\":0,\"tls\":0,\"expected\":\"\",\"created\":1,"
                    + "\"state\":\"FAILED\",\"done\":0,\"total\":-1,\"finished\":0}\n" };
            DownloadQueue.Store store = new DownloadQueue.Store() {
                public String load() { return saved[0]; }
                public void save(String data) { saved[0] = data; }
            };
            final List<DownloadTask> started = new ArrayList<DownloadTask>();
            DownloadQueue q = new DownloadQueue(store, new DownloadQueue.EngineFactory() {
                public DownloadQueue.Engine create() {
                    return new DownloadQueue.Engine() {
                        public void start(DownloadTask t, DownloadEngine.Listener l) {
                            started.add(t);
                            l.onError(new IOException("Invalid FTP URL: ftp://a:secret@h/x"));
                        }
                        public void cancel() {}
                        public String tlsSummary() { return null; }
                    };
                }
            });
            List<DownloadTask> snap = q.snapshot();
            checkEq("queue: old record without the new keys loads", 2, snap.size());
            DownloadTask t = snap.get(0);
            checkEq("queue: interrupted entry keeps its part", part.getPath(), t.partPath);
            checkEq("queue: validator loaded", "\"e1\"", t.validator);
            checkEq("queue: bytes done from the part file", 777L, t.bytesDone);
            q.retry(4);
            check("queue: retry hands the part to the engine", started.size() == 1 && part.getPath().equals(started.get(0).partPath)
                    && started.get(0).bytesTotal == 5000 && "big.iso".equals(started.get(0).fileName));
            DownloadTask after = q.snapshot().get(0);
            checkEq("queue: error message masks a password", "Invalid FTP URL: ftp://a:***@h/x", after.error);
            check("queue: part still recorded after a failure", part.getPath().equals(after.partPath));
            check("queue: record persisted with part and validator", saved[0].contains("\"part\":") && saved[0].contains("\"validator\":"));
            q.remove(4);
            check("queue: remove deletes the part", !part.exists());
        } catch (Exception e) {
            check("queue records: " + e, false);
        }
    }

    // --- helpers ---

    private static String md5Hex(String s) {
        return hash("MD5", s);
    }

    private static String hash(String alg, String s) {
        try {
            byte[] d = MessageDigest.getInstance(alg).digest(s.getBytes("UTF-8"));
            StringBuilder sb = new StringBuilder();
            for (byte x : d) sb.append(String.format("%02x", x & 0xff));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
