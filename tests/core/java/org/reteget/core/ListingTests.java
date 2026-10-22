package org.reteget.core;

import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.reteget.core.ssh.KnownHosts;
import org.reteget.core.ssh.SshConfig;
import org.reteget.core.ssh.SshKeyStore;
import org.reteget.core.ssh.TestSshServer;
import org.reteget.core.tls.TlsTests;

/**
 * Folder listings (RFC-0005): the parsers on real-world samples, the walker's limits, and whole
 * listings over SFTP, FTP/FTPS and http(s) (WebDAV and index pages) against the test servers.
 */
public final class ListingTests {

    public static int passed = 0;
    public static int failed = 0;

    private ListingTests() {}

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
        check(msg + (ok ? "" : " (expected [" + expected + "], got [" + actual + "])"), ok);
    }

    public static void run() {
        System.out.println("\n[Folder listings]");
        try {
            testAddresses();
            testMlsd();
            testUnixList();
            testWindowsList();
            testDav();
            testHtmlIndex();
            testLatestOnFolder();
            testWalker();
            testFtpWire();
            testSftpWire();
            testHttpWire();
        } catch (Exception e) {
            check("listing tests: " + e, false);
        }
    }

    private static String names(List<RemoteEntry> l) {
        StringBuilder sb = new StringBuilder();
        for (RemoteEntry e : l) {
            if (sb.length() > 0) sb.append(',');
            sb.append(e.name).append(e.directory ? "/" : "");
        }
        return sb.toString();
    }

    private static RemoteEntry find(List<RemoteEntry> l, String name) {
        for (RemoteEntry e : l) if (e.name.equals(name)) return e;
        return null;
    }

    private static void testAddresses() {
        checkEq("asFolder adds a slash", "ftp://h/pub/", Listings.asFolder("ftp://h/pub"));
        checkEq("folderOf a file", "sftp://u@h/pub/", Listings.folderOf("sftp://u@h/pub/app.apk"));
        checkEq("folderOf a folder", "sftp://u@h/pub/", Listings.folderOf("sftp://u@h/pub/"));
        checkEq("folderOf a host", "https://h/", Listings.folderOf("https://h"));
        checkEq("folderOf drops the query", "https://h/a/", Listings.folderOf("https://h/a/x.apk?sig=1/2"));
        checkEq("parentOf", "ftp://u:p@h/pub/", Listings.parentOf("ftp://u:p@h/pub/apk/"));
        checkEq("parentOf the top", null, Listings.parentOf("ftp://u:p@h/"));
        checkEq("parentOf the SFTP home", null, Listings.parentOf("sftp://u@h/~/"));
        checkEq("child encodes a space and Korean", "https://h/a/My%20%ED%8C%8C%EC%9D%BC.apk",
                Listings.child("https://h/a/", "My 파일.apk", false));
        checkEq("child encodes # and ? and %", "ftp://h/%23x%3F%25/", Listings.child("ftp://h/", "#x?%", true));
        checkEq("stripUserInfo", "sftp://h:22/x/", Listings.stripUserInfo("sftp://u:p@ss@h:22/x/"));
        check("no slash or dot names", !Listings.usableName("..") && !Listings.usableName("a/b") && !Listings.usableName("")
                && !Listings.usableName("a\nb") && Listings.usableName(".hidden"));
    }

    private static void testMlsd() throws IOException {
        String text = "type=cdir;sizd=4096;modify=20260101000000;UNIX.mode=0755; .\r\n"
                + "type=pdir;sizd=4096;modify=20260101000000; ..\r\n"
                + "type=file;size=246258;modify=20261007012242;UNIX.mode=0644; reteget-0.5.0.apk\r\n"
                + "Type=dir;Modify=20260102030405.123;Perm=el; old releases\r\n"
                + "type=OS.unix=slink:/srv/x;size=10; latest.apk\r\n"
                + "type=OS.unix=chr-13/29; ttyS0\r\n"
                + "type=file;size=1; a/b\r\n";
        List<RemoteEntry> l = Listings.parseMlsd(text, "ftp://u@h/pub/");
        checkEq("mlsd: entries", "reteget-0.5.0.apk,old releases/,latest.apk", names(l));
        RemoteEntry f = find(l, "reteget-0.5.0.apk");
        checkEq("mlsd: size", 246258L, f == null ? null : f.size);
        checkEq("mlsd: time (UTC)", 1791336162000L, f == null ? null : f.modified);
        checkEq("mlsd: folder url", "ftp://u@h/pub/old%20releases/", find(l, "old releases").url);
    }

    private static void testUnixList() throws IOException {
        long now = 1791336162000L; // 2026-10-07
        String text = "total 1234\r\n"
                + "drwxr-xr-x    2 ftp      ftp          4096 Sep 30 12:01 apk\r\n"
                + "-rw-r--r--    1 ftp      ftp        246258 Oct 07 01:22 reteget-0.5.0.apk\r\n"
                + "-rw-r--r--    1 1000     1000          100 Dec 24  2025 old file.txt\r\n"
                + "-rw-r--r--    1 ftp      ftp             5 Nov 30 23:59 future.txt\r\n"
                + "lrwxrwxrwx    1 ftp      ftp            17 Jan  2  2026 latest -> apk/latest.apk\r\n"
                + "-rw-r--r--   1 owner group 12 Mar  3 2024 tiny\r\n"
                + "-rw-r--r-- 1 user 77 Feb 01 2026 nogroup.bin\r\n"
                + "drwxr-xr-x    2 ftp      ftp          4096 Sep 30 12:01 .\r\n"
                + "garbage line\r\n";
        List<RemoteEntry> l = Listings.parseList(text, "ftp://h/", now);
        checkEq("list unix: entries", "apk/,reteget-0.5.0.apk,old file.txt,future.txt,latest,tiny,nogroup.bin", names(l));
        checkEq("list unix: size", 246258L, find(l, "reteget-0.5.0.apk").size);
        checkEq("list unix: year given", 1766534400000L, find(l, "old file.txt").modified);
        check("list unix: a date without a year after now is last year", find(l, "future.txt").modified < now
                && find(l, "future.txt").modified > now - 366L * 86400000);
        checkEq("list unix: folder size unknown", -1L, find(l, "apk").size);
    }

    private static void testWindowsList() throws IOException {
        String text = "10-07-26  01:22AM               246258 reteget-0.5.0.apk\r\n"
                + "09-30-26  12:01PM       <DIR>          apk files\r\n"
                + "2026-01-01 garbage\r\n";
        List<RemoteEntry> l = Listings.parseList(text, "ftp://h/", 0);
        checkEq("list windows: entries", "reteget-0.5.0.apk,apk files/", names(l));
        checkEq("list windows: time", 1791336120000L, find(l, "reteget-0.5.0.apk").modified);
        checkEq("list windows: 12 PM is noon", 1790769660000L, find(l, "apk files").modified);
    }

    static final String DAV_APACHE = "<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
            + "<D:multistatus xmlns:D=\"DAV:\" xmlns:ns0=\"DAV:\">\n"
            + "<D:response xmlns:lp1=\"DAV:\"><D:href>/dav/pub/</D:href><D:propstat><D:prop>"
            + "<lp1:resourcetype><D:collection/></lp1:resourcetype><lp1:getlastmodified>Wed, 07 Oct 2026 01:22:42 GMT</lp1:getlastmodified>"
            + "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n"
            + "<D:response><D:href>/dav/pub/reteget-0.5.0.apk</D:href><D:propstat><D:prop><lp1:resourcetype/>"
            + "<lp1:getcontentlength>246258</lp1:getcontentlength><lp1:getlastmodified>Wed, 07 Oct 2026 01:22:42 GMT</lp1:getlastmodified>"
            + "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>\n"
            + "<D:response><D:href>/dav/pub/My%20Files/</D:href><D:propstat><D:prop><lp1:resourcetype><D:collection/></lp1:resourcetype>"
            + "</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat>"
            + "<D:propstat><D:prop><lp1:getcontentlength/></D:prop><D:status>HTTP/1.1 404 Not Found</D:status></D:propstat></D:response>\n"
            + "<!-- a comment --><D:response><D:href>http://nas:8080/dav/pub/a&amp;b%E2%82%AC.txt</D:href><D:propstat><D:prop>"
            + "<D:resourcetype></D:resourcetype><D:getcontentlength>3</D:getcontentlength></D:prop></D:propstat></D:response>\n"
            + "<D:response><D:href>/dav/pub/sub/deeper.txt</D:href></D:response>\n"
            + "<D:response><D:href>/elsewhere/x.txt</D:href></D:response>\n"
            + "</D:multistatus>\n";

    private static void testDav() throws IOException {
        List<RemoteEntry> l = Listings.parseDav(DAV_APACHE, "https://me:pw@nas:8080/dav/pub/");
        checkEq("dav: entries (self, deeper and foreign left out)", "reteget-0.5.0.apk,My Files/,a&b€.txt", names(l));
        checkEq("dav: size", 246258L, find(l, "reteget-0.5.0.apk").size);
        checkEq("dav: time", 1791336162000L, find(l, "reteget-0.5.0.apk").modified);
        checkEq("dav: entry url keeps the user info", "https://me:pw@nas:8080/dav/pub/My%20Files/", find(l, "My Files").url);
        checkEq("dav: entities and an absolute href", 3L, find(l, "a&b€.txt").size);
        String nextcloud = "<?xml version=\"1.0\"?><d:multistatus xmlns:d=\"DAV:\" xmlns:oc=\"http://owncloud.org/ns\">"
                + "<d:response><d:href>/remote.php/dav/files/me/Apps/</d:href><d:propstat><d:prop><d:resourcetype><d:collection/></d:resourcetype></d:prop></d:propstat></d:response>"
                + "<d:response><d:href>/remote.php/dav/files/me/Apps/%ED%95%9C%EA%B8%80.apk</d:href><d:propstat><d:prop><d:resourcetype/>"
                + "<d:getcontentlength>10</d:getcontentlength></d:prop></d:propstat></d:response></d:multistatus>";
        l = Listings.parseDav(nextcloud, "https://cloud/remote.php/dav/files/me/Apps/");
        checkEq("dav nextcloud: Korean name", "한글.apk", names(l));
    }

    private static void testLatestOnFolder() throws IOException {
        String folder = "sftp://me:pw@nas/apk/";
        List<RemoteEntry> l = Arrays.asList(file(folder, "app-0.9.apk", 1), file(folder, "app-0.10.apk", 1),
                dir(folder, "app-9.9.apk"), file(folder, "other-1.0.apk", 1), file(folder, "app 1.0.apk", 1));
        IndexMatcher.Match m = IndexMatcher.latest(Listings.asIndexPage(l), folder, "sftp://me:pw@nas/apk/app-{1}.apk");
        checkEq("latest on a folder: newest file, folders left out", "sftp://me:pw@nas/apk/app-0.10.apk", m == null ? null : m.url);
        checkEq("latest on a folder: version", "0.10", m == null ? null : m.version);
    }

    private static void testHtmlIndex() throws IOException {
        String nginx = "<html><head><title>Index of /apk/</title></head><body><h1>Index of /apk/</h1><hr><pre>"
                + "<a href=\"../\">../</a>\n"
                + "<a href=\"old/\">old/</a>                                               30-Sep-2026 12:01       -\n"
                + "<a href=\"reteget-0.5.0.apk\">reteget-0.5.0.apk</a>                     07-Oct-2026 01:22  246258\n"
                + "<a href=\"My%20App.apk\">My App.apk</a>\n"
                + "<a href=\"reteget-0.5.0.apk\">again</a>\n"
                + "</pre><hr></body></html>";
        List<RemoteEntry> l = Listings.parseHtmlIndex(nginx, "http://u:p@h:8000/apk/");
        checkEq("html nginx: entries", "old/,reteget-0.5.0.apk,My App.apk", names(l));
        checkEq("html nginx: url", "http://u:p@h:8000/apk/My%20App.apk", find(l, "My App.apk").url);
        String apache = "<table><tr><th><a href=\"?C=N;O=D\">Name</a></th><th><a href=\"?C=M;O=A\">Last modified</a></th></tr>"
                + "<tr><td><a href=\"/files/\">Parent Directory</a></td></tr>"
                + "<tr><td><a href='app.apk'>app.apk</a></td></tr>"
                + "<tr><td><a href=\"/files/apk/sub/\">sub/</a></td></tr>"
                + "<tr><td><a href=\"https://other.example/x.apk\">x</a></td></tr>"
                + "<tr><td><a href=\"sub/deeper.apk\">deep</a></td></tr>"
                + "<tr><td><a href=\"#top\">top</a><a href=\"mailto:a@b\">m</a></td></tr></table>";
        l = Listings.parseHtmlIndex(apache, "https://h/files/apk/");
        checkEq("html apache: sort links, parent, other hosts and deeper links left out", "app.apk,sub/", names(l));
    }

    /** A folder tree in memory: url -> entries. */
    private static RemoteWalker.Lister tree(final Map<String, List<RemoteEntry>> t, final List<String> calls) {
        return new RemoteWalker.Lister() {
            public List<RemoteEntry> list(String folderUrl) throws IOException {
                calls.add(folderUrl);
                List<RemoteEntry> l = t.get(folderUrl);
                if (l == null) throw new IOException("no such folder " + folderUrl);
                return l;
            }
        };
    }

    private static RemoteEntry file(String folder, String name, long size) {
        return new RemoteEntry(name, false, size, 0, Listings.child(folder, name, false));
    }

    private static RemoteEntry dir(String folder, String name) {
        return new RemoteEntry(name, true, -1, 0, Listings.child(folder, name, true));
    }

    private static void testWalker() throws IOException {
        Map<String, List<RemoteEntry>> t = new HashMap<String, List<RemoteEntry>>();
        String root = "sftp://u:pw@h/pub/";
        String a = root + "a/";
        String b = a + "b/";
        t.put(a, Arrays.asList(file(a, "1.apk", 10), dir(a, "b")));
        t.put(b, Arrays.asList(file(b, "2.apk", -1), dir(b, "loop")));
        t.put(b + "loop/", Arrays.asList(new RemoteEntry("back", true, -1, 0, a))); // a link back up
        List<String> calls = new ArrayList<String>();
        List<RemoteWalker.Planned> p = RemoteWalker.plan(Arrays.asList(dir(root, "a"), file(root, "top.apk", 5)), tree(t, calls), null);
        StringBuilder sb = new StringBuilder();
        for (RemoteWalker.Planned x : p) sb.append(x.subdir).append('|').append(x.name).append(' ');
        checkEq("walker: files with their subfolders", "a|1.apk a/b|2.apk |top.apk ", sb.toString());
        checkEq("walker: a loop is walked once", 3, calls.size());
        checkEq("walker: known bytes", 15L, RemoteWalker.knownBytes(p));
        checkEq("walker: unknown sizes", 1, RemoteWalker.unknownSizes(p));

        Map<String, List<RemoteEntry>> deep = new HashMap<String, List<RemoteEntry>>();
        String u = root;
        for (int i = 0; i < 12; i++) {
            deep.put(u + "d/", Arrays.asList(dir(u + "d/", "d")));
            u = u + "d/";
        }
        try {
            RemoteWalker.plan(Arrays.asList(dir(root, "d")), tree(deep, new ArrayList<String>()), null);
            check("walker: depth limit", false);
        } catch (RemoteWalker.TooManyException e) {
            checkEq("walker: depth limit", RemoteWalker.MAX_DEPTH, e.limit);
        }
        List<RemoteEntry> many = new ArrayList<RemoteEntry>();
        for (int i = 0; i <= RemoteWalker.MAX_FILES; i++) many.add(file(a, "f" + i, 1));
        Map<String, List<RemoteEntry>> wide = new HashMap<String, List<RemoteEntry>>();
        wide.put(a, many);
        try {
            RemoteWalker.plan(Arrays.asList(dir(root, "a")), tree(wide, new ArrayList<String>()), null);
            check("walker: file limit", false);
        } catch (RemoteWalker.TooManyException e) {
            checkEq("walker: file limit", RemoteWalker.MAX_FILES, e.limit);
        }
        try {
            RemoteWalker.plan(Arrays.asList(dir(root, "a")), tree(t, new ArrayList<String>()), new RemoteWalker.Progress() {
                public boolean listing(String folderUrl, int filesSoFar) {
                    return false;
                }
            });
            check("walker: cancel", false);
        } catch (IOException e) {
            check("walker: cancel", !(e instanceof RemoteWalker.TooManyException));
        }
    }

    private static void testFtpWire() throws Exception {
        String[][] cases = { { "plain", "ftp", "mlsd" }, { "plain", "ftp", "unix" }, { "plain", "ftp", "windows" },
                { "plain", "ftp", "broken" }, { "explicit", "ftpes", "mlsd" }, { "implicit", "ftps", "unix" } };
        File ks = null;
        for (String[] c : cases) {
            if (!"plain".equals(c[0])) {
                if (ks == null) ks = TlsTests.keystore("ftps-list", "-keyalg EC -groupname secp256r1", "dns:localhost,ip:127.0.0.1");
                if (ks == null) {
                    System.out.println("  SKIP: keytool is missing; FTPS listing not run");
                    continue;
                }
                DownloadEngine.ftpsTrustManagerForTest = TlsTests.trustManagerFor(ks);
                TlsPins.set(new TlsPins(null));
            }
            TestFtpServer s = new TestFtpServer();
            s.mode = c[0];
            s.supportMlsd = "mlsd".equals(c[2]);
            s.brokenMlsd = "broken".equals(c[2]);
            s.listStyle = "windows".equals(c[2]) ? "windows" : "unix";
            s.files.put("/pub/app.apk", new byte[1234]);
            s.files.put("/pub/sub dir/x.apk", new byte[3]);
            s.directories.add("/pub/empty");
            s.start(ks);
            try {
                String base = c[1] + "://user:pw@127.0.0.1:" + s.port() + "/pub";
                List<RemoteEntry> l = new DownloadEngine().list(base, false, null);
                String p = c[1] + " " + c[2] + ": ";
                checkEq(p + "entries", "app.apk,empty/,sub dir/", names(l));
                checkEq(p + "size", 1234L, find(l, "app.apk") == null ? null : find(l, "app.apk").size);
                checkEq(p + "folder url", c[1] + "://user:pw@127.0.0.1:" + s.port() + "/pub/sub%20dir/",
                        find(l, "sub dir") == null ? null : find(l, "sub dir").url);
                List<RemoteEntry> sub = new DownloadEngine().list(find(l, "sub dir").url, false, null);
                checkEq(p + "into a folder", "x.apk", names(sub));
                if ("mlsd".equals(c[2])) check(p + "MLSD used", s.log.toString().contains("MLSD /pub/"));
                if ("broken".equals(c[2])) check(p + "LIST after a refused MLSD", s.log.toString().contains("LIST /pub/"));
                if (!"plain".equals(c[0])) {
                    check(p + "listing inside TLS", s.log.toString().contains("tls " + ("mlsd".equals(c[2]) ? "MLSD" : "LIST")));
                }
                try {
                    new DownloadEngine().list(c[1] + "://user:pw@127.0.0.1:" + s.port() + "/nope/", false, null);
                    check(p + "missing folder fails", false);
                } catch (IOException e) {
                    check(p + "missing folder fails", e.getMessage().contains("cannot list"));
                }
            } finally {
                s.close();
            }
        }
        DownloadEngine.ftpsTrustManagerForTest = null;
        TlsPins.set(new TlsPins(null));
    }

    private static void testSftpWire() throws Exception {
        try {
            java.security.Signature.getInstance("Ed25519");
        } catch (Exception e) {
            System.out.println("  SKIP: needs the JDK's Ed25519 (JDK 15+)");
            return;
        }
        TestSshServer s = new TestSshServer();
        s.files.put("/pub/app.apk", new byte[777]);
        s.mtimes.put("/pub/app.apk", Long.valueOf(1791336162L));
        s.files.put("/pub/apk/x.apk", new byte[5]);
        s.directories.add("/pub/empty");
        s.links.put("/pub/latest.apk", "/pub/app.apk");
        s.links.put("/pub/to-apk", "/pub/apk");
        s.links.put("/pub/broken", "/nowhere");
        s.start();
        try {
            KnownHosts kh = new KnownHosts(null);
            SshConfig.set(kh, new SshKeyStore(null));
            String base = "sftp://user:pw@127.0.0.1:" + s.port() + "/pub/";
            try {
                new DownloadEngine().list(base, false, null);
                check("sftp list: unknown host key asks first", false);
            } catch (IOException e) {
                check("sftp list: unknown host key asks first", e instanceof UserQuestion);
            }
            kh.trust(KnownHosts.hostPort("127.0.0.1", s.port()), s.hostKeyBlob());
            List<RemoteEntry> l = new DownloadEngine().list(base, false, null);
            checkEq("sftp list: entries (broken link left out)", "apk/,app.apk,empty/,latest.apk,to-apk/", sorted(l));
            checkEq("sftp list: size", 777L, find(l, "app.apk").size);
            checkEq("sftp list: time", 1791336162000L, find(l, "app.apk").modified);
            checkEq("sftp list: a link to a file has its size", 777L, find(l, "latest.apk").size);
            checkEq("sftp list: into a folder", "x.apk", names(new DownloadEngine().list(find(l, "apk").url, false, null)));
            HttpTests.Recorder rec = new HttpTests.Recorder();
            new DownloadEngine().execute(find(l, "app.apk").url, HttpTests.tempDir(), false, false, false, null, null, rec);
            check("sftp list: an entry's url downloads", rec.completed != null && rec.completed.length() == 777);
        } finally {
            s.close();
            SshConfig.set(new KnownHosts(null), new SshKeyStore(null));
        }
    }

    private static String sorted(List<RemoteEntry> l) {
        List<String> n = new ArrayList<String>();
        for (RemoteEntry e : l) n.add(e.name + (e.directory ? "/" : ""));
        java.util.Collections.sort(n);
        StringBuilder sb = new StringBuilder();
        for (String x : n) sb.append(sb.length() > 0 ? "," : "").append(x);
        return sb.toString();
    }

    private static void testHttpWire() throws Exception {
        final String page = "<a href=\"../\">../</a><a href=\"a.apk\">a.apk</a><a href=\"d/\">d/</a>";
        HttpTests.Server dav = new HttpTests.Server(new HttpTests.Handler() {
            public void handle(int n, HttpTests.Request r, OutputStream out, HttpTests.Server sv) throws IOException {
                if (r.h("authorization") == null) {
                    HttpTests.respond(out, "401 Unauthorized", new String[] { "WWW-Authenticate: Basic realm=\"dav\"", "Content-Length: 0" }, null, 0, 0);
                    return;
                }
                if (r.line.startsWith("PROPFIND /dav/ ")) {
                    HttpTests.respond(out, "301 Moved", new String[] { "Location: /dav/pub/", "Content-Length: 0" }, null, 0, 0);
                    return;
                }
                byte[] xml = DAV_APACHE.replace("http://nas:8080", "").getBytes("UTF-8");
                boolean ok = r.line.startsWith("PROPFIND /dav/pub/ ") && "1".equals(r.h("depth"));
                HttpTests.respond(out, ok ? "207 Multi-Status" : "400 Bad", new String[] { "Content-Type: application/xml",
                        "Content-Length: " + (ok ? xml.length : 0) }, ok ? xml : null, 0, ok ? xml.length : 0);
            }
        });
        HttpTests.Server index = new HttpTests.Server(new HttpTests.Handler() {
            public void handle(int n, HttpTests.Request r, OutputStream out, HttpTests.Server sv) throws IOException {
                if (r.line.startsWith("PROPFIND")) {
                    HttpTests.respond(out, "405 Method Not Allowed", new String[] { "Content-Length: 0" }, null, 0, 0);
                    return;
                }
                byte[] b = page.getBytes("UTF-8");
                HttpTests.respond(out, "200 OK", new String[] { "Content-Type: text/html", "Content-Length: " + b.length }, b, 0, b.length);
            }
        });
        try {
            List<RemoteEntry> l = new DownloadEngine().list("http://me:pw@127.0.0.1:" + dav.port() + "/dav", false, null);
            checkEq("webdav: entries after a 401 and a redirect", "reteget-0.5.0.apk,My Files/,a&b€.txt", names(l));
            checkEq("webdav: entry url on the redirected folder, with the user info",
                    "http://me:pw@127.0.0.1:" + dav.port() + "/dav/pub/reteget-0.5.0.apk", find(l, "reteget-0.5.0.apk").url);
            l = new DownloadEngine().list("http://127.0.0.1:" + index.port() + "/apk/", false, null);
            checkEq("index page after PROPFIND is refused", "a.apk,d/", names(l));
            check("index page: GET after PROPFIND", index.requests.size() == 2 && index.requests.get(1).line.startsWith("GET /apk/ "));
        } finally {
            dav.close();
            index.close();
        }
    }
}
