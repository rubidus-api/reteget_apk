package org.reteget.core;

import java.io.File;
import java.util.Arrays;
import java.util.Random;
import org.reteget.core.tls.TlsTests;

/** ftp://, ftpes:// and ftps:// through DownloadEngine and the queue, against TestFtpServer. */
public final class FtpEngineTests {

    public static int passed = 0;
    public static int failed = 0;

    private FtpEngineTests() {}

    static final byte[] FILE = bytes(400000, 31);

    private static byte[] bytes(int n, int seed) {
        byte[] b = new byte[n];
        new Random(seed).nextBytes(b);
        return b;
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

    private static File ks1, ks2;

    public static void run() {
        System.out.println("\n[FTP and FTPS downloads]");
        try {
            testPlain();
            ks1 = TlsTests.keystore("ftps-a", "-keyalg EC -groupname secp256r1", "dns:localhost,ip:127.0.0.1");
            ks2 = TlsTests.keystore("ftps-b", "-keyalg RSA -keysize 2048", "dns:localhost,ip:127.0.0.1");
            if (ks1 == null || ks2 == null) {
                System.out.println("  SKIP: keytool is missing; FTPS tests not run");
                return;
            }
            testCertificateQuestion();
            testTlsModes();
            testFtpsFailures();
            testFtpsResumeAndQueue();
        } catch (Exception e) {
            check("ftp tests: " + e, false);
        } finally {
            DownloadEngine.ftpsTrustManagerForTest = null;
            TlsPins.set(new TlsPins(null));
        }
    }

    static final class Mem implements TlsPins.Store, DownloadQueue.Store {
        String data;

        public String load() {
            return data;
        }

        public void save(String d) {
            data = d;
        }
    }

    private static TestFtpServer server(String mode) throws Exception {
        TestFtpServer s = new TestFtpServer();
        s.mode = mode;
        s.files.put("/pub/app.apk", FILE);
        return s;
    }

    private static String url(String scheme, TestFtpServer s, String userInfo, String path) {
        return scheme + "://" + (userInfo == null ? "" : userInfo + "@") + "127.0.0.1:" + s.port() + path;
    }

    private static HttpTests.Recorder get(String url, File dir, DownloadEngine.Resume resume, long... backoff) {
        HttpTests.Recorder rec = new HttpTests.Recorder();
        HttpTests.engine(backoff).execute(url, dir, false, false, false, resume, rec);
        return rec;
    }

    private static boolean ok(HttpTests.Recorder r) {
        return r.completed != null && Arrays.equals(FILE, HttpTests.read(r.completed));
    }

    private static String msg(HttpTests.Recorder r) {
        return r.error == null ? "" : String.valueOf(r.error.getMessage());
    }

    private static int count(TestFtpServer s, String prefix) {
        int n = 0;
        for (String l : s.log) if (l.startsWith(prefix)) n++;
        return n;
    }

    private static void testPlain() throws Exception {
        TestFtpServer s = server("plain").start(null);
        File dir = HttpTests.tempDir();
        HttpTests.Recorder r = get(url("ftp", s, "user:pw", "/pub/app.apk"), dir, null);
        check("ftp: download with a password: " + msg(r), ok(r) && "app.apk".equals(r.completed.getName()));
        check("ftp: password in the clear is noted", r.notices.contains(DownloadEngine.NOTICE_CLEARTEXT_PASSWORD));
        check("ftp: validator is size:MDTM", (FILE.length + ":20240102030405").equals(r.validator));
        check("ftp: EPSV is used", count(s, "clear EPSV") == 1 && count(s, "clear PASV") == 0);
        r = get(url("ftp", s, null, "/pub/app.apk"), dir, null);
        check("ftp: anonymous download, no password note", ok(r) && !r.notices.contains(DownloadEngine.NOTICE_CLEARTEXT_PASSWORD)
                && s.log.contains("clear USER anonymous"));
        r = get(url("ftp", s, "user:wrong", "/pub/app.apk"), dir, null);
        check("ftp: wrong password", msg(r).contains("check the user name and password"));
        r = get(url("ftp", s, "user:pw", "/pub/missing.bin"), dir, null);
        check("ftp: missing file", msg(r).contains("cannot send this file") && HttpTests.noPartLeft(dir));
        r = get(url("ftp", s, "user:pw", "/pub/"), dir, null);
        check("ftp: address without a file name", msg(r).contains("must name a file"));
        s.close();

        s = server("plain");
        s.supportEpsv = false;
        s.start(null);
        r = get(url("ftp", s, "user:pw", "/pub/app.apk"), dir, null);
        check("ftp: PASV when EPSV is refused, and the address in the reply is ignored: " + msg(r), ok(r) && count(s, "clear PASV") == 1);
        s.close();

        s = server("plain");
        s.cutAfter = 150000;
        s.start(null);
        dir = HttpTests.tempDir();
        r = get(url("ftp", s, "user:pw", "/pub/app.apk"), dir, null, 1, 1, 1);
        check("ftp: cut transfer resumes with REST and completes: " + msg(r),
                ok(r) && s.log.contains("clear REST 150000") && r.resumedAt == 150000 && HttpTests.noPartLeft(dir));
        s.close();

        s = server("plain");
        s.cutAfter = 100000;
        s.start(null);
        dir = HttpTests.tempDir();
        HttpTests.Recorder first = get(url("ftp", s, "user:pw", "/pub/app.apk"), dir, null);
        check("ftp: without automatic resumes the .part is kept", first.error != null && first.partPath != null
                && new File(first.partPath).length() == 100000);
        s.supportRest = false;
        r = get(url("ftp", s, "user:pw", "/pub/app.apk"), dir, new DownloadEngine.Resume("app.apk", first.validator, first.total));
        check("ftp: server without REST: fetched again from the start: " + msg(r),
                ok(r) && r.notices.contains(DownloadEngine.NOTICE_RESTARTED) && r.resumedAt == -1);
        s.close();

        s = server("plain");
        s.supportMdtm = false;
        s.cutAfter = 100000;
        s.start(null);
        dir = HttpTests.tempDir();
        r = get(url("ftp", s, "user:pw", "/pub/app.apk"), dir, null, 1, 1);
        check("ftp: no MDTM, no resume: the cut is an error and nothing is kept", r.error != null && r.validator == null
                && HttpTests.noPartLeft(dir) && s.sessions == 1);
        s.transfers = 0;
        s.close();

        s = server("plain").start(null);
        dir = HttpTests.tempDir();
        java.io.FileOutputStream o = new java.io.FileOutputStream(new File(dir, "app.apk.part"));
        o.write(new byte[5000]);
        o.close();
        s.mdtm.put("/pub/app.apk", "20250101000000");
        r = get(url("ftp", s, "user:pw", "/pub/app.apk"), dir, new DownloadEngine.Resume("app.apk", FILE.length + ":20240102030405", FILE.length));
        check("ftp: changed file is fetched again from the start", ok(r) && r.notices.contains(DownloadEngine.NOTICE_RESTARTED) && count(s, "clear REST") == 0);
        HttpTests.Recorder c = new HttpTests.Recorder();
        DownloadEngine e = HttpTests.engine();
        c.cancelOnPartial = e;
        dir = HttpTests.tempDir();
        e.execute(url("ftp", s, "user:pw", "/pub/app.apk"), dir, false, false, false, null, c);
        check("ftp: cancel deletes the .part", c.cancelledCalled && dir.list().length == 0);
        s.close();

        s = server("plain").start(null);
        r = get(url("ftpes", s, "user:pw", "/pub/app.apk"), HttpTests.tempDir(), null);
        check("ftpes: a server without AUTH TLS is refused, nothing sent in the clear",
                msg(r).contains("does not offer FTP over TLS") && count(s, "clear USER") == 0 && count(s, "clear PASS") == 0);
        s.close();
    }

    private static void testCertificateQuestion() throws Exception {
        Mem mem = new Mem();
        TlsPins.set(new TlsPins(mem));
        DownloadEngine.ftpsTrustManagerForTest = TlsTests.trustManagerFor(ks2); // does not know ks1's certificate
        TestFtpServer s = server("explicit").start(ks1);
        String hp = TlsPins.hostPort("127.0.0.1", s.port());
        File dir = HttpTests.tempDir();
        HttpTests.Recorder r = get(url("ftpes", s, "user:pw", "/pub/app.apk"), dir, null);
        TlsCertQuestion q = r.error instanceof TlsCertQuestion ? (TlsCertQuestion) r.error : null;
        check("ftpes: an untrusted certificate asks the user, with its fingerprint: " + msg(r), q != null
                && TlsCertQuestion.UNKNOWN.equals(q.kind) && hp.equals(q.hostPort) && q.fingerprint.length() == 95);
        check("ftpes: nothing was sent before the answer", count(s, "tls USER") == 0 && count(s, "clear USER") == 0 && dir.list().length == 0);
        TlsCertQuestion back = TlsCertQuestion.fromToken(q.token());
        check("the certificate question survives as a token", back != null && back.fingerprint.equals(q.fingerprint)
                && back.hostPort.equals(hp) && back.kind.equals(q.kind));
        TlsPins.get().trust(q);
        check("the accepted certificate is on record after a reload", q.fingerprint.equals(new TlsPins(mem).get(hp)));
        DownloadEngine e = HttpTests.engine();
        r = new HttpTests.Recorder();
        e.execute(url("ftpes", s, "user:pw", "/pub/app.apk"), dir, false, false, false, null, r);
        check("ftpes: after 'trust' the download completes: " + msg(r), ok(r));
        check("ftpes: user name and password only inside TLS", count(s, "tls USER") == 1 && count(s, "tls PASS") == 1
                && count(s, "clear USER") == 0 && count(s, "clear PASS") == 0 && s.log.contains("clear AUTH TLS"));
        check("ftpes: data connection protected and resumed (" + e.getLastTlsSummary() + "; server: " + s.lastDataReuse + ")",
                s.log.contains("tls PROT P") && s.lastDataReuse.endsWith("reused")
                        && String.valueOf(e.getLastTlsSummary()).endsWith("data connection resumed"));
        check("ftpes: no cleartext-password note", !r.notices.contains(DownloadEngine.NOTICE_CLEARTEXT_PASSWORD));

        s.useKeystore(ks2);
        DownloadEngine.ftpsTrustManagerForTest = TlsTests.trustManagerFor(ks2); // even a certificate that now validates
        r = get(url("ftpes", s, "user:pw", "/pub/app.apk"), dir, null);
        q = r.error instanceof TlsCertQuestion ? (TlsCertQuestion) r.error : null;
        check("ftpes: another certificate than the recorded one is blocked: " + msg(r), q != null && TlsCertQuestion.CHANGED.equals(q.kind)
                && q.oldFingerprint != null && !q.oldFingerprint.equals(q.fingerprint) && msg(r).contains("has changed"));
        back = q == null ? null : TlsCertQuestion.fromToken(q.token());
        check("the changed-certificate question survives as a token", back != null && back.oldFingerprint.equals(q.oldFingerprint));
        TlsPins.get().trust(q);
        r = get(url("ftpes", s, "user:pw", "/pub/app.apk"), dir, null);
        check("ftpes: after replacing the record it works again", ok(r));
        s.close();

        // A certificate that validates needs no question and leaves no record.
        TlsPins.set(new TlsPins(new Mem()));
        s = server("explicit").start(ks2);
        r = get("ftpes://user:pw@localhost:" + s.port() + "/pub/app.apk", dir, null);
        check("ftpes: a certificate that validates is not asked about: " + msg(r), ok(r)
                && TlsPins.get().get(TlsPins.hostPort("localhost", s.port())) == null);
        s.close();
    }

    private static void testTlsModes() throws Exception {
        String[][] cases = { { "explicit", "ftpes", "TLSv1.3" }, { "explicit", "ftpes", "TLSv1.2" },
                { "implicit", "ftps", "TLSv1.3" }, { "implicit", "ftps", "TLSv1.2" } };
        DownloadEngine.ftpsTrustManagerForTest = TlsTests.trustManagerFor(ks1);
        TlsPins.set(new TlsPins(null));
        for (String[] c : cases) {
            TestFtpServer s = server(c[0]);
            s.protocols = new String[] { c[2] };
            s.start(ks1);
            DownloadEngine e = HttpTests.engine();
            HttpTests.Recorder r = new HttpTests.Recorder();
            e.execute(url(c[1], s, "user:pw", "/pub/app.apk"), HttpTests.tempDir(), false, false, false, null, r);
            String sum = String.valueOf(e.getLastTlsSummary());
            check(c[1] + " " + c[2] + ", server requires session reuse: " + msg(r) + " [" + sum + "]",
                    ok(r) && s.lastDataReuse.equals(c[2] + " reused") && sum.startsWith("FTPS TLS " + c[2].substring(4))
                            && sum.endsWith("data connection resumed"));
            check(c[1] + " " + c[2] + ": nothing in the clear but AUTH", count(s, "clear USER") == 0 && count(s, "clear PASS") == 0
                    // a TLS 1.2-only server is reached on the second connection, so AUTH is seen twice
                    && count(s, "clear") == (!"explicit".equals(c[0]) ? 0 : "TLSv1.2".equals(c[2]) ? 2 : 1));
            s.close();
        }
    }

    private static void testFtpsFailures() throws Exception {
        DownloadEngine.ftpsTrustManagerForTest = TlsTests.trustManagerFor(ks1);
        TlsPins.set(new TlsPins(null));
        TestFtpServer s = server("explicit");
        s.allowProtP = false;
        s.start(ks1);
        HttpTests.Recorder r = get(url("ftpes", s, "user:pw", "/pub/app.apk"), HttpTests.tempDir(), null);
        check("ftpes: a server that will not protect the data is refused", msg(r).contains("PROT P refused") && count(s, "tls RETR") == 0);
        s.close();

        s = server("explicit");
        s.protocols = new String[] { "TLSv1.2" };
        s.forgetSessionBeforeData = true; // the server cannot resume, yet insists on it
        s.start(ks1);
        r = get(url("ftpes", s, "user:pw", "/pub/app.apk"), HttpTests.tempDir(), null);
        check("ftpes: the server's 'session reuse required' reaches the user: " + msg(r), msg(r).contains("session reuse required"));
        s.close();

        s = server("explicit");
        s.requireReuse = false;
        s.forgetSessionBeforeData = true;
        s.protocols = new String[] { "TLSv1.2" };
        s.start(ks1);
        DownloadEngine e = HttpTests.engine();
        r = new HttpTests.Recorder();
        e.execute(url("ftpes", s, "user:pw", "/pub/app.apk"), HttpTests.tempDir(), false, false, false, null, r);
        check("ftpes: a server that does not resume and does not mind: full handshake on the data connection [" + e.getLastTlsSummary() + "]",
                ok(r) && String.valueOf(e.getLastTlsSummary()).endsWith("data connection not resumed"));
        s.close();

        s = server("explicit").start(ks1);
        r = get(url("ftpes", s, "user:nope", "/pub/app.apk"), HttpTests.tempDir(), null);
        check("ftpes: wrong password", msg(r).contains("check the user name and password"));
        r = get(url("ftp", s, "user:pw", "/pub/app.apk"), HttpTests.tempDir(), null);
        check("ftp:// to a TLS-only server fails without sending the password", r.error != null && count(s, "clear PASS") == 0);
        s.close();
    }

    private static DownloadTask waitFor(DownloadQueue q, long id, DownloadTask.State state) throws InterruptedException {
        for (int i = 0; i < 400; i++) {
            for (DownloadTask t : q.snapshot()) {
                if (t.id == id && t.state == state) return t;
            }
            Thread.sleep(25);
        }
        return null;
    }

    private static void testFtpsResumeAndQueue() throws Exception {
        DownloadEngine.ftpsTrustManagerForTest = TlsTests.trustManagerFor(ks1);
        TlsPins.set(new TlsPins(null));
        for (String proto : new String[] { "TLSv1.3", "TLSv1.2" }) {
            TestFtpServer s = server("explicit");
            s.protocols = new String[] { proto };
            s.cutAfter = 180000;
            s.start(ks1);
            File dir = HttpTests.tempDir();
            HttpTests.Recorder r = get(url("ftpes", s, "user:pw", "/pub/app.apk"), dir, null, 1, 1, 1);
            check("ftpes " + proto + ": a cut transfer resumes with REST over a new session: " + msg(r),
                    ok(r) && s.transfers == 2 && s.log.contains("tls REST 180000") && r.resumedAt == 180000 && HttpTests.noPartLeft(dir));
            s.close();
        }

        // Through the queue: the certificate question, then the download.
        DownloadEngine.ftpsTrustManagerForTest = TlsTests.trustManagerFor(ks2);
        TlsPins.set(new TlsPins(new Mem()));
        TestFtpServer s = server("implicit");
        s.password = "topsecret";
        s.start(ks1);
        Mem mem = new Mem();
        DownloadQueue q = new DownloadQueue(mem, DownloadQueue.defaultEngines());
        DownloadTask t = q.enqueue(url("ftps", s, "user:topsecret", "/pub/app.apk"), HttpTests.tempDir(), false, false, "");
        DownloadTask f = waitFor(q, t.id, DownloadTask.State.FAILED);
        TlsCertQuestion ask = f == null ? null : TlsCertQuestion.fromToken(f.ask);
        check("queue: an untrusted FTPS certificate leaves the entry waiting with the question", ask != null
                && mem.data.contains("\"ask\":") && !String.valueOf(f.error).contains("topsecret"));
        TlsPins.get().trust(ask);
        q.retry(t.id);
        DownloadTask d = waitFor(q, t.id, DownloadTask.State.DONE);
        if (d == null) System.err.println("  queue state: " + q.snapshot().get(0).state + " " + q.snapshot().get(0).error);
        check("queue: after the answer the FTPS download finishes", d != null && d.ask == null
                && Arrays.equals(FILE, HttpTests.read(new File(d.filePath))) && String.valueOf(d.tlsSummary).startsWith("FTPS TLS"));
        s.close();
    }
}
