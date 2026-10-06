package org.reteget.core;

import java.io.File;
import java.util.Arrays;
import java.util.List;
import java.util.Random;
import org.reteget.core.ssh.KnownHosts;
import org.reteget.core.ssh.SshConfig;
import org.reteget.core.ssh.SshKeyFile;
import org.reteget.core.ssh.SshKeyStore;
import org.reteget.core.ssh.SshPromptException;
import org.reteget.core.ssh.TestSshServer;

/**
 * sftp:// through DownloadEngine and the queue: host key decisions, keys and passphrases,
 * resume. The server is the JDK-crypto test server of the ssh tests.
 */
public final class SftpEngineTests {

    public static int passed = 0;
    public static int failed = 0;

    private SftpEngineTests() {}

    static final byte[] FILE = bytes(400000, 21);
    static final byte[] FILE2 = bytes(350000, 22);

    private static byte[] bytes(int n, int seed) {
        byte[] b = new byte[n];
        new Random(seed).nextBytes(b);
        return b;
    }

    public static void run() {
        System.out.println("\n[sftp:// downloads]");
        try {
            java.security.Signature.getInstance("Ed25519");
        } catch (Exception e) {
            System.out.println("  SKIP: needs the JDK's Ed25519 (JDK 15+)");
            return;
        }
        testRecords();
        testHostKeyFlow();
        testAddresses();
        testResume();
        testKeys();
        testQueue();
        SshConfig.set(new KnownHosts(null), new SshKeyStore(null));
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
        check(msg + (expected == null ? actual == null : expected.equals(actual) ? "" : " (expected [" + expected + "], got [" + actual + "])"),
                expected == null ? actual == null : expected.equals(actual));
    }

    /** A string kept in memory, standing in for the app's preferences. */
    static final class Mem implements KnownHosts.Store, SshKeyStore.Store, DownloadQueue.Store {
        String data;

        public String load() {
            return data;
        }

        public void save(String d) {
            data = d;
        }
    }

    private static TestSshServer server() throws Exception {
        TestSshServer s = new TestSshServer();
        s.files.put("/pub/app.apk", FILE);
        return s;
    }

    private static String url(TestSshServer s, String userInfo, String path) {
        return "sftp://" + userInfo + "@127.0.0.1:" + s.port() + path;
    }

    private static HttpTests.Recorder get(String url, File dir, DownloadEngine.Resume resume, String key, long... backoff) {
        HttpTests.Recorder rec = new HttpTests.Recorder();
        HttpTests.engine(backoff).execute(url, dir, false, false, false, resume, key, rec);
        return rec;
    }

    /** Fresh records with {@code s}'s host key already accepted. */
    private static KnownHosts trusting(TestSshServer s) throws Exception {
        KnownHosts kh = new KnownHosts(new Mem());
        kh.trust(KnownHosts.hostPort("127.0.0.1", s.port()), s.hostKeyBlob());
        SshConfig.set(kh, new SshKeyStore(new Mem()));
        return kh;
    }

    private static void testRecords() {
        try {
            TestSshServer s = server().start();
            Mem mem = new Mem();
            KnownHosts kh = new KnownHosts(mem);
            kh.trust("nas.local:22", s.hostKeyBlob());
            kh.trust("other:2222", s.hostKeyBlob());
            KnownHosts again = new KnownHosts(mem);
            check("host key record survives a reload", again.all().size() == 2 && again.get("nas.local:22") != null
                    && again.get("nas.local:22").fingerprint.startsWith("SHA256:") && "ssh-ed25519".equals(again.keyTypeFor("other:2222")));
            KnownHosts target = new KnownHosts(new Mem());
            target.trust("other:2222", TestSshServer.blob(TestSshServer.generate("ssh-ed25519").getPublic()));
            String before = target.get("other:2222").fingerprint;
            checkEq("import adds only the hosts that are missing", 1, target.importMissing(again.export()));
            checkEq("import never replaces a recorded key", before, target.get("other:2222").fingerprint);
            again.remove("nas.local:22");
            check("removed host is gone after a reload", new KnownHosts(mem).get("nas.local:22") == null);
            checkEq("host names are compared in lower case", "nas.local:22", KnownHosts.hostPort("NAS.Local", 22));
            s.close();

            Mem keys = new Mem();
            SshKeyStore ks = new SshKeyStore(keys);
            SshKeyStore.Key k = ks.generate("phone key", "pass phrase");
            SshKeyStore.Key open = ks.generate("open key", null);
            check("generated key: protected, with a public line", k.isProtected && k.publicKeyLine().startsWith("ssh-ed25519 AAAA")
                    && k.publicKeyLine().endsWith(" phone key"));
            check("stored keys are not readable in the store", !keys.data.contains("PRIVATE KEY"));
            SshKeyStore reloaded = new SshKeyStore(keys);
            check("key store survives a reload, locked", reloaded.list().size() == 2 && !reloaded.isUnlocked(k.fingerprint)
                    && reloaded.isUnlocked(open.fingerprint));
            boolean asked = false;
            try {
                reloaded.identity(k.fingerprint);
            } catch (SshPromptException e) {
                asked = SshPromptException.PASSPHRASE.equals(e.kind) && k.fingerprint.equals(e.identityFingerprint)
                        && "phone key".equals(e.identityName);
            }
            check("a locked key asks for its passphrase", asked);
            boolean wrong = false;
            try {
                reloaded.unlock(k.fingerprint, "nope");
            } catch (java.io.IOException e) {
                wrong = "Wrong passphrase".equals(e.getMessage());
            }
            check("wrong passphrase leaves the key locked", wrong && !reloaded.isUnlocked(k.fingerprint));
            reloaded.unlock(k.fingerprint, "pass phrase");
            check("unlocked key signs", reloaded.identity(k.fingerprint) != null && reloaded.isUnlocked(k.fingerprint));
            reloaded.lockAll();
            check("lockAll forgets it", !reloaded.isUnlocked(k.fingerprint));
            reloaded.setPassphrase(open.fingerprint, null, "now locked");
            check("a passphrase can be added to an open key", reloaded.find(open.fingerprint).isProtected
                    && new SshKeyStore(keys).find(open.fingerprint).isProtected);
            boolean dup = false;
            try {
                reloaded.add("again", SshKeyFile.parse(SshKeyFile.generateEd25519("x", null).text()));
                reloaded.add("copy", reloaded.list().get(2).file());
            } catch (java.io.IOException e) {
                dup = e.getMessage().contains("already stored");
            }
            check("the same key is not stored twice", dup);
            reloaded.remove(k.fingerprint);
            check("removed key is gone after a reload", new SshKeyStore(keys).find(k.fingerprint) == null);
            boolean missing = false;
            try {
                reloaded.identity(k.fingerprint);
            } catch (java.io.IOException e) {
                missing = e.getMessage().contains("no longer stored");
            }
            check("a download whose key was removed says so", missing);
        } catch (Exception e) {
            check("records: " + e, false);
        }
    }

    private static void testHostKeyFlow() {
        TestSshServer s = null;
        try {
            s = server().start();
            KnownHosts kh = new KnownHosts(new Mem());
            SshConfig.set(kh, new SshKeyStore(new Mem()));
            String hp = KnownHosts.hostPort("127.0.0.1", s.port());
            File dir = HttpTests.tempDir();

            HttpTests.Recorder r = get(url(s, "user:pw", "/pub/app.apk"), dir, null, null);
            SshPromptException ask = r.error instanceof SshPromptException ? (SshPromptException) r.error : null;
            check("unknown host: the download stops and asks", ask != null && SshPromptException.UNKNOWN_HOST.equals(ask.kind)
                    && hp.equals(ask.hostPort) && "ssh-ed25519".equals(ask.keyType));
            check("unknown host: nothing was sent to log in, nothing written",
                    !s.log.contains("auth none") && HttpTests.noPartLeft(dir) && dir.list().length == 0);
            SshPromptException back = SshPromptException.fromToken(ask.token());
            check("the question survives as a token", back != null && back.kind.equals(ask.kind)
                    && back.fingerprint.equals(ask.fingerprint) && back.hostPort.equals(hp));

            kh.trust(ask.hostPort, org.reteget.core.ssh.TestKeys.decode(ask.blobBase64));
            DownloadEngine e = HttpTests.engine();
            r = new HttpTests.Recorder();
            e.execute(url(s, "user:pw", "/pub/app.apk"), dir, false, false, false, null, null, r);
            check("after 'trust' the download completes: " + r.error, r.completed != null && Arrays.equals(FILE, HttpTests.read(r.completed)));
            checkEq("file name from the path", "app.apk", r.completed == null ? null : r.completed.getName());
            check("connection summary for the queue entry", String.valueOf(e.getLastTlsSummary()).startsWith("SSH curve25519-sha256 "));
            checkEq("validator is size:mtime", FILE.length + ":1700000000", r.validator);

            s.newHostKey();
            String oldFp = kh.get(hp).fingerprint;
            r = get(url(s, "user:pw", "/pub/app.apk"), dir, null, null);
            ask = r.error instanceof SshPromptException ? (SshPromptException) r.error : null;
            check("changed host key: blocked, both fingerprints given", ask != null && SshPromptException.CHANGED_HOST.equals(ask.kind)
                    && oldFp.equals(ask.oldFingerprint) && !oldFp.equals(ask.fingerprint) && ask.getMessage().contains("has changed"));
            checkEq("changed host key: the record is not touched", oldFp, kh.get(hp).fingerprint);
            back = SshPromptException.fromToken(ask.token());
            check("the changed-key question survives as a token", back != null && oldFp.equals(back.oldFingerprint));
            kh.trust(hp, org.reteget.core.ssh.TestKeys.decode(ask.blobBase64));
            r = get(url(s, "user:pw", "/pub/app.apk"), dir, null, null);
            check("after replacing the key it works again", r.completed != null);
        } catch (Exception e) {
            check("host key flow: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    private static void testAddresses() {
        TestSshServer s = null;
        try {
            s = server();
            s.files.put("/pub/a b+c.bin", FILE2);
            s.files.put("home.bin", FILE2);
            s.directories.add("/pub");
            s.password = "p@ss:w/rd";
            s.start();
            trusting(s);
            File dir = HttpTests.tempDir();
            HttpTests.Recorder r = get(url(s, "user:p%40ss%3Aw%2Frd", "/pub/a%20b+c.bin"), dir, null, null);
            check("percent-encoded password and path: " + r.error, r.completed != null && Arrays.equals(FILE2, HttpTests.read(r.completed)));
            checkEq("decoded file name", "a b+c.bin", r.completed == null ? null : r.completed.getName());
            r = get(url(s, "user:p%40ss%3Aw%2Frd", "/~/home.bin"), dir, null, null);
            check("/~/ path", r.completed != null && s.log.contains("stat home.bin"));
            r = get("sftp://127.0.0.1:" + s.port() + "/pub/app.apk", dir, null, null);
            check("no user name: explained", r.error != null && r.error.getMessage().contains("needs a user name"));
            r = get(url(s, "user:p%40ss%3Aw%2Frd", "/pub/"), dir, null, null);
            check("address ending in /: explained", r.error != null && r.error.getMessage().contains("must name a file"));
            r = get(url(s, "user:p%40ss%3Aw%2Frd", "/pub"), dir, null, null);
            check("a directory: explained", r.error != null && r.error.getMessage().contains("directory"));
            r = get(url(s, "user:wrong", "/pub/app.apk"), dir, null, null);
            check("wrong password", r.error != null && r.error.getMessage().startsWith("Authentication failed"));
            r = get(url(s, "user", "/pub/app.apk"), dir, null, null);
            check("user without password: hint", r.error != null && r.error.getMessage().contains("needs a password"));
            check("failed logins leave nothing behind", HttpTests.noPartLeft(dir));
        } catch (Exception e) {
            check("addresses: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    private static int firstReadOffsetOfLastConnection(TestSshServer s) {
        int lastStat = s.log.lastIndexOf("stat /pub/app.apk");
        for (int i = lastStat; i < s.log.size(); i++) {
            String l = s.log.get(i);
            if (l.startsWith("read ")) return Integer.parseInt(l.split(" ")[1]);
        }
        return -1;
    }

    private static void testResume() {
        TestSshServer s = null;
        try {
            s = server();
            s.cutAfterFileBytes = 150000;
            s.start();
            trusting(s);
            File dir = HttpTests.tempDir();
            HttpTests.Recorder r = get(url(s, "user:pw", "/pub/app.apk"), dir, null, null, 1, 1, 1);
            check("cut connection: resumes on its own and completes: " + r.error,
                    r.completed != null && Arrays.equals(FILE, HttpTests.read(r.completed)));
            check("cut connection: second connection starts where the first stopped",
                    s.connections == 2 && r.resumedAt > 0 && r.resumedAt == firstReadOffsetOfLastConnection(s));
            check("cut connection: no .part left", HttpTests.noPartLeft(dir));
            s.close();

            s = server();
            s.cutAfterFileBytes = 200000;
            s.start();
            trusting(s);
            dir = HttpTests.tempDir();
            HttpTests.Recorder first = get(url(s, "user:pw", "/pub/app.apk"), dir, null, null);
            File part = first.partPath == null ? null : new File(first.partPath);
            check("without automatic resumes the run fails and keeps the .part",
                    first.error != null && part != null && part.length() > 0 && part.getName().equals("app.apk.part"));
            long have = part == null ? -1 : part.length();
            HttpTests.Recorder second = get(url(s, "user:pw", "/pub/app.apk"), dir,
                    new DownloadEngine.Resume("app.apk", first.validator, first.total), null);
            check("Retry resumes from the .part: " + second.error, second.completed != null
                    && Arrays.equals(FILE, HttpTests.read(second.completed)) && second.resumedAt == have
                    && firstReadOffsetOfLastConnection(s) == have);

            // the file changed on the server between the attempts
            dir = HttpTests.tempDir();
            java.io.FileOutputStream o = new java.io.FileOutputStream(new File(dir, "app.apk.part"));
            o.write(FILE, 0, 100000);
            o.close();
            s.mtimes.put("/pub/app.apk", Long.valueOf(1700000999L));
            HttpTests.Recorder third = get(url(s, "user:pw", "/pub/app.apk"), dir,
                    new DownloadEngine.Resume("app.apk", FILE.length + ":1700000000", FILE.length), null);
            check("changed file: fetched again from the start", third.completed != null && Arrays.equals(FILE, HttpTests.read(third.completed))
                    && third.notices.contains(DownloadEngine.NOTICE_RESTARTED) && third.resumedAt == -1
                    && firstReadOffsetOfLastConnection(s) == 0);

            // the .part already holds everything
            dir = HttpTests.tempDir();
            o = new java.io.FileOutputStream(new File(dir, "app.apk.part"));
            o.write(FILE);
            o.close();
            int readsBefore = 0;
            for (String l : s.log) if (l.startsWith("read ")) readsBefore++;
            HttpTests.Recorder fourth = get(url(s, "user:pw", "/pub/app.apk"), dir,
                    new DownloadEngine.Resume("app.apk", FILE.length + ":1700000999", FILE.length), null);
            int readsAfter = 0;
            for (String l : s.log) if (l.startsWith("read ")) readsAfter++;
            check("complete .part: finished without reading", fourth.completed != null && readsAfter == readsBefore
                    && Arrays.equals(FILE, HttpTests.read(fourth.completed)));

            dir = HttpTests.tempDir();
            HttpTests.Recorder c = new HttpTests.Recorder();
            DownloadEngine e = HttpTests.engine();
            c.cancelOnPartial = e;
            e.execute(url(s, "user:pw", "/pub/app.apk"), dir, false, false, false, null, null, c);
            check("cancel: onCancel, .part deleted", c.cancelledCalled && c.completed == null && dir.list().length == 0);
        } catch (Exception e) {
            check("resume: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }

    private static void testKeys() {
        TestSshServer s = null;
        try {
            s = server();
            s.allowPassword = false;
            s.start();
            trusting(s);
            SshKeyStore ks = SshConfig.keys();
            SshKeyStore.Key k = ks.generate("nas", "key pass");
            s.authorizedKeys.add(k.file().publicBlob());
            ks.lockAll();
            File dir = HttpTests.tempDir();
            int before = s.connections;
            HttpTests.Recorder r = get(url(s, "user", "/pub/app.apk"), dir, null, k.fingerprint);
            check("locked key: asks for the passphrase before connecting", r.error instanceof SshPromptException
                    && SshPromptException.PASSPHRASE.equals(((SshPromptException) r.error).kind) && s.connections == before);
            ks.unlock(k.fingerprint, "key pass");
            r = get(url(s, "user", "/pub/app.apk"), dir, null, k.fingerprint);
            check("unlocked key logs in: " + r.error, r.completed != null && Arrays.equals(FILE, HttpTests.read(r.completed))
                    && s.log.contains("publickey ssh-ed25519 signed") && !s.log.contains("auth password"));
            r = get(url(s, "user", "/pub/app.apk"), dir, null, null);
            check("no key chosen: the key is not offered", r.error != null && r.error.getMessage().contains("needs a key"));
            r = get(url(s, "user", "/pub/app.apk"), dir, null, "SHA256:nosuchkey");
            check("chosen key missing from the store", r.error != null && r.error.getMessage().contains("no longer stored"));
        } catch (Exception e) {
            check("keys: " + e, false);
        } finally {
            if (s != null) s.close();
        }
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

    private static void testQueue() {
        TestSshServer s = null;
        try {
            s = server().start();
            KnownHosts kh = new KnownHosts(new Mem());
            SshKeyStore ks = new SshKeyStore(new Mem());
            SshConfig.set(kh, ks);
            SshKeyStore.Key k = ks.generate("queue key", "qp");
            ks.lockAll();
            s.authorizedKeys.add(k.file().publicBlob());
            s.allowPassword = false;
            Mem mem = new Mem();
            DownloadQueue q = new DownloadQueue(mem, DownloadQueue.defaultEngines());
            File dir = HttpTests.tempDir();
            String u = url(s, "user:secretpw", "/pub/app.apk");
            DownloadTask t = q.enqueue(u, dir, false, false, "", null, null, k.fingerprint);

            DownloadTask f = waitFor(q, t.id, DownloadTask.State.FAILED);
            SshPromptException ask = f == null ? null : SshPromptException.fromToken(f.ask);
            check("queue: locked key -> the entry waits with a passphrase question",
                    ask != null && SshPromptException.PASSPHRASE.equals(ask.kind) && k.fingerprint.equals(f.sshKey));
            check("queue: question and key choice are in the saved record", mem.data.contains("\"ask\":") && mem.data.contains("\"sshkey\":"));
            DownloadQueue reloaded = new DownloadQueue(mem, DownloadQueue.defaultEngines());
            check("queue: the question is still there after a restart",
                    SshPromptException.fromToken(reloaded.snapshot().get(0).ask) != null);

            ks.unlock(k.fingerprint, "qp");
            q.retry(t.id);
            f = waitFor(q, t.id, DownloadTask.State.FAILED);
            ask = f == null ? null : SshPromptException.fromToken(f.ask);
            check("queue: then the unknown host key question", ask != null && SshPromptException.UNKNOWN_HOST.equals(ask.kind));
            check("queue: error text carries no password", f != null && !String.valueOf(f.error).contains("secretpw"));

            kh.trust(ask.hostPort, org.reteget.core.ssh.TestKeys.decode(ask.blobBase64));
            q.retry(t.id);
            DownloadTask d = waitFor(q, t.id, DownloadTask.State.DONE);
            check("queue: after both answers the download finishes", d != null && d.ask == null
                    && Arrays.equals(FILE, HttpTests.read(new File(d.filePath))) && String.valueOf(d.tlsSummary).startsWith("SSH "));
        } catch (Exception e) {
            check("queue: " + e, false);
        } finally {
            if (s != null) s.close();
        }
    }
}
