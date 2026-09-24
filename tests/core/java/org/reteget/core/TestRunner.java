package org.reteget.core;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class TestRunner {

    private static int passed = 0;
    private static int failed = 0;

    public static void main(String[] args) {
        // Must precede any JSSE use: the JDK TLS server in TlsTests then rotates keys every
        // 64 KiB, which exercises KeyUpdate handling in the TLS 1.3 client.
        java.security.Security.setProperty("jdk.tls.keyLimits", "AES/GCM/NoPadding KeyUpdate 2^16");
        System.out.println("Running reteget unit tests...");

        testUrlTemplateBasic();
        testUrlTemplateNamed();
        testUrlTemplatePositional();
        testUrlTemplateDuplicates();
        testUrlTemplateNoPlaceholders();

        testFilenameExtraction();
        testContentDispositionFilename();
        testFilenameSanitization();

        testTlsHelperCertLoading();

        testChecksumExtraction();
        testChecksumAlgorithmDetection();
        testChecksumComputationAndVerification();
        testChecksumMultiHash();

        testApkSignatureExtraction();
        testApkSignatureCommonName();
        testApkSignatureNormalization();
        testApkSignatureContinuityVerification();

        testPresetItemSerialization();
        testPresetItemDisplayName();
        testPresetItemLegacyCompatibility();
        testPresetDefaultsAndMerge();
        testDownloadQueue();
        testIconResources();
        testSettingsBundle();

        testPureGcmEncryptionDecryption();
        testDownloadEngineSslErrorDetection();

        org.reteget.core.tls.TlsTests.run();
        passed += org.reteget.core.tls.TlsTests.passed;
        failed += org.reteget.core.tls.TlsTests.failed;

        System.out.println("\n-------------------------------------------");
        System.out.println("Test Results: " + passed + " passed, " + failed + " failed.");
        System.out.println("-------------------------------------------");

        if (failed > 0) {
            System.exit(1);
        }
    }

    private static void assertTrue(String msg, boolean condition) {
        if (condition) {
            passed++;
            System.out.println("  PASS: " + msg);
        } else {
            failed++;
            System.err.println("  FAIL: " + msg);
        }
    }

    private static void assertEquals(String msg, Object expected, Object actual) {
        boolean ok = (expected == null && actual == null) || (expected != null && expected.equals(actual));
        if (ok) {
            passed++;
            System.out.println("  PASS: " + msg);
        } else {
            failed++;
            System.err.println("  FAIL: " + msg + " (expected [" + expected + "], got [" + actual + "])");
        }
    }

    // --- UrlTemplate Tests ---

    private static void testUrlTemplateBasic() {
        UrlTemplate t = new UrlTemplate("https://url.com/aaaa-{1}-{2}.apk");
        assertTrue("hasPlaceholders", t.hasPlaceholders());
        List<String> placeholders = t.getPlaceholders();
        assertEquals("placeholder count", 2, placeholders.size());
        assertEquals("placeholder 0", "1", placeholders.get(0));
        assertEquals("placeholder 1", "2", placeholders.get(1));
    }

    private static void testUrlTemplateNamed() {
        UrlTemplate t = new UrlTemplate("https://github.com/{org}/{repo}/releases/download/v{version}/app-{version}.apk");
        Map<String, String> values = new HashMap<String, String>();
        values.put("org", "retro");
        values.put("repo", "myapp");
        values.put("version", "1.2.3");

        String resolved = t.resolve(values);
        assertEquals("resolved named template",
                "https://github.com/retro/myapp/releases/download/v1.2.3/app-1.2.3.apk", resolved);
    }

    private static void testUrlTemplatePositional() {
        UrlTemplate t = new UrlTemplate("https://url.com/aaaa-{1}-{2}.apk");
        String resolved = t.resolvePositional("v1.0", "armv7");
        assertEquals("resolved positional", "https://url.com/aaaa-v1.0-armv7.apk", resolved);
    }

    private static void testUrlTemplateDuplicates() {
        UrlTemplate t = new UrlTemplate("https://url.com/{1}/file-{1}.apk");
        List<String> p = t.getPlaceholders();
        assertEquals("distinct placeholders count", 1, p.size());
        assertEquals("distinct placeholder name", "1", p.get(0));

        Map<String, String> values = new HashMap<String, String>();
        values.put("1", "release");
        assertEquals("resolve duplicate placeholder",
                "https://url.com/release/file-release.apk", t.resolve(values));
    }

    private static void testUrlTemplateNoPlaceholders() {
        UrlTemplate t = new UrlTemplate("https://example.com/path/file.apk");
        assertTrue("no placeholders", !t.hasPlaceholders());
        assertEquals("identity resolve", "https://example.com/path/file.apk", t.resolve(null));
    }

    // --- DownloadEngine Tests ---

    private static void testFilenameExtraction() {
        String fn1 = DownloadEngine.extractFilename("https://example.com/releases/v1/F-Droid.apk", null);
        assertEquals("extract filename standard", "F-Droid.apk", fn1);

        String fn2 = DownloadEngine.extractFilename("https://example.com/download.php?file=archive.apk&token=123", null);
        assertEquals("extract filename from query path", "download.php", fn2);

        String fn3 = DownloadEngine.extractFilename("https://example.com/download/my%20test%20app.apk", null);
        assertEquals("extract URL decoded filename", "my test app.apk", fn3);
    }

    private static void testContentDispositionFilename() {
        String cd1 = "attachment; filename=\"custom_app_v2.apk\"";
        String fn1 = DownloadEngine.extractFilename("https://example.com/dl", cd1);
        assertEquals("extract from quoted Content-Disposition", "custom_app_v2.apk", fn1);

        String cd2 = "attachment; filename=bare_name.apk; size=1024";
        String fn2 = DownloadEngine.extractFilename("https://example.com/dl", cd2);
        assertEquals("extract from unquoted Content-Disposition", "bare_name.apk", fn2);
    }

    private static void testFilenameSanitization() {
        String badCd = "attachment; filename=\"bad/path:file?.apk\"";
        String fn = DownloadEngine.extractFilename("https://example.com/dl", badCd);
        assertEquals("sanitize illegal chars", "bad_path_file_.apk", fn);
    }

    // --- TlsHelper Tests ---

    private static void testTlsHelperCertLoading() {
        File rootsFile = new File("src/android/res/raw/trusted_roots.pem");
        assertTrue("roots.pem exists", rootsFile.exists());

        try {
            InputStream in = new FileInputStream(rootsFile);
            TlsHelper.init(in);
            assertTrue("compat socket factory created", TlsHelper.getSocketFactory(false) != null);
            assertTrue("insecure socket factory created", TlsHelper.getSocketFactory(true) != null);
            assertTrue("insecure hostname verifier created", TlsHelper.getHostnameVerifier(true) != null);
        } catch (Exception e) {
            assertTrue("cert loading exception: " + e.getMessage(), false);
        }
    }

    // --- ChecksumVerifier Tests ---

    private static void testChecksumExtraction() {
        String raw1 = "aadc789da2f43c7cecfff068ae2da9cd312983dc2da8bb424a264be91b773679  reteget-0.1.0.apk";
        assertEquals("extract GNU format hash",
                "aadc789da2f43c7cecfff068ae2da9cd312983dc2da8bb424a264be91b773679",
                ChecksumVerifier.extractHash(raw1));

        String raw2 = "SHA256 (archive.zip) = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        assertEquals("extract BSD format hash",
                "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                ChecksumVerifier.extractHash(raw2));

        String raw3 = "sha256: AADC789DA2F43C7CECFFF068AE2DA9CD312983DC2DA8BB424A264BE91B773679";
        assertEquals("extract prefix uppercase hash",
                "aadc789da2f43c7cecfff068ae2da9cd312983dc2da8bb424a264be91b773679",
                ChecksumVerifier.extractHash(raw3));

        String raw4 = "d41d8cd98f00b204e9800998ecf8427e";
        assertEquals("extract bare MD5",
                "d41d8cd98f00b204e9800998ecf8427e",
                ChecksumVerifier.extractHash(raw4));
    }

    private static void testChecksumAlgorithmDetection() {
        assertEquals("detect SHA-256 by length", ChecksumVerifier.ALGO_SHA256,
                ChecksumVerifier.detectAlgorithm("aadc789da2f43c7cecfff068ae2da9cd312983dc2da8bb424a264be91b773679"));

        assertEquals("detect SHA-1 by length", ChecksumVerifier.ALGO_SHA1,
                ChecksumVerifier.detectAlgorithm("da39a3ee5e6b4b0d3255bfef95601890afd80709"));

        assertEquals("detect MD5 by length", ChecksumVerifier.ALGO_MD5,
                ChecksumVerifier.detectAlgorithm("d41d8cd98f00b204e9800998ecf8427e"));

        assertEquals("detect SHA-512 by length", ChecksumVerifier.ALGO_SHA512,
                ChecksumVerifier.detectAlgorithm("cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"));

        assertEquals("detect by prefix sha256:", ChecksumVerifier.ALGO_SHA256,
                ChecksumVerifier.detectAlgorithm("sha256: 1234"));

        assertEquals("detect by BSD SHA1 (file) =", ChecksumVerifier.ALGO_SHA1,
                ChecksumVerifier.detectAlgorithm("SHA1 (file.bin) = da39a3ee5e6b4b0d3255bfef95601890afd80709"));
    }

    private static void testChecksumComputationAndVerification() {
        try {
            File tmp = File.createTempFile("reteget_test_", ".txt");
            tmp.deleteOnExit();
            java.io.FileOutputStream fos = new java.io.FileOutputStream(tmp);
            fos.write("Hello ReteGet\n".getBytes("UTF-8"));
            fos.close();

            // Computed SHA-256 for "Hello ReteGet\n":
            // echo "Hello ReteGet" | sha256sum -> b451000632d431f1fc8be48a520ca4aaae66a504ef96fe0d12f6a7d65609462f
            String expectedSha256 = ChecksumVerifier.computeHash(tmp, "SHA-256");
            assertTrue("sha256 computed non-empty", expectedSha256 != null && expectedSha256.length() == 64);

            ChecksumVerifier.Result resMatch = ChecksumVerifier.verify(tmp, expectedSha256);
            assertTrue("verify match returns true", resMatch.matched);
            assertEquals("verify match algo is SHA-256", ChecksumVerifier.ALGO_SHA256, resMatch.algorithm);

            ChecksumVerifier.Result resMismatch = ChecksumVerifier.verify(tmp, "0000000000000000000000000000000000000000000000000000000000000000");
            assertTrue("verify mismatch returns false", !resMismatch.matched);

            ChecksumVerifier.Result resPrefixMatch = ChecksumVerifier.verify(tmp, "sha256: " + expectedSha256);
            assertTrue("verify with sha256: prefix matches", resPrefixMatch.matched);

            tmp.delete();
        } catch (Exception e) {
            assertTrue("checksum test exception: " + e.getMessage(), false);
        }
    }

    private static void testChecksumMultiHash() {
        try {
            File tmp = File.createTempFile("reteget_multi_", ".txt");
            tmp.deleteOnExit();
            java.io.FileOutputStream fos = new java.io.FileOutputStream(tmp);
            fos.write("Hello World".getBytes("UTF-8"));
            fos.close();

            String[] algos = new String[] { "SHA-256", "SHA-1", "MD5" };
            Map<String, String> hashes = ChecksumVerifier.computeMultiHashes(tmp, algos);
            assertEquals("multi-hash count", 3, hashes.size());
            assertEquals("multi-hash md5", "b10a8db164e0754105b7a99be72e3fe5", hashes.get("MD5"));
            assertEquals("multi-hash sha1", "0a4d55a8d778e5022fab701977c5d840bbc486d0", hashes.get("SHA-1"));
            assertEquals("multi-hash sha256", "a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e", hashes.get("SHA-256"));

            tmp.delete();
        } catch (Exception e) {
            assertTrue("multi-hash exception: " + e.getMessage(), false);
        }
    }

    private static void testApkSignatureExtraction() {
        File apk = new File("dist/reteget-0.1.0-debug.apk");
        if (apk.exists()) {
            ApkSignatureVerifier.CertInfo cert = ApkSignatureVerifier.fromApkFile(apk);
            assertTrue("apk cert extracted from dist debug apk", cert != null);
            if (cert != null) {
                assertTrue("cert has sha256 fingerprint", cert.sha256Fingerprint != null && cert.sha256Fingerprint.length() > 64);
                assertTrue("cert display author non-empty", !cert.getDisplayAuthor().isEmpty());
                assertEquals("cert CN extracted", "ReteGet development", cert.commonName);
            }
        } else {
            System.out.println("  SKIP: dist/reteget-0.1.0-debug.apk not found for signature extraction test");
        }
    }

    private static void testApkSignatureCommonName() {
        assertEquals("CN only", "MyAuthor", ApkSignatureVerifier.extractCommonName("CN=MyAuthor"));
        assertEquals("CN with multiple attributes", "Rubidus",
                ApkSignatureVerifier.extractCommonName("CN=Rubidus, OU=Dev, O=Org, C=KR"));
        assertEquals("CN with quotes", "Special, Name",
                ApkSignatureVerifier.extractCommonName("CN=\"Special, Name\", O=Org"));
        assertEquals("no CN fallback to DN", "O=Org, C=KR",
                ApkSignatureVerifier.extractCommonName("O=Org, C=KR"));
    }

    private static void testApkSignatureNormalization() {
        assertEquals("normalize uppercase and colons", "AABBCC",
                ApkSignatureVerifier.normalizeFingerprint("aa:bb:cc"));
        assertEquals("normalize spaces", "AABBCC",
                ApkSignatureVerifier.normalizeFingerprint("aa bb cc"));
        assertEquals("format fingerprint", "0A:FF",
                ApkSignatureVerifier.formatFingerprint(new byte[] { 10, -1 }));
    }

    private static void testApkSignatureContinuityVerification() {
        java.util.Date now = new java.util.Date();
        ApkSignatureVerifier.CertInfo certA = new ApkSignatureVerifier.CertInfo(
                "AA:BB:CC:DD", "11:22", "CN=AuthorA", "CN=AuthorA", "AuthorA", now, now);
        ApkSignatureVerifier.CertInfo certB = new ApkSignatureVerifier.CertInfo(
                "EE:FF:00:11", "33:44", "CN=AuthorB", "CN=AuthorB", "AuthorB", now, now);

        // 1. Installed match
        ApkSignatureVerifier.VerificationResult r1 = ApkSignatureVerifier.verifyContinuity(certA, certA, null, null);
        assertEquals("r1 status match installed", ApkSignatureVerifier.Status.MATCH_INSTALLED, r1.status);
        assertTrue("r1 not mismatch", !r1.isMismatch);

        // 2. Installed conflict
        ApkSignatureVerifier.VerificationResult r2 = ApkSignatureVerifier.verifyContinuity(certA, certB, null, null);
        assertEquals("r2 status mismatch installed", ApkSignatureVerifier.Status.MISMATCH_INSTALLED, r2.status);
        assertTrue("r2 is mismatch", r2.isMismatch);

        // 3. Previous match (TOFU)
        ApkSignatureVerifier.VerificationResult r3 = ApkSignatureVerifier.verifyContinuity(certA, null, "aa:bb:cc:dd", "AuthorA");
        assertEquals("r3 status match previous", ApkSignatureVerifier.Status.MATCH_PREVIOUS, r3.status);
        assertTrue("r3 not mismatch", !r3.isMismatch);

        // 4. Previous mismatch (Author changed)
        ApkSignatureVerifier.VerificationResult r4 = ApkSignatureVerifier.verifyContinuity(certA, null, "EE:FF:00:11", "AuthorB");
        assertEquals("r4 status mismatch previous", ApkSignatureVerifier.Status.MISMATCH_PREVIOUS, r4.status);
        assertTrue("r4 is mismatch", r4.isMismatch);

        // 5. First time
        ApkSignatureVerifier.VerificationResult r5 = ApkSignatureVerifier.verifyContinuity(certA, null, null, null);
        assertEquals("r5 status first time", ApkSignatureVerifier.Status.FIRST_TIME, r5.status);
        assertTrue("r5 not mismatch", !r5.isMismatch);

        // 6. Unsigned
        ApkSignatureVerifier.VerificationResult r6 = ApkSignatureVerifier.verifyContinuity(null, null, null, null);
        assertEquals("r6 status unsigned", ApkSignatureVerifier.Status.UNSIGNED, r6.status);
        assertTrue("r6 not mismatch", !r6.isMismatch);
    }

    private static void testPresetItemSerialization() {
        PresetItem item = new PresetItem(
                "ReteGet",
                "https://github.com/rubidus-api/reteget_apk/releases/download/v{1}/reteget-{1}.apk",
                "reteget-0.1.0.apk",
                66318,
                "0.1.0",
                1727180400000L,
                "b451000632d431f1fc8be48a520ca4aaae66a504ef96fe0d12f6a7d65609462f",
                "2A:4F:91:0C:68:57:3E",
                "ReteGet development"
        );

        String json = item.toJson();
        assertTrue("json contains url", json.contains("\"url\":"));
        assertTrue("json contains name", json.contains("\"name\":\"ReteGet\""));
        assertTrue("json contains filename", json.contains("\"filename\":\"reteget-0.1.0.apk\""));
        assertTrue("json contains size", json.contains("\"size\":66318"));
        assertTrue("json contains sha256", json.contains("\"sha256\":\"b451000632d431f1"));

        PresetItem restored = PresetItem.fromJson(json);
        assertTrue("restored not null", restored != null);
        assertEquals("restored name", item.name, restored.name);
        assertEquals("restored url", item.url, restored.url);
        assertEquals("restored filename", item.lastFileName, restored.lastFileName);
        assertEquals("restored size", item.lastFileSize, restored.lastFileSize);
        assertEquals("restored version", item.lastVersion, restored.lastVersion);
        assertEquals("restored time", item.lastDownloadedAt, restored.lastDownloadedAt);
        assertEquals("restored sha256", item.lastSha256, restored.lastSha256);
        assertEquals("restored sig", item.lastSigFingerprint, restored.lastSigFingerprint);
        assertEquals("restored author", item.lastAuthor, restored.lastAuthor);

        assertTrue("hasMetadata is true", restored.hasMetadata());
        assertTrue("formatted size contains KB", restored.getFormattedSize().contains("KB"));
        assertTrue("summary contains filename", restored.getMetadataSummary().contains("reteget-0.1.0.apk"));
    }

    private static void testPresetItemDisplayName() {
        PresetItem p1 = new PresetItem("Custom Title", "https://example.com/downloads/app.apk");
        assertEquals("p1 explicit name", "Custom Title", p1.getDisplayName());

        PresetItem p2 = new PresetItem("", "https://example.com/downloads/tool-v1.apk");
        p2.lastFileName = "tool-v1.apk";
        assertEquals("p2 fallback to lastFileName", "tool-v1.apk", p2.getDisplayName());

        PresetItem p3 = new PresetItem("", "https://example.com/downloads/v1.0/my_suite.apk");
        assertEquals("p3 fallback to url filename", "my_suite.apk", p3.getDisplayName());

        PresetItem p4 = new PresetItem("", "https://example.com/");
        assertEquals("p4 fallback to full url", "https://example.com/", p4.getDisplayName());
    }

    private static void testPresetItemLegacyCompatibility() {
        String legacyUrl = "https://archive.org/download/{1}/{2}.apk";
        PresetItem item = PresetItem.fromJson(legacyUrl);
        assertTrue("legacy restored not null", item != null);
        assertEquals("legacy url match", legacyUrl, item.url);
        assertEquals("legacy empty name", "", item.name);
        assertTrue("legacy has no metadata", !item.hasMetadata());
        assertEquals("legacy summary string", "No download record yet", item.getMetadataSummary());
    }

    private static void testPresetDefaultsAndMerge() {
        List<PresetItem> d = PresetItem.defaults();
        assertEquals("four built-in rete presets", 4, d.size());
        boolean allGithub = true;
        boolean allTemplates = true;
        for (PresetItem p : d) {
            allGithub &= p.url.startsWith("https://github.com/rubidus-api/");
            allTemplates &= p.url.contains("{1}") && p.lastVersion != null && !p.lastVersion.isEmpty();
        }
        assertTrue("built-in presets point at GitHub releases", allGithub);
        assertTrue("built-in presets are version templates with a default version", allTemplates);
        assertEquals("first preset is ReteGet", "ReteGet", d.get(0).name);
        assertTrue("legacy ReteKey (minSdk 14) listed before the Android 9+ build",
                d.get(2).url.endsWith("-legacy.apk") && !d.get(3).url.endsWith("-legacy.apk"));
        UrlTemplate t = new UrlTemplate(d.get(1).url);
        assertEquals("ReteClock template resolves to the release asset",
                "https://github.com/rubidus-api/reteclock_apk/releases/download/v0.50.0/reteclock-0.50.0.apk",
                t.resolve(java.util.Collections.singletonMap("1", "0.50.0")));

        List<PresetItem> stored = new java.util.ArrayList<PresetItem>();
        stored.add(new PresetItem("Old ReteKey",
                "https://github.com/rubidus-api/retekey_apk/releases/download/v{1}/retekey-{1}.apk"));
        stored.add(new PresetItem("My mirror", "https://example.org/files/{1}.zip"));
        stored.add(new PresetItem("Old ReteGet",
                "https://github.com/rubidus-api/reteget_apk/releases/download/v{1}/reteget-{1}.apk"));
        List<PresetItem> merged = PresetItem.mergeDefaults(stored);
        assertEquals("merge keeps user presets and refreshes built-ins", 5, merged.size());
        assertEquals("user preset kept after the built-ins", "My mirror", merged.get(4).name);
        assertEquals("stale built-in replaced by the current one", "ReteGet", merged.get(0).name);
    }

    /** Fake engine: completes, fails or waits depending on the URL. */
    private static final class FakeEngines implements DownloadQueue.EngineFactory {
        final List<DownloadEngine.Listener> waiting = new java.util.ArrayList<DownloadEngine.Listener>();
        int started;

        public DownloadQueue.Engine create() {
            return new DownloadQueue.Engine() {
                DownloadEngine.Listener l;

                public void start(DownloadTask t, DownloadEngine.Listener listener) {
                    started++;
                    l = listener;
                    listener.onStart(t.displayName(), 10);
                    if (t.url.contains("fail")) {
                        listener.onError(new java.io.IOException("HTTP 404"));
                    } else if (t.url.contains("wait")) {
                        waiting.add(listener);
                    } else {
                        listener.onProgress(10, 10, 100, 5);
                        listener.onComplete(new File(t.destDir, t.displayName()));
                    }
                }

                public void cancel() {
                    l.onCancel();
                }

                public String tlsSummary() {
                    return "TLS 1.3 test";
                }
            };
        }
    }

    private static void testDownloadQueue() {
        final String[] saved = { null };
        DownloadQueue.Store store = new DownloadQueue.Store() {
            public String load() { return saved[0]; }
            public void save(String data) { saved[0] = data; }
        };
        FakeEngines engines = new FakeEngines();
        final List<DownloadTask> completed = new java.util.ArrayList<DownloadTask>();
        DownloadQueue q = new DownloadQueue(store, engines);
        q.setListener(new DownloadQueue.Listener() {
            public void onTaskChanged(DownloadTask t) {}
            public void onTaskCompleted(DownloadTask t) { completed.add(t); }
        });
        File dir = new File("build/test/queue");
        DownloadTask a = q.enqueue("https://h/a.apk", dir, false, false, "abc");
        DownloadTask b = q.enqueue("https://h/wait.apk", dir, false, true, "");
        DownloadTask c = q.enqueue("https://h/c.zip", dir, false, false, "");
        List<DownloadTask> s = q.snapshot();
        assertEquals("queue: first entry done", DownloadTask.State.DONE, s.get(0).state);
        assertEquals("queue: completion reported with TLS info", "TLS 1.3 test", completed.get(0).tlsSummary);
        assertEquals("queue: expected checksum kept", "abc", completed.get(0).expectedChecksum);
        assertEquals("queue: second entry running", DownloadTask.State.RUNNING, s.get(1).state);
        assertEquals("queue: third waits its turn (one at a time)", DownloadTask.State.QUEUED, s.get(2).state);

        q.cancel(b.id);
        s = q.snapshot();
        assertEquals("queue: cancelled entry stays listed", DownloadTask.State.CANCELLED, s.get(1).state);
        assertEquals("queue: next entry ran after cancel", DownloadTask.State.DONE, s.get(2).state);

        DownloadTask f = q.enqueue("https://h/fail.bin", dir, false, false, "");
        DownloadTask failed = q.snapshot().get(3);
        assertTrue("queue: failure recorded with reason",
                failed.state == DownloadTask.State.FAILED && "HTTP 404".equals(failed.error));
        int before = engines.started;
        q.retry(f.id);
        assertTrue("queue: retry runs the entry again", engines.started == before + 1);

        DownloadTask doneA = q.snapshot().get(0);
        assertTrue("queue: a finished entry starts unverified", !doneA.verified);
        q.markVerified(a.id, "abcd", DownloadTask.WARN_CHECKSUM + "," + DownloadTask.WARN_SIGNATURE);
        DownloadTask reread = new DownloadQueue(store, engines).snapshot().get(0);
        assertTrue("queue: verification result persists (so Install still warns after a restart)",
                reread.verified && "abcd".equals(reread.sha256)
                        && reread.hasWarning(DownloadTask.WARN_CHECKSUM) && reread.hasWarning(DownloadTask.WARN_SIGNATURE)
                        && !reread.hasWarning(DownloadTask.WARN_MISSING));

        q.remove(a.id);
        assertEquals("queue: removing a finished record", 3, q.snapshot().size());
        assertTrue("queue: removing a done record keeps nothing else changed",
                q.snapshot().get(0).id == b.id);

        q.retry(b.id); // waits again
        assertEquals("queue: retried entry running", DownloadTask.State.RUNNING, q.snapshot().get(0).state);
        DownloadQueue reloaded = new DownloadQueue(store, engines);
        DownloadTask back = reloaded.snapshot().get(0);
        assertTrue("queue: entry running at process death comes back as failed/interrupted",
                back.state == DownloadTask.State.FAILED && DownloadQueue.INTERRUPTED.equals(back.error));
        assertEquals("queue: records survive reload", 3, reloaded.snapshot().size());
        q.remove(b.id);
        assertEquals("queue: removing a running entry cancels and drops it", 2, q.snapshot().size());
        assertEquals("queue: clear finished", 2, q.clearFinished());
        assertEquals("queue: empty after clear", 0, q.snapshot().size());
        DownloadTask parsed = DownloadTask.fromJson(new DownloadTask(7, "https://x/\"q\".apk", "/d", true, true,
                "sha", 5).toJson());
        assertTrue("queue: JSON round trip with quotes", parsed != null && parsed.url.equals("https://x/\"q\".apk")
                && parsed.insecure && parsed.forceBuiltInTls && parsed.id == 7);
    }

    private static java.awt.image.BufferedImage png(String rel) throws Exception {
        return javax.imageio.ImageIO.read(new File("src/android/res/" + rel));
    }

    private static int alpha(java.awt.image.BufferedImage img, int x, int y) {
        return (img.getRGB(x, y) >>> 24) & 0xff;
    }

    /** Connected opaque pieces (alpha >= 128) in rows [y0, y1). */
    private static int pieces(java.awt.image.BufferedImage img, int y0, int y1) {
        int w = img.getWidth();
        boolean[][] seen = new boolean[y1 - y0][w];
        int count = 0;
        for (int y = y0; y < y1; y++) {
            for (int x = 0; x < w; x++) {
                if (seen[y - y0][x] || alpha(img, x, y) < 128) continue;
                count++;
                java.util.ArrayDeque<int[]> stack = new java.util.ArrayDeque<int[]>();
                stack.push(new int[] { x, y });
                seen[y - y0][x] = true;
                while (!stack.isEmpty()) {
                    int[] p = stack.pop();
                    int[][] next = { { p[0] + 1, p[1] }, { p[0] - 1, p[1] }, { p[0], p[1] + 1 }, { p[0], p[1] - 1 } };
                    for (int[] n : next) {
                        if (n[0] < 0 || n[0] >= w || n[1] < y0 || n[1] >= y1) continue;
                        if (seen[n[1] - y0][n[0]] || alpha(img, n[0], n[1]) < 128) continue;
                        seen[n[1] - y0][n[0]] = true;
                        stack.push(n);
                    }
                }
            }
        }
        return count;
    }

    private static void testIconResources() {
        try {
            String[] legacy = { "ldpi", "mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi" };
            boolean all = true;
            for (String d : legacy) {
                all &= new File("src/android/res/drawable-" + d + "/ic_launcher.png").isFile();
            }
            for (String d : new String[] { "mdpi", "hdpi", "xhdpi", "xxhdpi", "xxxhdpi" }) {
                all &= new File("src/android/res/drawable-" + d + "/ic_launcher_foreground.png").isFile();
                all &= new File("src/android/res/drawable-" + d + "/ic_launcher_monochrome.png").isFile();
            }
            assertTrue("icon: legacy PNGs and adaptive layers exist for every density", all);
            String xml = new String(java.nio.file.Files.readAllBytes(
                    new File("src/android/res/drawable-anydpi-v26/ic_launcher.xml").toPath()), "UTF-8");
            assertTrue("icon: adaptive icon names background, foreground and monochrome",
                    xml.contains("<background") && xml.contains("<foreground") && xml.contains("<monochrome"));
            assertTrue("icon: adaptive icon is only in a -v26 folder (API 9-25 keep the PNG)",
                    !new File("src/android/res/drawable/ic_launcher.xml").exists());

            java.awt.image.BufferedImage icon = png("drawable-xxhdpi/ic_launcher.png");
            assertTrue("icon: legacy corners are transparent and the plate is opaque",
                    alpha(icon, 0, 0) == 0 && alpha(icon, icon.getWidth() - 1, icon.getHeight() - 1) == 0
                            && alpha(icon, icon.getWidth() / 2, 4) == 255);

            java.awt.image.BufferedImage mono = png("drawable-xxhdpi/ic_launcher_monochrome.png");
            int opaque = 0;
            for (int y = 0; y < mono.getHeight(); y++) {
                for (int x = 0; x < mono.getWidth(); x++) {
                    if (alpha(mono, x, y) >= 128) opaque++;
                }
            }
            double share = opaque / (double) (mono.getWidth() * mono.getHeight());
            assertTrue("icon: monochrome layer has the drawing opaque, not a plate with a hole (" 
                    + String.format(java.util.Locale.US, "%.3f", share) + ")", share > 0.02 && share < 0.15);
            java.awt.image.BufferedImage fg = png("drawable-xxhdpi/ic_launcher_foreground.png");
            assertTrue("icon: foreground layer is transparent outside the drawing", alpha(fg, 0, 0) == 0
                    && alpha(fg, fg.getWidth() / 2, 2) == 0);
            int h = mono.getHeight();
            assertTrue("icon: arrow and tray are separate shapes on the themed layer",
                    pieces(mono, h / 2, h) >= 2);
        } catch (Exception e) {
            assertTrue("icon resources: " + e, false);
        }
    }

    private static void testSettingsBundle() {
        SettingsBundle b = new SettingsBundle();
        b.appVersion = "0.3.2";
        b.builtInTls = Boolean.TRUE;
        b.presets.addAll(PresetItem.defaults());
        b.presets.add(new PresetItem("Mirror \"A\" \\ 한글", "https://example.org/{1}/a.apk"));
        b.signers.put("com.reteclock", new String[] { "90:44:6B", "reteclock" });
        String file = b.write();
        SettingsBundle r = SettingsBundle.parse(file);
        assertEquals("settings: option survives", Boolean.TRUE, r.builtInTls);
        assertEquals("settings: all presets survive", b.presets.size(), r.presets.size());
        assertEquals("settings: quotes, backslash and Hangul in a name survive", "Mirror \"A\" \\ 한글", r.presets.get(4).name);
        assertEquals("settings: preset record survives", PresetItem.defaults().get(1).toJson(), r.presets.get(1).toJson());
        assertEquals("settings: signer survives", "reteclock", r.signers.get("com.reteclock")[1]);
        assertTrue("settings: a file this wrote reads without complaints", r.complaints.isEmpty());

        // Every line is in the INI and TOML subset: comment, [section], or key = true/false/int/"string".
        java.util.regex.Pattern ok = java.util.regex.Pattern.compile(
                "^(#.*|\\[[a-z0-9_-]+\\]|[a-z0-9_-]+ = (true|false|-?[0-9]+|\"([^\"\\\\]|\\\\[\\\\\"])*\"))?$");
        boolean subset = !file.startsWith("\uFEFF") && file.indexOf('\r') < 0;
        String firstSection = null;
        for (String line : file.split("\n")) {
            subset &= ok.matcher(line).matches();
            if (firstSection == null && line.startsWith("[")) firstSection = line;
            if (firstSection == null && line.contains(" = ")) subset = false;
        }
        assertTrue("settings: every written line is in the INI and TOML subset", subset);

        String handEdited = "\uFEFF; my backup\r\n[Options]\r\nBuilt_In_TLS: yes\r\n\r\n"
                + "[preset-7]\r\nName = My mirror\r\nURL = https://example.org/{1}.zip\r\ncolour = red\r\n"
                + "[weather]\r\nsunny = true\r\n";
        SettingsBundle h = SettingsBundle.parse(handEdited);
        assertEquals("settings: a hand-edited file (case, colon, bare values, CRLF, BOM) still reads",
                "My mirror|https://example.org/{1}.zip|true",
                h.presets.get(0).name + "|" + h.presets.get(0).url + "|" + h.builtInTls);
        assertEquals("settings: what cannot be understood is listed, not guessed (unknown key, unknown section)", 2, h.complaints.size());

        List<PresetItem> current = new java.util.ArrayList<PresetItem>();
        current.add(new PresetItem("Only here", "https://local/x.apk"));
        current.add(new PresetItem("Old name", PresetItem.defaults().get(1).url));
        SettingsBundle.Merge m = SettingsBundle.mergePresets(current, r.presets);
        assertEquals("settings merge: phone-only preset kept first", "Only here", m.presets.get(0).name);
        assertEquals("settings merge: matching URL takes the imported name", "ReteClock", m.presets.get(1).name);
        assertEquals("settings merge: counts", "4 added, 1 updated", m.added + " added, " + m.updated + " updated");

        boolean rejected = false;
        try {
            SettingsBundle.parse("{\"app\":\"other\"}");
        } catch (IllegalArgumentException e) {
            rejected = true;
        }
        assertTrue("settings: a file that is not ReteGet settings is refused", rejected);
    }

    private static void testPureGcmEncryptionDecryption() {
        try {
            byte[] key = new byte[16];
            for (int i = 0; i < 16; i++) key[i] = (byte) (i + 1);
            byte[] iv = new byte[12];
            for (int i = 0; i < 12; i++) iv[i] = (byte) (i * 3);

            byte[] plaintext = "Hello Pure Java TLS 1.2 AES-GCM on Galaxy Note 2!".getBytes("UTF-8");
            byte[] aad = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05 };

            org.reteget.core.tls.AesGcm gcm = new org.reteget.core.tls.AesGcm(key);
            byte[] ciphertextWithTag = gcm.encrypt(iv, plaintext, aad);

            assertTrue("ciphertext longer than plaintext by 16 bytes",
                    ciphertextWithTag.length == plaintext.length + 16);

            byte[] decrypted = gcm.decrypt(iv, ciphertextWithTag, aad);
            assertEquals("decrypted matches plaintext",
                    new String(plaintext, "UTF-8"), new String(decrypted, "UTF-8"));

            // Tamper test: modify 1 bit of ciphertext
            byte[] tampered = java.util.Arrays.copyOf(ciphertextWithTag, ciphertextWithTag.length);
            tampered[0] ^= 0x01;
            boolean failedTag = false;
            try {
                gcm.decrypt(iv, tampered, aad);
            } catch (SecurityException se) {
                failedTag = true;
            }
            assertTrue("tampered ciphertext throws SecurityException", failedTag);

            // Wrong AAD test
            byte[] wrongAad = new byte[] { 0x01, 0x02, 0x03, 0x04, 0x06 };
            boolean failedAad = false;
            try {
                gcm.decrypt(iv, ciphertextWithTag, wrongAad);
            } catch (SecurityException se) {
                failedAad = true;
            }
            assertTrue("wrong aad throws SecurityException", failedAad);

        } catch (Exception e) {
            assertTrue("gcm exception: " + e.getMessage(), false);
        }
    }

    private static void testDownloadEngineSslErrorDetection() {
        assertTrue("SSLException detected",
                DownloadEngine.isSslError(new javax.net.ssl.SSLException("SSL error")));
        assertTrue("SSLProtocolException detected",
                DownloadEngine.isSslError(new javax.net.ssl.SSLProtocolException("SSL handshake aborted: sslv3 alert handshake failure")));
        assertTrue("IOException with ssl message detected",
                DownloadEngine.isSslError(new java.io.IOException("SSL routines:SSL23_GET_SERVER_HELLO:sslv3 alert handshake failure")));
        assertTrue("IOException with handshake keyword",
                DownloadEngine.isSslError(new java.io.IOException("Handshake failed")));
        assertTrue("plain connection error not ssl",
                !DownloadEngine.isSslError(new java.io.IOException("Connection refused")));
    }
}
