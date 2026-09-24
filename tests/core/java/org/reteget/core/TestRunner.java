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
}
