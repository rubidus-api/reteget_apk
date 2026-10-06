package org.reteget.core;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.MessageDigest;
import org.reteget.core.ssh.KnownHosts;
import org.reteget.core.ssh.SshConfig;
import org.reteget.core.ssh.SshKeyFile;
import org.reteget.core.ssh.SshKeyStore;
import org.reteget.core.ssh.SshPromptException;

/**
 * Command-line check of sftp:// (and ftp://, ftpes://, ftps://) downloads against a live server, runnable on a desktop JVM or on
 * a device with app_process:
 *
 *   SftpProbe <sftp://user[:password]@host[:port]/path> <output dir> [private key file [passphrase]]
 *   SftpProbe <ftpes://user:password@host[:port]/path> <output dir>
 *
 * The host key (or an FTPS certificate that does not validate) is accepted on first sight and printed (this is a test tool, not the app's
 * behaviour). Prints the connection summary, timings, the file size and its SHA-256.
 */
public final class SftpProbe {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: SftpProbe <sftp url> <output dir> [private key file [passphrase]]");
            System.exit(2);
        }
        final KnownHosts hosts = new KnownHosts(null);
        SshKeyStore keys = new SshKeyStore(null);
        SshConfig.set(hosts, keys);
        String key = null;
        if (args.length > 2) {
            long t = System.currentTimeMillis();
            SshKeyStore.Key k = keys.add("probe", SshKeyFile.parse(text(new File(args[2]))));
            if (k.isProtected) keys.unlock(k.fingerprint, args.length > 3 ? args[3] : "");
            key = k.fingerprint;
            System.out.println("key " + k.type + " " + k.fingerprint + (k.isProtected ? " unlocked in " : " loaded in ")
                    + (System.currentTimeMillis() - t) + " ms");
        }
        for (int attempt = 0; attempt < 2; attempt++) {
            final long start = System.currentTimeMillis();
            final DownloadEngine engine = new DownloadEngine();
            final Exception[] error = new Exception[1];
            final File[] done = new File[1];
            engine.execute(args[0], new File(args[1]), false, false, false, null, key, new DownloadEngine.ResumeListener() {
                public void onStart(String filename, long totalBytes) {
                    System.out.println("start: " + filename + " (" + totalBytes + " bytes) after "
                            + (System.currentTimeMillis() - start) + " ms, " + engine.getLastTlsSummary());
                }

                public void onProgress(long bytesRead, long totalBytes, int percent, long bytesPerSec) {}

                public void onComplete(File f) {
                    done[0] = f;
                }

                public void onError(Exception ex) {
                    error[0] = ex;
                }

                public void onCancel() {}

                public void onPartial(String partPath, String validator, long totalBytes) {}

                public void onNotice(String notice, long value) {
                    System.out.println("notice: " + notice + " " + value);
                }
            });
            if (error[0] instanceof SshPromptException && attempt == 0
                    && SshPromptException.UNKNOWN_HOST.equals(((SshPromptException) error[0]).kind)) {
                SshPromptException q = (SshPromptException) error[0];
                System.out.println("host key " + q.keyType + " " + q.fingerprint + " of " + q.hostPort + " accepted for this run");
                hosts.trust(q);
                continue;
            }
            if (error[0] instanceof TlsCertQuestion && attempt == 0) {
                TlsCertQuestion q = (TlsCertQuestion) error[0];
                System.out.println("certificate of " + q.hostPort + " (" + q.reason + ") " + q.fingerprint + " accepted for this run");
                TlsPins.get().trust(q);
                continue;
            }
            if (error[0] != null) {
                System.out.println("FAILED: " + error[0]);
                System.exit(1);
            }
            long ms = System.currentTimeMillis() - start;
            System.out.println("OK: " + done[0].getName() + " " + done[0].length() + " bytes sha256=" + sha256(done[0])
                    + " in " + ms + " ms" + (ms > 0 ? " (" + done[0].length() * 1000 / ms / 1024 + " KiB/s)" : ""));
            return;
        }
    }

    private static String text(File f) throws Exception {
        InputStream in = new FileInputStream(f);
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] b = new byte[4096];
            int n;
            while ((n = in.read(b)) > 0) out.write(b, 0, n);
            return out.toString("UTF-8");
        } finally {
            in.close();
        }
    }

    private static String sha256(File f) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        InputStream in = new FileInputStream(f);
        try {
            byte[] b = new byte[65536];
            int n;
            while ((n = in.read(b)) > 0) md.update(b, 0, n);
        } finally {
            in.close();
        }
        StringBuilder sb = new StringBuilder();
        for (byte x : md.digest()) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
}
