package org.reteget.core;

import java.io.File;
import java.io.FileInputStream;
import java.security.MessageDigest;

/**
 * Command-line check of the in-tree TLS engine against a live server, runnable on a
 * desktop JVM or on a device with dalvikvm:
 *
 *   TlsProbe <url> <output dir> [trusted_roots.pem]
 *
 * Downloads through DownloadEngine with the in-tree engine forced, then prints the
 * negotiated TLS parameters, the file size and its SHA-256.
 */
public final class TlsProbe {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("usage: TlsProbe <url> <output dir> [trusted_roots.pem]");
            System.exit(2);
        }
        TlsHelper.init(args.length > 2 ? new FileInputStream(args[2]) : null);
        final DownloadEngine engine = new DownloadEngine();
        final Object done = new Object();
        final File[] result = new File[1];
        final Exception[] error = new Exception[1];
        final long start = System.currentTimeMillis();
        engine.download(args[0], new File(args[1]), false, true, new DownloadEngine.Listener() {
            public void onStart(String filename, long totalBytes) {
                System.out.println("start: " + filename + " (" + totalBytes + " bytes) via " + engine.getLastTlsSummary());
            }

            public void onProgress(long bytesRead, long totalBytes, int percent, long bytesPerSec) {}

            public void onComplete(File f) {
                synchronized (done) {
                    result[0] = f;
                    done.notifyAll();
                }
            }

            public void onError(Exception ex) {
                synchronized (done) {
                    error[0] = ex;
                    done.notifyAll();
                }
            }

            public void onCancel() {
                onError(new Exception("cancelled"));
            }
        });
        synchronized (done) {
            while (result[0] == null && error[0] == null) {
                done.wait();
            }
        }
        if (error[0] != null) {
            System.out.println("FAILED: " + error[0]);
            error[0].printStackTrace(System.out);
            System.exit(1);
        }
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        FileInputStream in = new FileInputStream(result[0]);
        byte[] buf = new byte[16384];
        int n;
        while ((n = in.read(buf)) > 0) {
            md.update(buf, 0, n);
        }
        in.close();
        StringBuilder hex = new StringBuilder();
        for (byte b : md.digest()) {
            hex.append(Integer.toHexString((b & 0xff) | 0x100).substring(1));
        }
        System.out.println("OK: " + result[0].getName() + " " + result[0].length() + " bytes sha256=" + hex
                + " via " + engine.getLastTlsSummary() + " in " + (System.currentTimeMillis() - start) + " ms");
    }
}
