package org.reteget.core;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Universal download engine handling HTTP, HTTPS, and FTP downloads
 * with redirect following, Content-Disposition extraction, speed calculation,
 * and cancellation support.
 */
public class DownloadEngine {

    private static final int MAX_REDIRECTS = 7;
    private static final int CONNECT_TIMEOUT_MS = 15000;
    private static final int READ_TIMEOUT_MS = 30000;
    private static final Pattern FILENAME_PATTERN =
            Pattern.compile("filename\\s*=\\s*\"?([^\"\\;\\n]+)\"?", Pattern.CASE_INSENSITIVE);

    public interface Listener {
        void onStart(String filename, long totalBytes);
        void onProgress(long bytesRead, long totalBytes, int percent, long bytesPerSec);
        void onComplete(File destinationFile);
        void onError(Exception ex);
        void onCancel();
    }

    private volatile boolean cancelled = false;
    private volatile HttpURLConnection activeConnection;

    public void cancel() {
        cancelled = true;
        HttpURLConnection conn = activeConnection;
        if (conn != null) {
            try {
                conn.disconnect();
            } catch (Exception ignored) {}
        }
    }

    public boolean isCancelled() {
        return cancelled;
    }

    public void download(final String urlStr, final File destinationDir, final boolean insecure, final Listener listener) {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    cancelled = false;
                    if (urlStr.toLowerCase().startsWith("ftp://")) {
                        downloadFtp(urlStr, destinationDir, listener);
                    } else {
                        downloadHttp(urlStr, destinationDir, insecure, listener);
                    }
                } catch (Exception ex) {
                    if (cancelled) {
                        if (listener != null) listener.onCancel();
                    } else {
                        if (listener != null) listener.onError(ex);
                    }
                }
            }
        }, "DownloadThread").start();
    }

    private void downloadFtp(String urlStr, File destinationDir, final Listener listener) throws IOException {
        final long[] lastTime = { System.currentTimeMillis() };
        final long[] lastBytes = { 0 };

        File file = FtpDownloader.download(urlStr, destinationDir, new FtpDownloader.DownloadCallback() {
            @Override
            public void onStart(String filename, long totalBytes) {
                if (listener != null) {
                    listener.onStart(filename, totalBytes);
                }
            }

            @Override
            public void onProgress(long bytesDownloaded, long totalBytes) {
                if (listener != null) {
                    long now = System.currentTimeMillis();
                    long dt = now - lastTime[0];
                    long speed = 0;
                    if (dt >= 500) {
                        speed = ((bytesDownloaded - lastBytes[0]) * 1000) / dt;
                        lastTime[0] = now;
                        lastBytes[0] = bytesDownloaded;
                    }
                    int pct = totalBytes > 0 ? (int) ((bytesDownloaded * 100) / totalBytes) : -1;
                    listener.onProgress(bytesDownloaded, totalBytes, pct, speed);
                }
            }

            @Override
            public boolean isCancelled() {
                return cancelled;
            }
        });

        if (listener != null) {
            listener.onComplete(file);
        }
    }

    private void downloadHttp(String initialUrl, File destinationDir, boolean insecure, Listener listener)
            throws IOException {
        String currentUrl = initialUrl;
        int redirectCount = 0;
        HttpURLConnection conn = null;
        InputStream in = null;
        OutputStream out = null;
        File targetFile = null;

        try {
            while (redirectCount < MAX_REDIRECTS) {
                if (cancelled) {
                    if (listener != null) listener.onCancel();
                    return;
                }

                URL url = new URL(currentUrl);
                conn = (HttpURLConnection) url.openConnection();
                activeConnection = conn;
                conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
                conn.setReadTimeout(READ_TIMEOUT_MS);
                conn.setInstanceFollowRedirects(false); // handle manually for HTTP->HTTPS or S3 redirects
                conn.setRequestProperty("User-Agent", "reteget/0.1.0 (Android Legacy)");
                conn.setRequestProperty("Accept-Encoding", "identity"); // Ensure raw Content-Length

                TlsHelper.configureConnection(conn, insecure);

                int code = conn.getResponseCode();

                // Handle Redirects
                if (code == HttpURLConnection.HTTP_MOVED_PERM
                        || code == HttpURLConnection.HTTP_MOVED_TEMP
                        || code == HttpURLConnection.HTTP_SEE_OTHER
                        || code == 307
                        || code == 308) {

                    String location = conn.getHeaderField("Location");
                    if (location == null || location.isEmpty()) {
                        throw new IOException("HTTP redirect " + code + " without Location header");
                    }
                    // Resolve relative redirect URLs against current URL
                    URL nextUrl = new URL(url, location);
                    currentUrl = nextUrl.toString();
                    conn.disconnect();
                    redirectCount++;
                    continue;
                }

                if (code < 200 || code >= 300) {
                    throw new IOException("HTTP server returned error response: " + code + " " + conn.getResponseMessage());
                }

                // Successful response (200-299)
                break;
            }

            if (redirectCount >= MAX_REDIRECTS) {
                throw new IOException("Too many HTTP redirects (limit: " + MAX_REDIRECTS + ")");
            }

            String contentDisposition = conn.getHeaderField("Content-Disposition");
            String filename = extractFilename(currentUrl, contentDisposition);
            long totalBytes = conn.getContentLength();
            if (totalBytes < 0) {
                String lenStr = conn.getHeaderField("Content-Length");
                if (lenStr != null) {
                    try {
                        totalBytes = Long.parseLong(lenStr.trim());
                    } catch (Exception ignored) {}
                }
            }

            if (!destinationDir.exists()) {
                destinationDir.mkdirs();
            }
            targetFile = new File(destinationDir, filename);

            if (listener != null) {
                listener.onStart(filename, totalBytes);
            }

            in = new BufferedInputStream(conn.getInputStream(), 16384);
            out = new FileOutputStream(targetFile);

            byte[] buffer = new byte[16384];
            int read;
            long downloaded = 0;
            long lastTime = System.currentTimeMillis();
            long lastDownloaded = 0;
            long currentSpeed = 0;

            while ((read = in.read(buffer)) != -1) {
                if (cancelled) {
                    break;
                }
                out.write(buffer, 0, read);
                downloaded += read;

                long now = System.currentTimeMillis();
                long dt = now - lastTime;
                if (dt >= 400) {
                    currentSpeed = ((downloaded - lastDownloaded) * 1000) / dt;
                    lastTime = now;
                    lastDownloaded = downloaded;

                    if (listener != null) {
                        int pct = totalBytes > 0 ? (int) ((downloaded * 100) / totalBytes) : -1;
                        listener.onProgress(downloaded, totalBytes, pct, currentSpeed);
                    }
                }
            }

            out.flush();

            if (cancelled) {
                if (out != null) {
                    try { out.close(); } catch (Exception ignored) {}
                    out = null;
                }
                if (targetFile != null && targetFile.exists()) {
                    targetFile.delete();
                }
                if (listener != null) {
                    listener.onCancel();
                }
                return;
            }

            if (listener != null) {
                int pct = totalBytes > 0 ? 100 : -1;
                listener.onProgress(downloaded, totalBytes, pct, currentSpeed);
                listener.onComplete(targetFile);
            }

        } catch (IOException e) {
            if (targetFile != null && targetFile.exists()) {
                targetFile.delete();
            }
            throw e;
        } finally {
            if (out != null) {
                try { out.close(); } catch (Exception ignored) {}
            }
            if (in != null) {
                try { in.close(); } catch (Exception ignored) {}
            }
            if (conn != null) {
                conn.disconnect();
            }
            activeConnection = null;
        }
    }

    public static String extractFilename(String urlStr, String contentDisposition) {
        if (contentDisposition != null) {
            Matcher m = FILENAME_PATTERN.matcher(contentDisposition);
            if (m.find()) {
                String fn = m.group(1).trim();
                if (fn.startsWith("\"") && fn.endsWith("\"")) {
                    fn = fn.substring(1, fn.length() - 1);
                }
                if (!fn.isEmpty()) {
                    return sanitizeFilename(fn);
                }
            }
        }

        try {
            URI uri = URI.create(urlStr);
            String path = uri.getPath();
            if (path != null && !path.isEmpty()) {
                int slash = path.lastIndexOf('/');
                if (slash >= 0 && slash < path.length() - 1) {
                    String fn = path.substring(slash + 1);
                    fn = URLDecoder.decode(fn, "UTF-8");
                    if (!fn.isEmpty()) {
                        return sanitizeFilename(fn);
                    }
                }
            }
        } catch (Exception ignored) {}

        return "download_" + System.currentTimeMillis() + ".apk";
    }

    private static String sanitizeFilename(String fn) {
        return fn.replaceAll("[\\\\/:*?\"<>|]", "_");
    }
}
