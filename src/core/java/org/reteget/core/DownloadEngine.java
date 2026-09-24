package org.reteget.core;

import java.io.BufferedInputStream;
import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URI;
import java.net.URL;
import java.net.URLDecoder;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.X509TrustManager;
import org.reteget.core.tls.TlsClient;
import org.reteget.core.tls.TlsConnection;

/**
 * Universal download engine handling HTTP, HTTPS, and FTP downloads
 * with redirect following, Content-Disposition extraction, speed calculation,
 * an in-tree TLS 1.3 / 1.2 engine for legacy Android devices (API 16 / Galaxy Note 2),
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
    private volatile TlsConnection activeTlsConnection;
    private volatile String lastTlsSummary;
    private volatile Socket activePlainSocket;

    public void cancel() {
        cancelled = true;
        HttpURLConnection conn = activeConnection;
        if (conn != null) {
            try {
                conn.disconnect();
            } catch (Exception ignored) {}
        }
        TlsConnection tlsSock = activeTlsConnection;
        if (tlsSock != null) {
            try {
                tlsSock.close();
            } catch (Exception ignored) {}
        }
        Socket plainSock = activePlainSocket;
        if (plainSock != null) {
            try {
                plainSock.close();
            } catch (Exception ignored) {}
        }
    }

    /**
     * Protocol, cipher and key exchange of the last connection made by the in-tree TLS
     * engine, or null when the download used the system TLS stack.
     */
    public String getLastTlsSummary() {
        return lastTlsSummary;
    }

    public boolean isCancelled() {
        return cancelled;
    }

    public void download(final String urlStr, final File destinationDir, final boolean insecure, final Listener listener) {
        download(urlStr, destinationDir, insecure, false, listener);
    }

    public void download(final String urlStr, final File destinationDir, final boolean insecure, final boolean forcePureTls, final Listener listener) {
        // Reset before the thread starts, so a cancel() that arrives first is not wiped out.
        cancelled = false;
        lastTlsSummary = null;
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    if (urlStr.toLowerCase(Locale.US).startsWith("ftp://")) {
                        downloadFtp(urlStr, destinationDir, listener);
                    } else {
                        downloadHttpWithFallback(urlStr, destinationDir, insecure, forcePureTls, listener);
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
                conn.setRequestProperty("User-Agent", "reteget/0.3.3 (Android Legacy)");
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

            String encoding = conn.getContentEncoding();
            boolean identity = encoding == null || encoding.equalsIgnoreCase("identity");
            if (!cancelled && identity && totalBytes > 0 && downloaded != totalBytes) {
                throw new EOFException("Download incomplete: received " + downloaded + " of " + totalBytes + " bytes");
            }

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

    private void downloadHttpWithFallback(String initialUrl, File destinationDir, boolean insecure, boolean forcePureTls, Listener listener) throws IOException {
        if (forcePureTls && initialUrl.toLowerCase(Locale.US).startsWith("https://")) {
            downloadPureTls(initialUrl, destinationDir, insecure, listener);
            return;
        }

        try {
            downloadHttp(initialUrl, destinationDir, insecure, listener);
        } catch (IOException e) {
            if (!cancelled && initialUrl.toLowerCase(Locale.US).startsWith("https://") && isSslError(e)) {
                // System SSL handshake failed (e.g. SSLv3 protocol alert on Galaxy Note 2).
                // Automatically fall back to the in-tree TLS engine (1.3, then 1.2).
                downloadPureTls(initialUrl, destinationDir, insecure, listener);
                return;
            }
            throw e;
        }
    }

    private void downloadPureTls(String initialUrl, File destinationDir, boolean insecure, Listener listener)
            throws IOException {
        String currentUrl = initialUrl;
        int redirectCount = 0;
        TlsConnection currentTlsSocket = null;
        Socket currentPlainSocket = null;
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
                String host = url.getHost();
                boolean isHttps = url.getProtocol().equalsIgnoreCase("https");
                int defaultPort = isHttps ? 443 : 80;
                int port = url.getPort() > 0 ? url.getPort() : defaultPort;
                String path = url.getFile();
                if (path == null || path.isEmpty()) {
                    path = "/";
                }

                InputStream sockIn;
                OutputStream sockOut;

                if (isHttps) {
                    X509TrustManager tm = TlsHelper.getTrustManager(insecure);
                    currentTlsSocket = TlsClient.connect(host, port, READ_TIMEOUT_MS, insecure ? null : tm);
                    activeTlsConnection = currentTlsSocket;
                    lastTlsSummary = currentTlsSocket.getSummary();
                    sockIn = currentTlsSocket.getInputStream();
                    sockOut = currentTlsSocket.getOutputStream();
                } else {
                    currentPlainSocket = new Socket();
                    currentPlainSocket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
                    currentPlainSocket.setSoTimeout(READ_TIMEOUT_MS);
                    activePlainSocket = currentPlainSocket;
                    sockIn = currentPlainSocket.getInputStream();
                    sockOut = currentPlainSocket.getOutputStream();
                }

                String req = "GET " + path + " HTTP/1.1\r\n"
                        + "Host: " + host + "\r\n"
                        + "User-Agent: reteget/0.3.3 (Android Legacy)\r\n"
                        + "Accept-Encoding: identity\r\n"
                        + "Connection: close\r\n\r\n";
                sockOut.write(req.getBytes("US-ASCII"));
                sockOut.flush();

                // Read HTTP response headers
                Map<String, String> headers = new HashMap<String, String>();
                String statusLine = readLine(sockIn);
                if (statusLine == null || !statusLine.startsWith("HTTP/")) {
                    throw new IOException("Invalid HTTP response from server: " + statusLine);
                }

                String[] statusParts = statusLine.split(" ");
                if (statusParts.length < 2) {
                    throw new IOException("Invalid HTTP status line: " + statusLine);
                }
                int code;
                try {
                    code = Integer.parseInt(statusParts[1]);
                } catch (NumberFormatException e) {
                    throw new IOException("Cannot parse HTTP status code: " + statusParts[1]);
                }

                String headerLine;
                while ((headerLine = readLine(sockIn)) != null && !headerLine.isEmpty()) {
                    int colon = headerLine.indexOf(':');
                    if (colon > 0) {
                        String key = headerLine.substring(0, colon).trim().toLowerCase(Locale.US);
                        String val = headerLine.substring(colon + 1).trim();
                        headers.put(key, val);
                    }
                }

                // Handle Redirects
                if (code == 301 || code == 302 || code == 303 || code == 307 || code == 308) {
                    String location = headers.get("location");
                    if (location == null || location.isEmpty()) {
                        throw new IOException("HTTP redirect " + code + " without Location header");
                    }
                    URL nextUrl = new URL(url, location);
                    currentUrl = nextUrl.toString();
                    closeCurrentSockets(currentTlsSocket, currentPlainSocket);
                    currentTlsSocket = null;
                    currentPlainSocket = null;
                    redirectCount++;
                    continue;
                }

                if (code < 200 || code >= 300) {
                    throw new IOException("HTTP server returned error: " + statusLine);
                }

                String contentDisposition = headers.get("content-disposition");
                String filename = extractFilename(currentUrl, contentDisposition);
                long totalBytes = -1;
                String lenStr = headers.get("content-length");
                if (lenStr != null) {
                    try {
                        totalBytes = Long.parseLong(lenStr.trim());
                    } catch (Exception ignored) {}
                }

                if (!destinationDir.exists()) {
                    destinationDir.mkdirs();
                }
                targetFile = new File(destinationDir, filename);

                if (listener != null) {
                    listener.onStart(filename, totalBytes);
                }

                in = new BufferedInputStream(sockIn, 16384);
                out = new FileOutputStream(targetFile);

                boolean isChunked = headers.containsKey("transfer-encoding")
                        && headers.get("transfer-encoding").toLowerCase(Locale.US).contains("chunked");

                long downloaded = 0;
                long lastTime = System.currentTimeMillis();
                long lastDownloaded = 0;
                long currentSpeed = 0;
                boolean chunkedEnded = false;

                if (isChunked) {
                    while (true) {
                        if (cancelled) break;
                        String chunkHeader = readLine(in);
                        if (chunkHeader == null) break;
                        chunkHeader = chunkHeader.trim();
                        if (chunkHeader.isEmpty()) continue;
                        int semi = chunkHeader.indexOf(';');
                        if (semi > 0) chunkHeader = chunkHeader.substring(0, semi).trim();
                        int chunkSize;
                        try {
                            chunkSize = Integer.parseInt(chunkHeader, 16);
                        } catch (NumberFormatException e) {
                            throw new IOException("Invalid chunk size: " + chunkHeader);
                        }
                        if (chunkSize == 0) {
                            readLine(in); // trailing empty line
                            chunkedEnded = true;
                            break;
                        }

                        byte[] chunkBuf = new byte[Math.min(chunkSize, 16384)];
                        int rem = chunkSize;
                        while (rem > 0) {
                            if (cancelled) break;
                            int toRead = Math.min(rem, chunkBuf.length);
                            int n = in.read(chunkBuf, 0, toRead);
                            if (n == -1) throw new EOFException("Premature EOF in chunked body");
                            out.write(chunkBuf, 0, n);
                            downloaded += n;
                            rem -= n;

                            long now = System.currentTimeMillis();
                            long dt = now - lastTime;
                            if (dt >= 400) {
                                currentSpeed = ((downloaded - lastDownloaded) * 1000) / dt;
                                lastTime = now;
                                lastDownloaded = downloaded;
                                if (listener != null) {
                                    listener.onProgress(downloaded, -1, -1, currentSpeed);
                                }
                            }
                        }
                        readLine(in); // chunk CRLF
                    }
                } else {
                    byte[] buffer = new byte[16384];
                    int read;
                    while ((read = in.read(buffer)) != -1) {
                        if (cancelled) break;
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

                        if (totalBytes > 0 && downloaded >= totalBytes) {
                            break;
                        }
                    }
                }

                out.flush();

                // A body cut short (connection closed early, or by an attacker) is never a success.
                if (!cancelled && isChunked && !chunkedEnded) {
                    throw new EOFException("Download incomplete: chunked body ended without its final chunk");
                }
                if (!cancelled && !isChunked && totalBytes > 0 && downloaded != totalBytes) {
                    throw new EOFException("Download incomplete: received " + downloaded + " of " + totalBytes + " bytes");
                }

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
                return;
            }

            if (redirectCount >= MAX_REDIRECTS) {
                throw new IOException("Too many HTTP redirects (limit: " + MAX_REDIRECTS + ")");
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
            closeCurrentSockets(currentTlsSocket, currentPlainSocket);
        }
    }

    private void closeCurrentSockets(TlsConnection tlsSock, Socket plainSock) {
        if (tlsSock != null) {
            try { tlsSock.close(); } catch (Exception ignored) {}
        }
        if (plainSock != null) {
            try { plainSock.close(); } catch (Exception ignored) {}
        }
        activeTlsConnection = null;
        activePlainSocket = null;
    }

    public static boolean isSslError(Throwable t) {
        while (t != null) {
            if (t instanceof javax.net.ssl.SSLException) return true;
            String msg = t.getMessage();
            if (msg != null) {
                String lower = msg.toLowerCase(Locale.US);
                if (lower.contains("ssl") || lower.contains("handshake") || lower.contains("protocol")
                        || lower.contains("cert") || lower.contains("alert")) {
                    return true;
                }
            }
            t = t.getCause();
        }
        return false;
    }

    private static String readLine(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        int b;
        while ((b = in.read()) != -1) {
            if (b == '\r') continue;
            if (b == '\n') return bos.toString("US-ASCII");
            bos.write(b);
        }
        if (bos.size() == 0) return null;
        return bos.toString("US-ASCII");
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
