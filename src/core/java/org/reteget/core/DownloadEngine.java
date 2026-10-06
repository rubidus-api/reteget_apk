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
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.net.ssl.X509TrustManager;
import org.reteget.core.ssh.KnownHosts;
import org.reteget.core.ssh.SftpSession;
import org.reteget.core.ssh.SshConfig;
import org.reteget.core.ssh.SshIdentity;
import org.reteget.core.tls.TlsClient;
import org.reteget.core.tls.TlsConnection;

/**
 * Universal download engine handling HTTP, HTTPS, and FTP downloads
 * with redirect following, Content-Disposition extraction, speed calculation,
 * an in-tree TLS 1.3 / 1.2 engine for legacy Android devices (API 16 / Galaxy Note 2),
 * and cancellation support.
 *
 * <p>HTTP(S) downloads are written to {@code <name>.part} and renamed when complete. A body that
 * breaks off is continued with {@code Range} / {@code If-Range} (up to three times on its own,
 * and again when the caller passes a {@link Resume}). A 401 is answered with Basic or Digest
 * when the URL carries a user name and password ({@link HttpAuth}).
 *
 * <p>sftp:// downloads run over the in-tree SSH client ({@code org.reteget.core.ssh}) with the
 * same partial file and resume rules; the "validator" there is the remote file's size and time.
 */
public class DownloadEngine {

    private static final int MAX_REDIRECTS = 7;
    private static final int CONNECT_TIMEOUT_MS = 15000;
    private static final int READ_TIMEOUT_MS = 30000;
    private static final Pattern FILENAME_PATTERN =
            Pattern.compile("filename\\s*=\\s*\"?([^\"\\;\\n]+)\"?", Pattern.CASE_INSENSITIVE);

    /** Suffix of the file a download is written to until it is complete. */
    public static final String PART_SUFFIX = ".part";

    /** {@link ResumeListener#onNotice}: the download continued from a partial file at the given byte. */
    public static final String NOTICE_RESUMED = "resumed";
    /** {@link ResumeListener#onNotice}: a partial file could not be continued; the download started over. */
    public static final String NOTICE_RESTARTED = "restarted";
    /** {@link ResumeListener#onNotice}: a password was sent with Basic over plain http. */
    public static final String NOTICE_CLEARTEXT_PASSWORD = "cleartext-password";

    public interface Listener {
        void onStart(String filename, long totalBytes);
        void onProgress(long bytesRead, long totalBytes, int percent, long bytesPerSec);
        void onComplete(File destinationFile);
        void onError(Exception ex);
        void onCancel();
    }

    /** A Listener that also learns what is needed to continue the download later. */
    public interface ResumeListener extends Listener {
        /**
         * The body is being written to {@code partPath}. {@code validator} is the If-Range value
         * for a later resume (null: the server gave none, so no resume), {@code totalBytes} the
         * file's size or -1. Called after {@link #onStart} for every accepted response.
         */
        void onPartial(String partPath, String validator, long totalBytes);

        /** One of the NOTICE_* values; {@code value} is the byte offset for {@link #NOTICE_RESUMED}. */
        void onNotice(String notice, long value);
    }

    /** What an earlier attempt left: the file name, the If-Range validator and the size. */
    public static final class Resume {
        public final String fileName;
        public final String validator;
        public final long total;

        public Resume(String fileName, String validator, long total) {
            this.fileName = fileName;
            this.validator = validator;
            this.total = total;
        }
    }

    /** Thrown inside the engine when cancel() was called; reported as onCancel. */
    private static final class CancelledException extends IOException {
        CancelledException() {
            super("Download cancelled");
        }
    }

    private volatile boolean cancelled = false;
    private volatile HttpURLConnection activeConnection;
    private volatile TlsConnection activeTlsConnection;
    private volatile String lastTlsSummary;
    private volatile Socket activePlainSocket;
    private volatile SftpSession activeSftp;

    /** Pauses before the automatic resumes; package-private so tests can shorten them. */
    long[] backoffMs = { 2000, 5000, 10000 };

    // State of the current download, used only by the download thread.
    private Listener listener;
    private File dir;
    private String fileName;
    private String validator;
    private long knownTotal = -1;
    private boolean noRange;
    private long attemptBytes;
    private HttpAuth.Credentials credentials;
    private String credentialOrigin;
    private boolean cleartextNoticeSent;

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
        SftpSession sftp = activeSftp;
        if (sftp != null) sftp.abort();
    }

    private static volatile String appVersion = "";

    /** The app's version for the User-Agent; set once at start-up from the package's versionName. */
    public static void setAppVersion(String version) {
        appVersion = version == null ? "" : version.trim();
    }

    static String userAgent() {
        return (appVersion.length() > 0 ? "reteget/" + appVersion : "reteget") + " (Android Legacy)";
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
        download(urlStr, destinationDir, insecure, false, null, listener);
    }

    public void download(final String urlStr, final File destinationDir, final boolean insecure, final boolean forcePureTls, final Listener listener) {
        download(urlStr, destinationDir, insecure, forcePureTls, null, listener);
    }

    /** As above, continuing from the partial file {@code resume} describes when there is one. */
    public void download(final String urlStr, final File destinationDir, final boolean insecure, final boolean forcePureTls,
                         final Resume resume, final Listener listener) {
        download(urlStr, destinationDir, insecure, forcePureTls, resume, null, listener);
    }

    /**
     * As above; {@code sshKey} is the fingerprint of the key in {@link SshConfig#keys()} to log in
     * with for an sftp:// URL (null: password only).
     */
    public void download(final String urlStr, final File destinationDir, final boolean insecure, final boolean forcePureTls,
                         final Resume resume, final String sshKey, final Listener listener) {
        // Reset before the thread starts, so a cancel() that arrives first is not wiped out.
        cancelled = false;
        lastTlsSummary = null;
        new Thread(new Runnable() {
            @Override
            public void run() {
                execute(urlStr, destinationDir, insecure, forcePureTls, false, resume, sshKey, listener);
            }
        }, "DownloadThread").start();
    }

    /**
     * The whole download on the calling thread, reported through the listener; never throws.
     * {@code ownSocket} sends plain http through the engine's own socket code too (tests).
     */
    void execute(String urlStr, File destinationDir, boolean insecure, boolean forcePureTls, boolean ownSocket,
                 Resume resume, Listener l) {
        execute(urlStr, destinationDir, insecure, forcePureTls, ownSocket, resume, null, l);
    }

    void execute(String urlStr, File destinationDir, boolean insecure, boolean forcePureTls, boolean ownSocket,
                 Resume resume, String sshKey, Listener l) {
        listener = l;
        dir = destinationDir;
        fileName = null;
        validator = null;
        knownTotal = -1;
        noRange = false;
        credentials = null;
        cleartextNoticeSent = false;
        try {
            if (urlStr.toLowerCase(Locale.US).startsWith("ftp://")) {
                downloadFtp(urlStr, destinationDir, l);
            } else if (urlStr.toLowerCase(Locale.US).startsWith("sftp://")) {
                downloadSftp(urlStr, resume, sshKey);
            } else {
                downloadHttp(urlStr, destinationDir, insecure, forcePureTls, ownSocket, resume, l);
            }
        } catch (Exception ex) {
            if (cancelled) {
                deletePart();
                if (l != null) l.onCancel();
            } else {
                if (validator == null) deletePart(); // nothing to continue from later
                if (l != null) l.onError(ex);
            }
        }
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

    /** HTTP(S) with the system stack, falling back to the in-tree TLS, and automatic resumes. */
    private void downloadHttp(String urlStr, File destinationDir, boolean insecure, boolean forcePureTls,
                              boolean ownSocket, Resume resume, Listener l) throws IOException {
        if (resume != null && resume.fileName != null && resume.fileName.length() > 0) {
            fileName = resume.fileName;
            validator = resume.validator;
            knownTotal = resume.total;
        }
        URL entered = new URL(urlStr);
        credentials = HttpAuth.credentials(entered);
        URL start = HttpAuth.withoutUserInfo(entered);
        credentialOrigin = HttpAuth.origin(start);
        boolean https = start.getProtocol().equalsIgnoreCase("https");
        boolean useOwn = ownSocket || (forcePureTls && https);

        int resumes = 0;
        while (true) {
            attemptBytes = 0;
            try {
                if (useOwn) {
                    downloadOwnSocket(start, insecure);
                } else {
                    try {
                        downloadSystem(start, insecure);
                    } catch (IOException e) {
                        if (cancelled || !https || !isSslError(e)) throw e;
                        // System SSL failed (e.g. SSLv3 protocol alert on Galaxy Note 2): use the
                        // in-tree TLS engine (1.3, then 1.2), and keep using it for resumes.
                        useOwn = true;
                        downloadOwnSocket(start, insecure);
                    }
                }
                return;
            } catch (IOException e) {
                if (cancelled || attemptBytes == 0 || validator == null || resumes >= backoffMs.length) throw e;
                pause(backoffMs[resumes++]);
            }
        }
    }

    /** sftp:// with automatic resumes, like HTTP. */
    private void downloadSftp(String urlStr, Resume resume, String sshKey) throws IOException {
        if (resume != null && resume.fileName != null && resume.fileName.length() > 0) {
            fileName = resume.fileName;
            validator = resume.validator;
            knownTotal = resume.total;
        }
        URI uri;
        try {
            uri = new URI(urlStr);
        } catch (java.net.URISyntaxException e) {
            throw new IOException("Invalid SFTP URL");
        }
        String host = uri.getHost();
        if (host == null || host.length() == 0) throw new IOException("Invalid SFTP URL: no host");
        int port = uri.getPort() > 0 ? uri.getPort() : SftpSession.DEFAULT_PORT;
        HttpAuth.Credentials c = HttpAuth.credentials(uri.getRawUserInfo());
        if (c == null || c.user.length() == 0) {
            throw new IOException("An sftp:// address needs a user name, as in sftp://user:password@host/path");
        }
        String rawPath = uri.getRawPath() == null ? "" : uri.getRawPath();
        String path = SftpSession.remotePath(HttpAuth.percentDecode(rawPath));
        if (path.length() == 0 || path.endsWith("/")) {
            throw new IOException("The sftp:// address must name a file");
        }
        String password = uri.getRawUserInfo().indexOf(':') >= 0 ? c.password : null;

        int resumes = 0;
        while (true) {
            attemptBytes = 0;
            try {
                sftpAttempt(host, port, c.user, password, sshKey, path);
                return;
            } catch (IOException e) {
                if (cancelled || attemptBytes == 0 || validator == null || resumes >= backoffMs.length) throw e;
                pause(backoffMs[resumes++]);
            }
        }
    }

    /** One SFTP connection: log in, compare the file with what the partial file came from, fetch the rest. */
    private void sftpAttempt(String host, int port, String user, String password, String sshKey, String path)
            throws IOException {
        checkCancelled();
        String hostPort = KnownHosts.hostPort(host, port);
        KnownHosts hosts = SshConfig.knownHosts();
        SshIdentity identity = sshKey == null || sshKey.length() == 0 ? null : SshConfig.keys().identity(sshKey);
        SftpSession session = SftpSession.create();
        activeSftp = session;
        try {
            checkCancelled();
            session.connect(host, port, CONNECT_TIMEOUT_MS, READ_TIMEOUT_MS, user, password, identity,
                    hosts.checkFor(hostPort), hosts.keyTypeFor(hostPort));
            lastTlsSummary = session.summary();
            SftpSession.FileInfo info = session.stat(path);
            String current = info.size >= 0 && info.mtime >= 0 ? info.size + ":" + info.mtime : null;

            if (fileName == null) fileName = sanitizeFilename(path.substring(path.lastIndexOf('/') + 1));
            File part = partFile();
            long have = part.exists() ? part.length() : 0;
            boolean append = have > 0 && validator != null && validator.equals(current) && have <= info.size;
            if (have > 0 && validator != null && !append) notice(NOTICE_RESTARTED, 0);
            validator = current;
            knownTotal = info.size;
            long offset = append ? have : 0;

            if (!dir.exists()) dir.mkdirs();
            if (listener != null) listener.onStart(fileName, knownTotal);
            if (listener instanceof ResumeListener) {
                ((ResumeListener) listener).onPartial(part.getAbsolutePath(), validator, knownTotal);
            }
            if (append) notice(NOTICE_RESUMED, offset);

            final Sink sink = new Sink(append, offset);
            try {
                if (!(append && offset == info.size)) {
                    session.read(path, offset, info.size, new SftpSession.Sink() {
                        public void write(byte[] b, int off, int len) throws IOException {
                            sink.write(b, off, len);
                        }
                    });
                }
            } finally {
                sink.close();
            }
            checkCancelled();
            finishPart(sink.speed);
            session.close();
        } finally {
            session.abort();
            activeSftp = null;
        }
    }

    /** One attempt with HttpURLConnection. */
    private void downloadSystem(URL start, boolean insecure) throws IOException {
        URL url = start;
        int redirects = 0;
        String authorization = null;
        while (true) {
            checkCancelled();
            long offset = rangeOffset();
            HttpURLConnection conn = (HttpURLConnection) url.openConnection();
            activeConnection = conn;
            try {
                conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
                conn.setReadTimeout(READ_TIMEOUT_MS);
                conn.setInstanceFollowRedirects(false); // handle manually for HTTP->HTTPS or S3 redirects
                conn.setRequestProperty("User-Agent", userAgent());
                conn.setRequestProperty("Accept-Encoding", "identity"); // Ensure raw Content-Length
                if (offset > 0) {
                    conn.setRequestProperty("Range", "bytes=" + offset + "-");
                    conn.setRequestProperty("If-Range", validator);
                }
                if (authorization != null) conn.setRequestProperty("Authorization", authorization);

                TlsHelper.configureConnection(conn, insecure);

                int code = conn.getResponseCode();

                if (isRedirect(code)) {
                    url = nextHop(url, conn.getHeaderField("Location"), code, ++redirects);
                    authorization = null;
                    continue;
                }
                if (code == 401) {
                    authorization = authorize(url, headerValues(conn, "WWW-Authenticate"), authorization);
                    continue;
                }

                int action = offset > 0 ? HttpResume.decide(offset, knownTotal, code, conn.getHeaderField("Content-Range")) : 0;
                if (action == HttpResume.REREQUEST) {
                    dropPartAndRetryWithoutRange();
                    continue;
                }
                if (action == HttpResume.COMPLETE) {
                    finishPart(0);
                    return;
                }
                if (code < 200 || code >= 300) {
                    throw new IOException("HTTP server returned error response: " + code + " " + conn.getResponseMessage());
                }

                boolean append = action == HttpResume.APPEND;
                long length = conn.getContentLength();
                if (length < 0) length = parseLong(conn.getHeaderField("Content-Length"));
                accept(url, conn.getHeaderField("Content-Disposition"), append, offset, length,
                        conn.getHeaderField("Content-Range"), conn.getHeaderField("ETag"), conn.getHeaderField("Last-Modified"));

                String encoding = conn.getContentEncoding();
                boolean identity = encoding == null || encoding.equalsIgnoreCase("identity");
                Sink sink = new Sink(append, append ? offset : 0);
                InputStream in = new BufferedInputStream(conn.getInputStream(), 16384);
                try {
                    copy(in, sink, identity ? length : -1);
                } finally {
                    sink.close();
                    try { in.close(); } catch (Exception ignored) {}
                }
                if (identity && length > 0 && sink.written != length) {
                    throw new EOFException("Download incomplete: received " + sink.written + " of " + length + " bytes");
                }
                finishPart(sink.speed);
                return;
            } finally {
                conn.disconnect();
                activeConnection = null;
            }
        }
    }

    /** One attempt with the engine's own socket code: the in-tree TLS for https, a plain socket for http. */
    private void downloadOwnSocket(URL start, boolean insecure) throws IOException {
        URL url = start;
        int redirects = 0;
        String authorization = null;
        while (true) {
            checkCancelled();
            long offset = rangeOffset();
            String host = url.getHost();
            boolean isHttps = url.getProtocol().equalsIgnoreCase("https");
            int port = url.getPort() >= 0 ? url.getPort() : url.getDefaultPort();
            TlsConnection tls = null;
            Socket plain = null;
            try {
                InputStream sockIn;
                OutputStream sockOut;
                if (isHttps) {
                    X509TrustManager tm = TlsHelper.getTrustManager(insecure);
                    tls = TlsClient.connect(host, port, READ_TIMEOUT_MS, insecure ? null : tm);
                    activeTlsConnection = tls;
                    lastTlsSummary = tls.getSummary();
                    sockIn = tls.getInputStream();
                    sockOut = tls.getOutputStream();
                } else {
                    plain = new Socket();
                    activePlainSocket = plain;
                    plain.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
                    plain.setSoTimeout(READ_TIMEOUT_MS);
                    sockIn = plain.getInputStream();
                    sockOut = plain.getOutputStream();
                }
                checkCancelled();

                StringBuilder req = new StringBuilder();
                req.append("GET ").append(HttpAuth.requestTarget(url)).append(" HTTP/1.1\r\n");
                req.append("Host: ").append(host);
                if (url.getPort() >= 0 && url.getPort() != url.getDefaultPort()) req.append(':').append(url.getPort());
                req.append("\r\n");
                req.append("User-Agent: ").append(userAgent()).append("\r\n");
                req.append("Accept-Encoding: identity\r\n");
                if (offset > 0) {
                    req.append("Range: bytes=").append(offset).append("-\r\n");
                    req.append("If-Range: ").append(validator).append("\r\n");
                }
                if (authorization != null) req.append("Authorization: ").append(authorization).append("\r\n");
                req.append("Connection: close\r\n\r\n");
                sockOut.write(req.toString().getBytes("UTF-8"));
                sockOut.flush();

                InputStream in = new BufferedInputStream(sockIn, 16384);
                String statusLine = readLine(in);
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
                Map<String, String> headers = new HashMap<String, String>();
                List<String> challenges = new ArrayList<String>();
                String headerLine;
                while ((headerLine = readLine(in)) != null && !headerLine.isEmpty()) {
                    int colon = headerLine.indexOf(':');
                    if (colon > 0) {
                        String key = headerLine.substring(0, colon).trim().toLowerCase(Locale.US);
                        String val = headerLine.substring(colon + 1).trim();
                        headers.put(key, val);
                        if (key.equals("www-authenticate")) challenges.add(val);
                    }
                }

                if (isRedirect(code)) {
                    url = nextHop(url, headers.get("location"), code, ++redirects);
                    authorization = null;
                    continue;
                }
                if (code == 401) {
                    authorization = authorize(url, challenges, authorization);
                    continue;
                }

                int action = offset > 0 ? HttpResume.decide(offset, knownTotal, code, headers.get("content-range")) : 0;
                if (action == HttpResume.REREQUEST) {
                    dropPartAndRetryWithoutRange();
                    continue;
                }
                if (action == HttpResume.COMPLETE) {
                    finishPart(0);
                    return;
                }
                if (code < 200 || code >= 300) {
                    throw new IOException("HTTP server returned error: " + statusLine);
                }

                boolean append = action == HttpResume.APPEND;
                boolean chunked = headers.containsKey("transfer-encoding")
                        && headers.get("transfer-encoding").toLowerCase(Locale.US).contains("chunked");
                long length = chunked ? -1 : parseLong(headers.get("content-length"));
                accept(url, headers.get("content-disposition"), append, offset, length,
                        headers.get("content-range"), headers.get("etag"), headers.get("last-modified"));

                Sink sink = new Sink(append, append ? offset : 0);
                try {
                    if (chunked) {
                        copyChunked(in, sink);
                    } else {
                        copy(in, sink, length);
                    }
                } finally {
                    sink.close();
                }
                // A body cut short (connection closed early, or by an attacker) is never a success.
                if (!chunked && length > 0 && sink.written != length) {
                    throw new EOFException("Download incomplete: received " + sink.written + " of " + length + " bytes");
                }
                finishPart(sink.speed);
                return;
            } finally {
                if (tls != null) {
                    try { tls.close(); } catch (Exception ignored) {}
                }
                if (plain != null) {
                    try { plain.close(); } catch (Exception ignored) {}
                }
                activeTlsConnection = null;
                activePlainSocket = null;
            }
        }
    }

    // --- Shared steps ---

    private static boolean isRedirect(int code) {
        return code == 301 || code == 302 || code == 303 || code == 307 || code == 308;
    }

    private static URL nextHop(URL from, String location, int code, int redirects) throws IOException {
        if (location == null || location.isEmpty()) {
            throw new IOException("HTTP redirect " + code + " without Location header");
        }
        if (redirects >= MAX_REDIRECTS) {
            throw new IOException("Too many HTTP redirects (limit: " + MAX_REDIRECTS + ")");
        }
        // Resolve relative redirect URLs against the current URL; credentials in a Location are ignored.
        return HttpAuth.withoutUserInfo(new URL(from, location));
    }

    /** The Authorization value answering a 401 for {@code url}, or an IOException saying why not. */
    private String authorize(URL url, List<String> challenges, String previous) throws IOException {
        if (previous != null) {
            throw new IOException("Authentication failed (HTTP 401): check the user name and password");
        }
        if (credentials == null) {
            throw new IOException("HTTP 401: the server needs a user name and password; "
                    + "put them in the URL, as in http://user:password@host/path");
        }
        if (!HttpAuth.origin(url).equals(credentialOrigin)) {
            throw new IOException("HTTP 401 from " + url.getHost()
                    + ": the user name and password are only sent to the address they were given for");
        }
        HttpAuth.Answer answer = HttpAuth.answer(challenges, credentials, HttpAuth.requestTarget(url));
        if (answer == null) {
            throw new IOException("HTTP 401: unsupported authentication (" + schemesOf(challenges) + ")");
        }
        if (answer.basic && url.getProtocol().equalsIgnoreCase("http") && !cleartextNoticeSent) {
            cleartextNoticeSent = true;
            notice(NOTICE_CLEARTEXT_PASSWORD, 0);
        }
        return answer.header;
    }

    private static String schemesOf(List<String> challenges) {
        StringBuilder sb = new StringBuilder();
        for (HttpAuth.Challenge c : HttpAuth.parseChallenges(challenges)) {
            if (sb.length() > 0) sb.append(", ");
            sb.append(c.scheme);
        }
        return sb.length() > 0 ? sb.toString() : "no challenge";
    }

    private static List<String> headerValues(HttpURLConnection conn, String name) {
        List<String> out = new ArrayList<String>();
        Map<String, List<String>> fields = conn.getHeaderFields();
        if (fields == null) return out;
        for (Map.Entry<String, List<String>> e : fields.entrySet()) {
            if (e.getKey() != null && e.getKey().equalsIgnoreCase(name) && e.getValue() != null) out.addAll(e.getValue());
        }
        return out;
    }

    /** Where a range request starts: the partial file's length, or 0 for a full request. */
    private long rangeOffset() {
        if (noRange || validator == null || fileName == null) return 0;
        File part = partFile();
        return part.exists() ? part.length() : 0;
    }

    private void dropPartAndRetryWithoutRange() {
        noRange = true;
        deletePart();
        notice(NOTICE_RESTARTED, 0);
    }

    /** An accepted 2xx response: fix the file name, validator and size, and tell the listener. */
    private void accept(URL url, String contentDisposition, boolean append, long offset, long bodyLength,
                        String contentRange, String etag, String lastModified) throws IOException {
        if (fileName == null) fileName = extractFilename(url.toString(), contentDisposition);
        if (append) {
            long[] r = HttpResume.parseContentRange(contentRange);
            if (knownTotal < 0 && r != null && r[2] >= 0) knownTotal = r[2];
        } else {
            if (offset > 0) notice(NOTICE_RESTARTED, 0);
            validator = HttpResume.validator(etag, lastModified);
            knownTotal = bodyLength;
            noRange = false;
        }
        if (!dir.exists()) dir.mkdirs();
        if (listener != null) listener.onStart(fileName, knownTotal);
        if (listener instanceof ResumeListener) {
            ((ResumeListener) listener).onPartial(partFile().getAbsolutePath(), validator, knownTotal);
        }
        if (append) notice(NOTICE_RESUMED, offset);
    }

    /** The partial file holds the whole download: check its size and give it its real name. */
    private void finishPart(long speed) throws IOException {
        File part = partFile();
        long len = part.length();
        if (knownTotal > 0 && len != knownTotal) {
            throw new EOFException("Download incomplete: have " + len + " of " + knownTotal + " bytes");
        }
        File target = new File(dir, fileName);
        if (target.exists() && !target.delete()) {
            throw new IOException("Could not replace the existing " + fileName);
        }
        if (!part.renameTo(target)) {
            throw new IOException("Could not rename the finished download to " + fileName);
        }
        if (listener != null) {
            listener.onProgress(len, knownTotal, knownTotal > 0 ? 100 : -1, speed);
            listener.onComplete(target);
        }
    }

    private File partFile() {
        return new File(dir, fileName + PART_SUFFIX);
    }

    private void deletePart() {
        if (dir != null && fileName != null) {
            File part = partFile();
            if (part.exists()) part.delete();
        }
    }

    private void notice(String kind, long value) {
        if (listener instanceof ResumeListener) ((ResumeListener) listener).onNotice(kind, value);
    }

    private void checkCancelled() throws IOException {
        if (cancelled) throw new CancelledException();
    }

    private void pause(long ms) throws IOException {
        long end = System.currentTimeMillis() + ms;
        while (System.currentTimeMillis() < end) {
            checkCancelled();
            try {
                Thread.sleep(Math.min(100, Math.max(1, end - System.currentTimeMillis())));
            } catch (InterruptedException e) {
                throw new CancelledException();
            }
        }
        checkCancelled();
    }

    private static long parseLong(String s) {
        if (s == null) return -1;
        try {
            return Long.parseLong(s.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    /** The partial file being written, with progress reports in absolute bytes. */
    private final class Sink {
        final OutputStream out;
        final long start;
        long written;
        long speed;
        private long lastTime = System.currentTimeMillis();
        private long lastDone;

        Sink(boolean append, long start) throws IOException {
            this.out = new FileOutputStream(partFile(), append);
            this.start = start;
            this.lastDone = start;
        }

        void write(byte[] b, int n) throws IOException {
            write(b, 0, n);
        }

        void write(byte[] b, int off, int n) throws IOException {
            checkCancelled();
            out.write(b, off, n);
            written += n;
            attemptBytes += n;
            long now = System.currentTimeMillis();
            long dt = now - lastTime;
            if (dt >= 400) {
                long done = start + written;
                speed = ((done - lastDone) * 1000) / dt;
                lastTime = now;
                lastDone = done;
                if (listener != null) {
                    int pct = knownTotal > 0 ? (int) ((done * 100) / knownTotal) : -1;
                    listener.onProgress(done, knownTotal, pct, speed);
                }
            }
        }

        void close() {
            try {
                out.close();
            } catch (Exception ignored) {}
        }
    }

    /** Copies the body; {@code length} >= 0 stops after that many bytes. */
    private void copy(InputStream in, Sink sink, long length) throws IOException {
        byte[] buffer = new byte[16384];
        while (length < 0 || sink.written < length) {
            int want = length < 0 ? buffer.length : (int) Math.min(buffer.length, length - sink.written);
            int n = in.read(buffer, 0, want);
            if (n == -1) break;
            sink.write(buffer, n);
        }
        checkCancelled();
    }

    private void copyChunked(InputStream in, Sink sink) throws IOException {
        byte[] buffer = new byte[16384];
        while (true) {
            checkCancelled();
            String chunkHeader = readLine(in);
            if (chunkHeader == null) {
                throw new EOFException("Download incomplete: chunked body ended without its final chunk");
            }
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
                return;
            }
            int rem = chunkSize;
            while (rem > 0) {
                int n = in.read(buffer, 0, Math.min(rem, buffer.length));
                if (n == -1) throw new EOFException("Premature EOF in chunked body");
                sink.write(buffer, n);
                rem -= n;
            }
            readLine(in); // chunk CRLF
        }
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
