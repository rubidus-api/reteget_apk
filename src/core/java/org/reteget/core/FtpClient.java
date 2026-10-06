package org.reteget.core;

import java.io.ByteArrayOutputStream;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.IDN;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.reteget.core.tls.CertificatePolicy;
import org.reteget.core.tls.Tls12Socket;
import org.reteget.core.tls.Tls13Socket;
import org.reteget.core.tls.TlsConnection;
import org.reteget.core.tls.TlsVersionException;

/**
 * FTP for one download (RFC 959, passive mode), plain or over TLS (RFC 4217):
 * <ul>
 * <li>{@code ftp://} plain;</li>
 * <li>{@code ftpes://} explicit TLS: connect in the clear, {@code AUTH TLS}, then everything
 *     else, the password included, inside TLS. There is no falling back to plain;</li>
 * <li>{@code ftps://} implicit TLS: TLS from the first byte (port 990).</li>
 * </ul>
 * With TLS the data connection is always protected ({@code PBSZ 0}, {@code PROT P}) and resumes
 * the control connection's TLS session, which most servers insist on. TLS is the in-tree engine
 * (1.3, then 1.2): the platform's TLS cannot be told to reuse a session on another port, and on
 * old Android has no usable version at all.
 *
 * <p>Replies are read a byte at a time before TLS starts, so nothing sent in the clear can be
 * taken for a reply that arrived inside TLS.
 */
final class FtpClient {

    static final String FTP = "ftp";
    static final String FTPES = "ftpes";
    static final String FTPS = "ftps";

    /** Receives the file's bytes in order. */
    interface Sink {
        void write(byte[] b, int off, int len) throws IOException;
    }

    /** Size and modification time (the raw MDTM value); -1 and null where the server did not say. */
    static final class Info {
        long size = -1;
        String modified;
    }

    /** The server would not start the transfer at an offset (REST). */
    static final class RestRefusedException extends IOException {
        RestRefusedException(String reply) {
            super("The server cannot continue a file (REST refused: " + reply + ")");
        }
    }

    private static final class Reply {
        final int code;
        final String text;

        Reply(int code, String text) {
            this.code = code;
            this.text = text;
        }

        @Override
        public String toString() {
            return text;
        }
    }

    private static final Pattern EPSV = Pattern.compile("\\(\\|\\|\\|(\\d{1,5})\\|\\)");
    private static final Pattern PASV = Pattern.compile("(\\d{1,3}),(\\d{1,3}),(\\d{1,3}),(\\d{1,3}),(\\d{1,3}),(\\d{1,3})");
    private static final int MAX_REPLY_LINE = 4096;
    private static final int MAX_REPLY_LINES = 200;

    private final boolean tls;
    private final boolean implicit;
    private final String host;
    private final String asciiHost;
    private final int port;
    private final String user;
    private final String password;
    private final CertificatePolicy policy;

    private int connectTimeoutMs;
    private int readTimeoutMs;
    private Socket control;
    private InputStream in;
    private OutputStream out;
    private TlsConnection controlTls;
    private boolean tls13;
    private volatile Socket data;
    private volatile boolean aborted;
    private boolean epsvRefused;
    private Boolean dataResumed;

    /**
     * @param scheme one of {@link #FTP}, {@link #FTPES}, {@link #FTPS}
     * @param policy how the server's certificate is judged; unused for plain FTP
     */
    FtpClient(String scheme, String host, int port, String user, String password, CertificatePolicy policy) {
        this.tls = !FTP.equals(scheme);
        this.implicit = FTPS.equals(scheme);
        this.host = host;
        this.asciiHost = IDN.toASCII(host).toLowerCase(Locale.US);
        this.port = port;
        this.user = user;
        this.password = password;
        this.policy = policy;
    }

    static int defaultPort(String scheme) {
        return FTPS.equals(scheme) ? 990 : 21;
    }

    /** Connects, starts TLS when the scheme asks for it, logs in and sets binary mode. */
    void connect(int connectTimeoutMs, int readTimeoutMs) throws IOException {
        this.connectTimeoutMs = connectTimeoutMs;
        this.readTimeoutMs = readTimeoutMs;
        for (int attempt = 0; ; attempt++) {
            tls13 = attempt == 0;
            control = new Socket();
            control.connect(new InetSocketAddress(host, port), connectTimeoutMs);
            control.setSoTimeout(readTimeoutMs);
            control.setTcpNoDelay(true);
            in = control.getInputStream();
            out = control.getOutputStream();
            if (aborted) throw new IOException("Download cancelled");
            try {
                if (implicit) startTls();
                Reply r = readReply();
                if (r.code != 220) throw new IOException("The FTP server refused the connection: " + r);
                if (tls && !implicit) {
                    r = command("AUTH TLS");
                    if (r.code != 234) {
                        throw new IOException("The server does not offer FTP over TLS (AUTH TLS refused: " + r
                                + "); nothing was sent unprotected");
                    }
                    startTls();
                }
                break;
            } catch (TlsVersionException e) {
                // No TLS 1.3 there: start over on a new connection with the TLS 1.2 engine.
                closeQuietly(control);
                if (!tls13) throw e;
            }
        }

        Reply r = command("USER " + user);
        if (r.code == 331) r = command("PASS " + password);
        if (r.code != 230) {
            throw new IOException(r.code == 530 || r.code == 331 || r.code == 332
                    ? "FTP login failed: check the user name and password (" + r + ")" : "FTP login failed: " + r);
        }
        if (tls) {
            r = command("PBSZ 0");
            if (r.code != 200) throw new IOException("The server refused PBSZ: " + r);
            r = command("PROT P");
            if (r.code != 200) {
                throw new IOException("The server will not encrypt the data connection (PROT P refused: " + r + ")");
            }
        }
        r = command("TYPE I");
        if (r.code != 200) throw new IOException("The server refused binary mode: " + r);
    }

    private void startTls() throws IOException {
        controlTls = tls13 ? Tls13Socket.over(control, asciiHost, policy, null, true, false)
                : Tls12Socket.over(control, asciiHost, policy, null, true);
        in = controlTls.getInputStream();
        out = controlTls.getOutputStream();
    }

    /** One line for the user: "FTP", or "FTPS" with the TLS parameters and whether the data connection resumed. */
    String summary() {
        if (!tls) return "FTP (not encrypted)";
        return "FTPS " + (controlTls == null ? "" : controlTls.getSummary())
                + (dataResumed == null ? "" : dataResumed.booleanValue() ? ", data connection resumed" : ", data connection not resumed");
    }

    /** The file's size (SIZE) and time (MDTM), as far as the server tells. */
    Info stat(String path) throws IOException {
        Info info = new Info();
        Reply r = command("SIZE " + path);
        if (r.code == 213) {
            try {
                info.size = Long.parseLong(r.text.substring(3).trim());
            } catch (NumberFormatException ignored) {
                // no size then
            }
        }
        r = command("MDTM " + path);
        if (r.code == 213) {
            String m = r.text.substring(3).trim();
            if (m.length() >= 14) info.modified = m;
        }
        return info;
    }

    /**
     * Downloads {@code path} from {@code offset} into {@code sink}.
     *
     * @param size the size SIZE gave, or -1; without it the end of the data connection must be a
     *             clean TLS close for the file to count as complete
     * @throws RestRefusedException when {@code offset} > 0 and the server cannot start there;
     *                              nothing was transferred
     */
    void retrieve(String path, long offset, long size, Sink sink) throws IOException {
        Socket d = openData();
        data = d;
        try {
            if (offset > 0) {
                Reply rest = command("REST " + offset);
                if (rest.code != 350) throw new RestRefusedException(rest.text);
            }
            Reply r = command("RETR " + path);
            if (r.code != 150 && r.code != 125) {
                throw new IOException(r.code == 550 ? "The server cannot send this file (" + r + ")" : "RETR failed: " + r);
            }
            InputStream din;
            TlsConnection dataTls = null;
            if (tls) {
                try {
                    dataTls = tls13 ? Tls13Socket.over(d, asciiHost, policy, controlTls.session(), false, false)
                            : Tls12Socket.over(d, asciiHost, policy, controlTls.session(), false);
                } catch (IOException e) {
                    if (aborted) throw e;
                    throw new IOException("TLS on the data connection failed: " + e.getMessage()
                            + afterFailure());
                }
                dataResumed = Boolean.valueOf(dataTls.wasResumed());
                din = dataTls.getInputStream();
            } else {
                din = d.getInputStream();
            }
            byte[] buf = new byte[16384];
            long got = 0;
            int n;
            while ((n = din.read(buf)) != -1) {
                sink.write(buf, 0, n);
                got += n;
            }
            boolean clean = dataTls == null || dataTls.closedCleanly();
            closeQuietly(d);
            data = null;
            r = readReply();
            if (r.code != 226 && r.code != 250) {
                throw new IOException("The transfer did not complete: " + r);
            }
            if (size >= 0 ? offset + got != size : !clean) {
                throw new EOFException(size >= 0
                        ? "Download incomplete: received " + (offset + got) + " of " + size + " bytes"
                        : "Download incomplete: the data connection was cut");
            }
        } finally {
            closeQuietly(d);
            data = null;
        }
    }

    /** What the server says on the control connection after the data connection failed, if anything. */
    private String afterFailure() {
        try {
            control.setSoTimeout(3000);
            Reply r = readReply();
            return "; the server says: " + r;
        } catch (IOException e) {
            return "";
        }
    }

    /** A passive data connection: EPSV first, then PASV; always to the address of the control connection. */
    private Socket openData() throws IOException {
        int dataPort = -1;
        if (!epsvRefused) {
            Reply r = command("EPSV");
            Matcher m = EPSV.matcher(r.text);
            if (r.code == 229 && m.find()) {
                dataPort = Integer.parseInt(m.group(1));
            } else {
                epsvRefused = true;
            }
        }
        if (dataPort < 0) {
            Reply r = command("PASV");
            Matcher m = PASV.matcher(r.text);
            if (r.code != 227 || !m.find()) throw new IOException("The server refused passive mode: " + r);
            // The address in the reply is ignored: behind NAT it is often wrong, and a server
            // must not be able to point a protected transfer at some other machine.
            dataPort = (Integer.parseInt(m.group(5)) << 8) + Integer.parseInt(m.group(6));
        }
        if (dataPort < 1 || dataPort > 65535) throw new IOException("The server named an invalid data port");
        Socket d = new Socket();
        try {
            d.connect(new InetSocketAddress(control.getInetAddress(), dataPort), connectTimeoutMs);
            d.setSoTimeout(readTimeoutMs);
        } catch (IOException e) {
            closeQuietly(d);
            throw e;
        }
        return d;
    }

    /** Says goodbye and closes. */
    void close() {
        try {
            if (out != null && !aborted) {
                control.setSoTimeout(2000);
                command("QUIT");
            }
        } catch (IOException ignored) {
            // leaving anyway
        }
        TlsConnection t = controlTls;
        if (t != null) {
            if (t.session() != null) t.session().wipe();
            try {
                t.close();
            } catch (IOException ignored) {
            }
        }
        abort();
    }

    /** Closes both connections at once; safe from any thread (cancel). */
    void abort() {
        aborted = true;
        closeQuietly(data);
        closeQuietly(control);
    }

    private static void closeQuietly(Socket s) {
        if (s == null) return;
        try {
            s.close();
        } catch (IOException ignored) {
        }
    }

    private Reply command(String line) throws IOException {
        if (line.indexOf('\r') >= 0 || line.indexOf('\n') >= 0) {
            throw new IOException("Line breaks are not allowed in an FTP address");
        }
        out.write((line + "\r\n").getBytes("UTF-8"));
        out.flush();
        return readReply();
    }

    /** One reply, possibly of several lines (RFC 959 section 4.2); the text is the last line. */
    private Reply readReply() throws IOException {
        String line = readLine();
        if (line.length() < 3) throw new IOException("Not an FTP reply: " + printable(line));
        int code;
        try {
            code = Integer.parseInt(line.substring(0, 3));
        } catch (NumberFormatException e) {
            throw new IOException("Not an FTP reply: " + printable(line));
        }
        if (line.length() > 3 && line.charAt(3) == '-') {
            String end = line.substring(0, 3) + " ";
            for (int i = 0; ; i++) {
                if (i >= MAX_REPLY_LINES) throw new IOException("The FTP reply is too long");
                line = readLine();
                if (line.startsWith(end)) break;
            }
        }
        return new Reply(code, printable(line));
    }

    private String readLine() throws IOException {
        ByteArrayOutputStream b = new ByteArrayOutputStream();
        while (true) {
            int c = in.read();
            if (c < 0) {
                throw new EOFException(aborted ? "Download cancelled" : "The FTP server closed the connection");
            }
            if (c == '\n') break;
            if (c != '\r') b.write(c);
            if (b.size() > MAX_REPLY_LINE) throw new IOException("The FTP reply is too long");
        }
        return b.toString("UTF-8");
    }

    private static String printable(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length() && sb.length() < 200; i++) {
            char c = s.charAt(i);
            sb.append(c >= 0x20 && c != 0x7f ? c : '?');
        }
        return sb.toString();
    }
}
