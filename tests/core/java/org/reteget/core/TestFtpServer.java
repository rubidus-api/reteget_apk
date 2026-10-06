package org.reteget.core;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;

/**
 * An FTP server for the tests on 127.0.0.1: plain, explicit TLS (AUTH TLS) or implicit TLS, with
 * the JDK's TLS. Like vsftpd and ProFTPD it can insist that the data connection resumes the
 * control connection's TLS session. The fields configure what it supports and how it misbehaves.
 */
public final class TestFtpServer implements Runnable {

    // --- configuration ---
    public String mode = "plain"; // plain, explicit, implicit
    public String[] protocols = { "TLSv1.3", "TLSv1.2" };
    public boolean requireReuse = true;
    public boolean forgetSessionBeforeData;
    public boolean supportRest = true;
    public boolean supportMdtm = true;
    public boolean supportEpsv = true;
    public boolean allowProtP = true;
    public String user = "user";
    public String password = "pw";
    public final Map<String, byte[]> files = new HashMap<String, byte[]>();
    public final Map<String, String> mdtm = new HashMap<String, String>();
    /** Cut the data connection after this many bytes, on the first transfer only (-1: never). */
    public long cutAfter = -1;

    // --- observations ---
    public final List<String> log = Collections.synchronizedList(new ArrayList<String>());
    public volatile int sessions;
    public volatile int transfers;
    public volatile String lastDataReuse = "";

    private final ServerSocket ss;
    private SSLContext ctx;
    private volatile boolean closed;

    public TestFtpServer() throws IOException {
        this(0);
    }

    public TestFtpServer(int port) throws IOException {
        ss = new ServerSocket(port, 50, InetAddress.getByName("127.0.0.1"));
    }

    /** {@code keystore} is a PKCS#12 file with the alias "server" and password "changeit"; null for plain only. */
    public TestFtpServer start(File keystore) throws Exception {
        if (keystore != null) useKeystore(keystore);
        Thread t = new Thread(this, "TestFtpServer");
        t.setDaemon(true);
        t.start();
        return this;
    }

    /** Switches to another certificate, as after a renewal (or an interception). */
    public void useKeystore(File keystore) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        FileInputStream in = new FileInputStream(keystore);
        try {
            ks.load(in, "changeit".toCharArray());
        } finally {
            in.close();
        }
        KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
        kmf.init(ks, "changeit".toCharArray());
        SSLContext c = SSLContext.getInstance("TLS");
        c.init(kmf.getKeyManagers(), null, null);
        ctx = c;
    }

    public int port() {
        return ss.getLocalPort();
    }

    public void close() {
        closed = true;
        try {
            ss.close();
        } catch (IOException ignored) {
        }
    }

    /** TestFtpServer <port> <mode> <keystore.p12|-> <password> <file>...: user "user", files as /pub/NAME. */
    public static void main(String[] args) throws Exception {
        TestFtpServer s = new TestFtpServer(Integer.parseInt(args[0]));
        s.mode = args[1];
        s.password = args[3];
        for (int i = 4; i < args.length; i++) {
            File f = new File(args[i]);
            s.files.put("/pub/" + f.getName(), java.nio.file.Files.readAllBytes(f.toPath()));
            s.mdtm.put("/pub/" + f.getName(), "20260101000000");
        }
        s.start("-".equals(args[2]) ? null : new File(args[2]));
        System.out.println("listening on 127.0.0.1:" + s.port() + " (" + s.mode + ")");
        while (true) Thread.sleep(60000);
    }

    public void run() {
        while (!closed) {
            final Socket s;
            try {
                s = ss.accept();
            } catch (IOException e) {
                return;
            }
            final int number = ++sessions;
            Thread t = new Thread(new Runnable() {
                public void run() {
                    try {
                        new Session(s, number).serve();
                    } catch (Exception e) {
                        log.add("server: " + e);
                    } finally {
                        try {
                            s.close();
                        } catch (IOException ignored) {
                        }
                    }
                }
            }, "TestFtpServer-session");
            t.setDaemon(true);
            t.start();
        }
    }

    private SSLSocket serverTls(Socket s) throws IOException {
        SSLSocket t = (SSLSocket) ctx.getSocketFactory().createSocket(s, null, s.getPort(), true);
        t.setUseClientMode(false);
        t.setEnabledProtocols(protocols);
        t.startHandshake();
        return t;
    }

    private final class Session {
        final Socket socket;
        final int number;
        InputStream in;
        OutputStream out;
        SSLSocket controlTls;
        boolean loggedIn, protP;
        String pendingUser;
        ServerSocket passive;
        long restart;

        Session(Socket s, int number) throws IOException {
            this.socket = s;
            this.number = number;
            s.setSoTimeout(15000);
            in = s.getInputStream();
            out = s.getOutputStream();
        }

        void reply(String line) throws IOException {
            out.write((line + "\r\n").getBytes("UTF-8"));
            out.flush();
        }

        String readLine() throws IOException {
            ByteArrayOutputStream b = new ByteArrayOutputStream();
            int c;
            while ((c = in.read()) >= 0 && c != '\n') {
                if (c != '\r') b.write(c);
            }
            return c < 0 && b.size() == 0 ? null : b.toString("UTF-8");
        }

        void startTls() throws IOException {
            controlTls = serverTls(socket);
            in = controlTls.getInputStream();
            out = controlTls.getOutputStream();
        }

        void serve() throws Exception {
            if ("implicit".equals(mode)) startTls();
            reply("220-Test FTP server");
            reply("220 ready");
            String line;
            while ((line = readLine()) != null) {
                String cmd = line.contains(" ") ? line.substring(0, line.indexOf(' ')).toUpperCase() : line.toUpperCase();
                String arg = line.contains(" ") ? line.substring(line.indexOf(' ') + 1) : "";
                log.add(((controlTls != null ? "tls " : "clear ") + cmd + ("PASS".equals(cmd) ? "" : " " + arg)).trim());
                if ("AUTH".equals(cmd)) {
                    if (!"explicit".equals(mode) || controlTls != null) {
                        reply("502 AUTH not available");
                    } else {
                        reply("234 Proceed with negotiation");
                        startTls();
                    }
                } else if ("USER".equals(cmd)) {
                    if ("explicit".equals(mode) && controlTls == null) {
                        reply("530 TLS required");
                    } else {
                        pendingUser = arg;
                        reply("anonymous".equals(arg) ? "230 Anonymous access" : "331 Password please");
                        loggedIn = "anonymous".equals(arg);
                    }
                } else if ("PASS".equals(cmd)) {
                    loggedIn = user.equals(pendingUser) && password.equals(arg);
                    reply(loggedIn ? "230 Logged in" : "530 Login incorrect");
                } else if ("QUIT".equals(cmd)) {
                    reply("221 Bye");
                    return;
                } else if (!loggedIn) {
                    reply("530 Please log in");
                } else if ("PBSZ".equals(cmd)) {
                    reply(controlTls != null ? "200 PBSZ=0" : "503 not in TLS");
                } else if ("PROT".equals(cmd)) {
                    if (controlTls == null || !allowProtP || !"P".equals(arg)) {
                        reply("534 Protection level refused");
                    } else {
                        protP = true;
                        reply("200 Protection set to Private");
                    }
                } else if ("TYPE".equals(cmd)) {
                    reply("200 Type set");
                } else if ("SIZE".equals(cmd)) {
                    byte[] f = files.get(arg);
                    reply(f == null ? "550 No such file" : "213 " + f.length);
                } else if ("MDTM".equals(cmd)) {
                    String m = mdtm.get(arg);
                    reply(!supportMdtm ? "502 no MDTM" : files.get(arg) == null ? "550 No such file" : "213 " + (m == null ? "20240102030405" : m));
                } else if ("EPSV".equals(cmd) || "PASV".equals(cmd)) {
                    if ("EPSV".equals(cmd) && !supportEpsv) {
                        reply("500 EPSV not understood");
                        continue;
                    }
                    if (passive != null) passive.close();
                    passive = new ServerSocket(0, 1, InetAddress.getByName("127.0.0.1"));
                    passive.setSoTimeout(10000);
                    int p = passive.getLocalPort();
                    reply("EPSV".equals(cmd) ? "229 Entering Extended Passive Mode (|||" + p + "|)"
                            : "227 Entering Passive Mode (10,255,255,1," + (p >> 8) + "," + (p & 0xff) + ")"); // a wrong address
                } else if ("REST".equals(cmd)) {
                    if (supportRest) {
                        restart = Long.parseLong(arg);
                        reply("350 Restarting at " + restart);
                    } else {
                        reply("502 REST not implemented");
                    }
                } else if ("RETR".equals(cmd)) {
                    retr(arg);
                } else {
                    reply("502 Not implemented");
                }
            }
        }

        void retr(String path) throws Exception {
            byte[] f = files.get(path);
            long from = restart;
            restart = 0;
            if (f == null) {
                reply("secret.bin".equals(path) ? "550 Permission denied" : "550 No such file");
                return;
            }
            if (passive == null) {
                reply("425 Use PASV first");
                return;
            }
            Socket d = passive.accept();
            passive.close();
            passive = null;
            try {
                reply("150 Opening data connection");
                OutputStream dout;
                SSLSocket dataTls = null;
                if (protP) {
                    if (forgetSessionBeforeData) controlTls.getSession().invalidate();
                    dataTls = serverTls(d);
                    SSLSession a = controlTls.getSession();
                    SSLSession b = dataTls.getSession();
                    boolean reused = (a.getId().length > 0 && Arrays.equals(a.getId(), b.getId()))
                            || a.getCreationTime() == b.getCreationTime();
                    lastDataReuse = b.getProtocol() + (reused ? " reused" : " new");
                    if (requireReuse && !reused) {
                        dataTls.close();
                        reply("522 SSL connection failed: session reuse required");
                        return;
                    }
                    dout = dataTls.getOutputStream();
                } else {
                    dout = d.getOutputStream();
                }
                int len = f.length - (int) from;
                if (cutAfter >= 0 && ++transfers == 1 && len > cutAfter) {
                    dout.write(f, (int) from, (int) cutAfter);
                    dout.flush();
                    d.close(); // no TLS close_notify, no 226
                    socket.close();
                    return;
                }
                dout.write(f, (int) from, len);
                dout.flush();
                if (dataTls != null) dataTls.close(); else d.close();
                reply("226 Transfer complete");
            } finally {
                d.close();
            }
        }
    }
}
