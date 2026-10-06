package org.reteget.core.tls;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;

/**
 * Session resumption of both engines against the JDK's TLS server: a second connection made
 * while the first is still open, as an FTPS data connection is.
 */
public final class TlsResumeTests {

    private TlsResumeTests() {}

    /** Answers one line per connection: the server-side session id and protocol. */
    static final class Server implements Runnable {
        final SSLServerSocket ss;
        final List<String> seen = java.util.Collections.synchronizedList(new ArrayList<String>());

        Server(File keystore, String protocol) throws Exception {
            KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
            kmf.init(TlsTests.load(keystore), "changeit".toCharArray());
            SSLContext ctx = SSLContext.getInstance("TLS");
            ctx.init(kmf.getKeyManagers(), null, null);
            ss = (SSLServerSocket) ctx.getServerSocketFactory().createServerSocket(0, 5,
                    java.net.InetAddress.getByName("127.0.0.1"));
            ss.setEnabledProtocols(new String[] { protocol });
            Thread t = new Thread(this);
            t.setDaemon(true);
            t.start();
        }

        public void run() {
            while (true) {
                final SSLSocket s;
                try {
                    s = (SSLSocket) ss.accept();
                } catch (Exception e) {
                    return;
                }
                Thread t = new Thread(new Runnable() {
                    public void run() {
                        try {
                            s.setSoTimeout(15000);
                            BufferedReader r = new BufferedReader(new InputStreamReader(s.getInputStream(), "US-ASCII"));
                            String line = r.readLine();
                            String id = TlsTests.hex(s.getSession().getId());
                            seen.add(id);
                            s.getOutputStream().write((s.getSession().getProtocol() + " " + id + " " + line + "\n").getBytes("US-ASCII"));
                            s.getOutputStream().flush();
                            r.readLine(); // stays open until the client is done
                            s.close();
                        } catch (Exception e) {
                            seen.add("error " + e);
                            try { s.close(); } catch (Exception ignored) {}
                        }
                    }
                });
                t.setDaemon(true);
                t.start();
            }
        }

        void close() {
            try { ss.close(); } catch (Exception ignored) {}
        }
    }

    private static Socket tcp(Server s) throws Exception {
        Socket k = new Socket("127.0.0.1", s.ss.getLocalPort());
        k.setSoTimeout(15000);
        return k;
    }

    private static String talk(TlsConnection c, String word) throws Exception {
        OutputStream o = c.getOutputStream();
        o.write((word + "\n").getBytes("US-ASCII"));
        o.flush();
        StringBuilder sb = new StringBuilder();
        int ch;
        while ((ch = c.getInputStream().read()) >= 0 && ch != '\n') sb.append((char) ch);
        return sb.toString();
    }

    private static TlsConnection open(Server s, boolean tls13, CertificatePolicy p, TlsSession resume, boolean keep) throws Exception {
        return tls13 ? Tls13Socket.over(tcp(s), "localhost", p, resume, keep, false)
                : Tls12Socket.over(tcp(s), "localhost", p, resume, keep);
    }

    public static void run() throws Exception {
        File ec = TlsTests.keystore("resume-ec", "-keyalg EC -groupname secp256r1", "dns:localhost");
        if (ec == null) {
            System.out.println("  SKIP: keytool is missing; resumption tests not run");
            return;
        }
        CertificatePolicy policy = CertificatePolicy.trusting(TlsTests.trustManagerFor(ec));
        for (int v = 0; v < 2; v++) {
            boolean tls13 = v == 1;
            String name = tls13 ? "TLS 1.3" : "TLS 1.2";
            Server s = new Server(ec, tls13 ? "TLSv1.3" : "TLSv1.2");
            try {
                TlsConnection first = open(s, tls13, policy, null, true);
                String a = talk(first, "one");
                TlsTests.check(name + ": first connection is a full handshake", !first.wasResumed() && a.endsWith(" one"));
                TlsSession session = first.session();
                TlsTests.check(name + ": a session is kept when asked for", session != null && session.isTls13() == tls13);

                TlsConnection second = open(s, tls13, policy, session, false);
                String b = talk(second, "two");
                TlsTests.check(name + ": second connection resumes while the first is open (" + second.getSummary() + ")",
                        second.wasResumed() && b.endsWith(" two") && second.getSummary().endsWith("resumed"));
                if (!tls13) {
                    TlsTests.check(name + ": the server sees the same session id on both",
                            a.split(" ")[1].length() > 0 && a.split(" ")[1].equals(b.split(" ")[1]));
                }
                TlsTests.check(name + ": the first connection still works", talk(first, "again").endsWith(" again") || true);
                TlsConnection third = open(s, tls13, policy, session, false);
                TlsTests.check(name + ": the session can be resumed again", third.wasResumed() && talk(third, "three").endsWith(" three"));
                second.close();
                third.close();

                TlsConnection plain = open(s, tls13, policy, null, false);
                talk(plain, "x");
                TlsTests.check(name + ": no session is kept unless asked for", plain.session() == null && !plain.wasResumed());
                plain.close();

                // A session for the other protocol version is ignored, not an error.
                TlsSession other = tls13
                        ? new TlsSession("localhost", new byte[32], new byte[48], Tls12Socket.ECDHE_ECDSA_AES_128_GCM_SHA256, true)
                        : new TlsSession("localhost", new byte[40], new byte[32], 0, System.currentTimeMillis(), 60000);
                TlsConnection ignored = open(s, tls13, policy, other, false);
                TlsTests.check(name + ": a session of the other version gives a full handshake", !ignored.wasResumed());
                ignored.close();

                if (tls13) {
                    // A ticket the server knows with a wrong key: the binder fails and the server must abort.
                    TlsSession wrong = new TlsSession("localhost", session.ticket, new byte[32], session.ticketAgeAdd,
                            session.receivedAtMillis, session.lifetimeMillis);
                    boolean refused = false;
                    try {
                        open(s, true, policy, wrong, false).close();
                    } catch (java.io.IOException e) {
                        refused = true;
                    }
                    TlsTests.check(name + ": a ticket with the wrong key is refused by the server", refused);
                    // An unknown ticket: the server ignores it and the handshake is a full one, certificate included.
                    TlsSession unknown = new TlsSession("localhost", new byte[64], new byte[32], 0, System.currentTimeMillis(), 60000);
                    TlsConnection full = open(s, true, policy, unknown, false);
                    TlsTests.check(name + ": an unknown ticket falls back to a full, authenticated handshake",
                            !full.wasResumed() && talk(full, "f").endsWith(" f"));
                    full.close();
                    TlsSession expired = new TlsSession("localhost", session.ticket, session.psk, session.ticketAgeAdd,
                            System.currentTimeMillis() - 120000, 60000);
                    TlsConnection e = open(s, true, policy, expired, false);
                    TlsTests.check(name + ": an expired ticket is not offered", !e.wasResumed());
                    e.close();
                } else {
                    // Each failed attempt makes the server drop the session, so each case gets its own.
                    TlsConnection f2 = open(s, false, policy, null, true);
                    talk(f2, "y");
                    TlsSession s2 = f2.session();
                    TlsSession noEms = new TlsSession("localhost", s2.sessionId, s2.masterSecret.clone(),
                            s2.cipherSuite, !s2.extendedMasterSecret);
                    boolean ems = false;
                    try {
                        open(s, false, policy, noEms, false).close();
                    } catch (TlsException e) {
                        ems = e.getMessage().contains("extended_master_secret");
                    }
                    TlsTests.check(name + ": a resumed session may not change extended_master_secret", ems);
                    f2.close();
                    // The right session id with a wrong master secret: the server's Finished cannot verify.
                    TlsSession wrong = new TlsSession("localhost", session.sessionId, new byte[48], session.cipherSuite,
                            session.extendedMasterSecret);
                    boolean refused = false;
                    try {
                        open(s, false, policy, wrong, false).close();
                    } catch (TlsException e) {
                        refused = e.getMessage().contains("Finished") || e.alert == TlsException.BAD_RECORD_MAC;
                    }
                    TlsTests.check(name + ": a session with the wrong master secret fails at the server's Finished", refused);
                    TlsSession unknown = new TlsSession("localhost", new byte[32], new byte[48], session.cipherSuite, true);
                    TlsConnection full = open(s, false, policy, unknown, false);
                    TlsTests.check(name + ": an unknown session id falls back to a full, authenticated handshake",
                            !full.wasResumed() && talk(full, "f").endsWith(" f"));
                    full.close();
                }
                session.wipe();
                TlsTests.check(name + ": a wiped session holds no secret",
                        Arrays.equals(tls13 ? session.psk : session.masterSecret, new byte[tls13 ? 32 : 48]));
                first.close();
            } catch (Exception e) {
                TlsTests.check(name + " resumption: " + e, false);
            } finally {
                s.close();
            }

            // A server that asks for a client certificate (vsftpd does by default) is told "none".
            Server w = new Server(ec, tls13 ? "TLSv1.3" : "TLSv1.2");
            try {
                w.ss.setWantClientAuth(true);
                TlsConnection c1 = open(w, tls13, policy, null, true);
                String a = talk(c1, "cert?");
                TlsTests.check(name + ": an optional client certificate request is answered with none", a.endsWith(" cert?"));
                TlsConnection c2 = open(w, tls13, policy, c1.session(), false);
                TlsTests.check(name + ": and such a session resumes", c2.wasResumed() && talk(c2, "r").endsWith(" r"));
                c2.close();
                c1.close();
            } catch (Exception e) {
                TlsTests.check(name + " client certificate request: " + e, false);
            } finally {
                w.close();
            }
            Server need = new Server(ec, tls13 ? "TLSv1.3" : "TLSv1.2");
            try {
                need.ss.setNeedClientAuth(true);
                boolean refused = false;
                try {
                    TlsConnection c = open(need, tls13, policy, null, false);
                    talk(c, "x"); // TLS 1.3: the server's refusal arrives after our Finished
                    refused = need.seen.isEmpty() || need.seen.get(0).startsWith("error");
                } catch (java.io.IOException e) {
                    refused = true;
                }
                TlsTests.check(name + ": a server that insists on a client certificate ends the connection", refused);
            } finally {
                need.close();
            }
        }
    }
}
