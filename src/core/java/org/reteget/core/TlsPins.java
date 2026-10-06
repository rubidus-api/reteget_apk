package org.reteget.core;

import java.io.IOException;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import javax.net.ssl.X509TrustManager;
import org.reteget.core.tls.CertificatePolicy;
import org.reteget.core.tls.TlsException;
import org.reteget.core.tls.TlsPinException;

/**
 * Certificates the user accepted for servers whose certificates do not validate (FTPS on a NAS
 * is the usual case), one SHA-256 fingerprint per host:port. A server on record must present
 * exactly that certificate; only the user's explicit answer changes the record.
 */
public final class TlsPins {

    /** Persistence for the record (one string). */
    public interface Store {
        String load();

        void save(String data);
    }

    private static volatile TlsPins instance = new TlsPins(null);

    /** The record downloads use; the app installs one backed by its storage at start-up. */
    public static TlsPins get() {
        return instance;
    }

    public static void set(TlsPins pins) {
        instance = pins;
    }

    private final Store store;
    private final Map<String, String> pins = new LinkedHashMap<String, String>();

    public TlsPins(Store store) {
        this.store = store;
        String raw = store == null ? null : store.load();
        if (raw != null) {
            for (String line : raw.split("\n")) {
                String[] f = line.trim().split(" ");
                if (f.length == 2 && f[1].length() == 95) pins.put(f[0], f[1]);
            }
        }
    }

    public static String hostPort(String host, int port) {
        return host.toLowerCase(Locale.US) + ":" + port;
    }

    public synchronized String get(String hostPort) {
        return pins.get(hostPort);
    }

    /** Records the certificate the user was asked about. */
    public synchronized void trust(TlsCertQuestion confirmed) {
        pins.put(confirmed.hostPort, confirmed.fingerprint);
        save();
    }

    public synchronized void remove(String hostPort) {
        pins.remove(hostPort);
        save();
    }

    /** The policy for a connection to {@code hostPort}: the record when there is one, else normal validation. */
    public CertificatePolicy policyFor(String hostPort, X509TrustManager trustManager) {
        return CertificatePolicy.pinned(trustManager, get(hostPort));
    }

    /**
     * Turns a TLS failure caused by the certificate decision into the question for the user;
     * any other failure comes back unchanged.
     */
    public IOException question(String hostPort, IOException e) {
        Throwable c = e instanceof TlsException ? e.getCause() : null;
        if (!(c instanceof TlsPinException)) return e;
        TlsPinException p = (TlsPinException) c;
        return new TlsCertQuestion(p.changed ? TlsCertQuestion.CHANGED : TlsCertQuestion.UNKNOWN, hostPort,
                p.fingerprint, p.changed ? get(hostPort) : null, p.reason);
    }

    private void save() {
        if (store == null) return;
        StringBuilder sb = new StringBuilder();
        for (Map.Entry<String, String> e : pins.entrySet()) {
            sb.append(e.getKey()).append(' ').append(e.getValue()).append('\n');
        }
        store.save(sb.toString());
    }
}
