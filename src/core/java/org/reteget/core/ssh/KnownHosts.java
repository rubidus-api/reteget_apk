package org.reteget.core.ssh;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;

/**
 * The host keys the user has accepted, one per host:port (trust on first use). A server whose
 * key is not on record, or differs from the record, is refused with an
 * {@link SshPromptException}; only {@link #trust} changes the record, and only the user's
 * explicit answer calls it.
 */
public final class KnownHosts {

    /** Persistence for the record (one string). */
    public interface Store {
        String load();

        void save(String data);
    }

    public static final class Entry {
        public final String hostPort;
        public final String keyType;
        public final String fingerprint;
        public final long firstSeen;
        final byte[] blob;

        Entry(String hostPort, byte[] blob, long firstSeen) throws IOException {
            this.hostPort = hostPort;
            this.blob = blob;
            this.firstSeen = firstSeen;
            SshHostKey k = SshHostKey.parse(blob);
            this.keyType = k.type;
            this.fingerprint = k.fingerprint();
        }
    }

    private final Store store;
    private final List<Entry> entries = new ArrayList<Entry>();

    public KnownHosts(Store store) {
        this.store = store;
        read(store == null ? null : store.load(), false);
    }

    /** host:port in the form used as the record's key. */
    public static String hostPort(String host, int port) {
        return host.toLowerCase(Locale.US) + ":" + port;
    }

    public synchronized Entry get(String hostPort) {
        for (Entry e : entries) {
            if (e.hostPort.equals(hostPort)) return e;
        }
        return null;
    }

    public synchronized List<Entry> all() {
        return new ArrayList<Entry>(entries);
    }

    /** Records {@code blob} as the key of {@code hostPort}, replacing what was there. */
    public synchronized void trust(String hostPort, byte[] blob) throws IOException {
        Entry e = new Entry(hostPort, blob.clone(), System.currentTimeMillis());
        remove(hostPort);
        entries.add(e);
        save();
    }

    /** Records the key the user was asked about (an unknown or changed host key). */
    public void trust(SshPromptException confirmed) throws IOException {
        byte[] blob = confirmed.blobBase64 == null ? null : SshBase64.decode(confirmed.blobBase64);
        if (confirmed.hostPort == null || blob == null) throw new SshException("Not a host key question");
        trust(confirmed.hostPort, blob);
    }

    public synchronized void remove(String hostPort) {
        for (int i = entries.size() - 1; i >= 0; i--) {
            if (entries.get(i).hostPort.equals(hostPort)) entries.remove(i);
        }
        save();
    }

    /** The check a connection to {@code hostPort} must pass. */
    public SshTransport.HostKeyCheck checkFor(final String hostPort) {
        return new SshTransport.HostKeyCheck() {
            public void check(SshHostKey key) throws IOException {
                Entry e = get(hostPort);
                if (e == null) throw SshPromptException.unknownHost(hostPort, key);
                if (!Arrays.equals(e.blob, key.blob())) {
                    throw SshPromptException.changedHost(hostPort, key, e.keyType, e.fingerprint);
                }
            }
        };
    }

    /** The key type on record for {@code hostPort}, so the same key is asked for again; or null. */
    public String keyTypeFor(String hostPort) {
        Entry e = get(hostPort);
        return e == null ? null : e.keyType;
    }

    /** The record as text: one "host:port type base64-blob first-seen" line per host. */
    public synchronized String export() {
        StringBuilder sb = new StringBuilder();
        for (Entry e : entries) {
            sb.append(e.hostPort).append(' ').append(e.keyType).append(' ')
                    .append(SshBase64.encode(e.blob, true)).append(' ').append(e.firstSeen).append('\n');
        }
        return sb.toString();
    }

    /** Adds the hosts of an exported record that are not on record yet; returns how many. */
    public synchronized int importMissing(String text) {
        int n = read(text, true);
        if (n > 0) save();
        return n;
    }

    private int read(String text, boolean onlyMissing) {
        int added = 0;
        if (text == null) return 0;
        for (String line : text.split("\n")) {
            String[] f = line.trim().split(" ");
            if (f.length < 3) continue;
            try {
                byte[] blob = SshBase64.decode(f[2]);
                if (blob == null || (onlyMissing && get(f[0]) != null)) continue;
                long seen = f.length > 3 ? Long.parseLong(f[3]) : 0;
                Entry e = new Entry(f[0], blob, seen);
                if (!e.keyType.equals(f[1])) continue;
                if (!onlyMissing) {
                    for (int i = entries.size() - 1; i >= 0; i--) {
                        if (entries.get(i).hostPort.equals(f[0])) entries.remove(i);
                    }
                }
                entries.add(e);
                added++;
            } catch (Exception ignored) {
                // a damaged line is skipped
            }
        }
        return added;
    }

    private void save() {
        if (store != null) store.save(export());
    }
}
