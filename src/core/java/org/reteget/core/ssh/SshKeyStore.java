package org.reteget.core.ssh;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * The user's private keys for public-key authentication. Key files are kept as they are:
 * a key protected by a passphrase stays encrypted in the store, and the passphrase is asked for
 * the first time the key is used in a run of the app and then kept, unlocked, in memory only.
 */
public final class SshKeyStore {

    /** Persistence for the keys (one string). */
    public interface Store {
        String load();

        void save(String data);
    }

    public static final class Key {
        public final String name;
        public final String fingerprint;
        public final String type;
        public final boolean isProtected;
        final SshKeyFile file;

        Key(String name, SshKeyFile file) {
            this.name = name;
            this.file = file;
            this.fingerprint = file.fingerprint();
            this.type = file.type;
            this.isProtected = file.isProtected();
        }

        /** The stored key file (still protected when the key has a passphrase). */
        public SshKeyFile file() {
            return file;
        }

        /** The line to put into the server's authorized_keys. */
        public String publicKeyLine() {
            return file.publicKeyLine(name);
        }
    }

    private final Store store;
    private final List<Key> keys = new ArrayList<Key>();
    private final Map<String, SshIdentity> unlocked = new HashMap<String, SshIdentity>();

    public SshKeyStore(Store store) {
        this.store = store;
        String raw = store == null ? null : store.load();
        if (raw != null) {
            for (String line : raw.split("\n")) {
                int sp = line.indexOf(' ');
                if (sp <= 0) continue;
                try {
                    byte[] name = SshBase64.decode(line.substring(0, sp));
                    byte[] text = SshBase64.decode(line.substring(sp + 1));
                    keys.add(new Key(SshBuf.fromUtf8(name), SshKeyFile.parse(SshBuf.fromUtf8(text))));
                } catch (Exception ignored) {
                    // a damaged record is skipped
                }
            }
        }
    }

    public synchronized List<Key> list() {
        return new ArrayList<Key>(keys);
    }

    public synchronized Key find(String fingerprint) {
        for (Key k : keys) {
            if (k.fingerprint.equals(fingerprint)) return k;
        }
        return null;
    }

    /** Stores a key under a name; an SshException when the same key is already there. */
    public synchronized Key add(String name, SshKeyFile file) throws IOException {
        if (find(file.fingerprint()) != null) throw new SshException("This key is already stored");
        String n = name == null ? "" : name.replace('\n', ' ').replace('\t', ' ').trim();
        if (n.length() == 0) n = file.type.substring(4) + " key";
        Key k = new Key(n, file);
        keys.add(k);
        save();
        return k;
    }

    /** A new Ed25519 key; a passphrase (may be null) protects it. */
    public Key generate(String name, String passphrase) throws IOException {
        return add(name, SshKeyFile.generateEd25519(name == null ? "" : name, passphrase));
    }

    public synchronized void remove(String fingerprint) {
        for (int i = keys.size() - 1; i >= 0; i--) {
            if (keys.get(i).fingerprint.equals(fingerprint)) keys.remove(i);
        }
        unlocked.remove(fingerprint);
        save();
    }

    /** Sets, changes or (with null) removes a key's passphrase. */
    public synchronized void setPassphrase(String fingerprint, String oldPassphrase, String newPassphrase) throws IOException {
        Key k = find(fingerprint);
        if (k == null) throw new SshException("That key is no longer stored");
        Key changed = new Key(k.name, k.file.withPassphrase(oldPassphrase, newPassphrase));
        keys.set(keys.indexOf(k), changed);
        unlocked.remove(fingerprint);
        save();
    }

    public synchronized boolean isUnlocked(String fingerprint) {
        Key k = find(fingerprint);
        return k != null && (!k.isProtected || unlocked.containsKey(fingerprint));
    }

    /** Opens a protected key for this run of the app; an SshException "Wrong passphrase" when it does not fit. */
    public synchronized void unlock(String fingerprint, String passphrase) throws IOException {
        Key k = find(fingerprint);
        if (k == null) throw new SshException("That key is no longer stored");
        unlocked.put(fingerprint, k.file.unlock(passphrase));
    }

    /** Forgets every unlocked key. */
    public synchronized void lockAll() {
        unlocked.clear();
    }

    /**
     * The key ready to sign. An {@link SshPromptException} when its passphrase has not been
     * given yet in this run.
     */
    public synchronized SshIdentity identity(String fingerprint) throws IOException {
        Key k = find(fingerprint);
        if (k == null) throw new SshException("The key chosen for this download is no longer stored");
        SshIdentity id = unlocked.get(fingerprint);
        if (id != null) return id;
        if (k.isProtected) throw SshPromptException.passphrase(fingerprint, k.name);
        id = k.file.unlock(null);
        unlocked.put(fingerprint, id);
        return id;
    }

    private void save() {
        if (store == null) return;
        StringBuilder sb = new StringBuilder();
        for (Key k : keys) {
            sb.append(SshBase64.encode(SshBuf.utf8(k.name), true)).append(' ')
                    .append(SshBase64.encode(SshBuf.utf8(k.file.text()), true)).append('\n');
        }
        store.save(sb.toString());
    }
}
