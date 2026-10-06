package org.reteget.core.ssh;

/**
 * The download cannot go on until the user decides or supplies something: an unknown host key
 * to confirm, a changed host key, or the passphrase of the chosen key. The download fails with
 * this; {@link #token} travels in the queue record so the question can be asked later, also
 * after the app was closed.
 */
public final class SshPromptException extends SshException {

    public static final String UNKNOWN_HOST = "hostkey";
    public static final String CHANGED_HOST = "hostkey-changed";
    public static final String PASSPHRASE = "passphrase";

    public final String kind;
    /** host:port, for the host key kinds. */
    public final String hostPort;
    /** The key the server presented (host key kinds). */
    public final String keyType, fingerprint, blobBase64;
    /** What was on record (CHANGED_HOST). */
    public final String oldKeyType, oldFingerprint;
    /** The user's key that is locked, and its name (PASSPHRASE). */
    public final String identityFingerprint, identityName;

    private SshPromptException(String message, String kind, String hostPort, String keyType, String fingerprint,
                               String blobBase64, String oldKeyType, String oldFingerprint,
                               String identityFingerprint, String identityName) {
        super(message);
        this.kind = kind;
        this.hostPort = hostPort;
        this.keyType = keyType;
        this.fingerprint = fingerprint;
        this.blobBase64 = blobBase64;
        this.oldKeyType = oldKeyType;
        this.oldFingerprint = oldFingerprint;
        this.identityFingerprint = identityFingerprint;
        this.identityName = identityName;
    }

    static SshPromptException unknownHost(String hostPort, SshHostKey key) {
        return new SshPromptException("The host key of " + hostPort + " is not known yet (" + key.type + " "
                + key.fingerprint() + "); confirm it to continue", UNKNOWN_HOST, hostPort, key.type, key.fingerprint(),
                SshBase64.encode(key.blob(), true), null, null, null, null);
    }

    static SshPromptException changedHost(String hostPort, SshHostKey key, String oldType, String oldFingerprint) {
        return new SshPromptException("The host key of " + hostPort + " has changed: it was " + oldType + " "
                + oldFingerprint + " and is now " + key.type + " " + key.fingerprint()
                + ". The server may have been reinstalled, or someone may be intercepting the connection",
                CHANGED_HOST, hostPort, key.type, key.fingerprint(), SshBase64.encode(key.blob(), true),
                oldType, oldFingerprint, null, null);
    }

    static SshPromptException passphrase(String identityFingerprint, String name) {
        return new SshPromptException("The key \"" + name + "\" needs its passphrase", PASSPHRASE, null, null, null,
                null, null, null, identityFingerprint, name);
    }

    /** The question as one line of tab-separated fields, for the queue record. */
    public String token() {
        if (PASSPHRASE.equals(kind)) return kind + "\t" + identityFingerprint + "\t" + identityName.replace('\t', ' ');
        return kind + "\t" + hostPort + "\t" + keyType + "\t" + fingerprint + "\t" + blobBase64
                + (CHANGED_HOST.equals(kind) ? "\t" + oldKeyType + "\t" + oldFingerprint : "");
    }

    /** The question a token stands for, or null when it is not one. */
    public static SshPromptException fromToken(String token) {
        if (token == null) return null;
        String[] f = token.split("\t", -1);
        try {
            if (PASSPHRASE.equals(f[0]) && f.length == 3) return passphrase(f[1], f[2]);
            if (UNKNOWN_HOST.equals(f[0]) && f.length == 5) {
                return unknownHost(f[1], SshHostKey.parse(SshBase64.decode(f[4])));
            }
            if (CHANGED_HOST.equals(f[0]) && f.length == 7) {
                return changedHost(f[1], SshHostKey.parse(SshBase64.decode(f[4])), f[5], f[6]);
            }
        } catch (Exception e) {
            return null;
        }
        return null;
    }
}
