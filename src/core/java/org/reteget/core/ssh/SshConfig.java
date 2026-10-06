package org.reteget.core.ssh;

/**
 * Where sftp:// downloads find the host key record and the user's keys. The app sets both at
 * start-up. Without a host key record every server is unknown, so nothing connects unconfirmed.
 */
public final class SshConfig {

    private SshConfig() {}

    private static volatile KnownHosts knownHosts = new KnownHosts(null);
    private static volatile SshKeyStore keys = new SshKeyStore(null);

    public static void set(KnownHosts hosts, SshKeyStore keyStore) {
        knownHosts = hosts;
        keys = keyStore;
    }

    public static KnownHosts knownHosts() {
        return knownHosts;
    }

    public static SshKeyStore keys() {
        return keys;
    }
}
