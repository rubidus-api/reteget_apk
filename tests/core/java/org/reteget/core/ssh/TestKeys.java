package org.reteget.core.ssh;

/** Test access to package-private helpers. */
public final class TestKeys {

    private TestKeys() {}

    public static byte[] decode(String base64) {
        return SshBase64.decode(base64);
    }
}
