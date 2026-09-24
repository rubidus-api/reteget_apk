package org.reteget.core.tls;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.SecureRandom;

/**
 * Cryptographic randomness for the TLS engine.
 *
 * Reads the kernel generator (/dev/urandom) directly when it exists: Android 4.1-4.3
 * shipped a SecureRandom whose OpenSSL PRNG could be poorly seeded, and the Galaxy Note 2
 * runs exactly those releases. Where the device file is absent (desktop JVMs on other
 * platforms) the platform SecureRandom is used.
 */
public final class TlsRandom {

    private static final File URANDOM = new File("/dev/urandom");
    private static SecureRandom fallback;

    private TlsRandom() {}

    public static void nextBytes(byte[] out) {
        if (URANDOM.canRead() && readUrandom(out)) {
            return;
        }
        synchronized (TlsRandom.class) {
            if (fallback == null) {
                fallback = new SecureRandom();
            }
            fallback.nextBytes(out);
        }
    }

    public static byte[] bytes(int n) {
        byte[] b = new byte[n];
        nextBytes(b);
        return b;
    }

    private static boolean readUrandom(byte[] out) {
        FileInputStream in = null;
        try {
            in = new FileInputStream(URANDOM);
            int pos = 0;
            while (pos < out.length) {
                int n = in.read(out, pos, out.length - pos);
                if (n <= 0) {
                    return false;
                }
                pos += n;
            }
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            if (in != null) {
                try { in.close(); } catch (IOException ignored) {}
            }
        }
    }
}
