package org.reteget.core.ssh;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

/**
 * AES in counter mode (NIST SP 800-38A) as SSH uses it (RFC 4344): one key stream for the whole
 * connection direction, the 128-bit counter starting at the IV and counting big-endian.
 *
 * Only the AES block operation comes from the platform ("AES/ECB/NoPadding", present since
 * API 1); "AES/CTR/NoPadding" is not reliable on the oldest Android releases.
 */
public final class AesCtr {

    /** Key stream is made this many blocks at a time: one cipher call instead of one per block. */
    private static final int BATCH = 2048;

    private final Cipher aesEcb;
    private final byte[] counter = new byte[16];
    private final byte[] counters = new byte[16 * BATCH];
    private final byte[] stream = new byte[16 * BATCH];
    private int used = 0;
    private int filled = 0;

    public AesCtr(byte[] key, byte[] iv) throws Exception {
        if (key.length != 16 && key.length != 32) throw new IllegalArgumentException("AES key must be 16 or 32 bytes");
        if (iv.length < 16) throw new IllegalArgumentException("AES-CTR IV must be 16 bytes");
        aesEcb = Cipher.getInstance("AES/ECB/NoPadding");
        aesEcb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        System.arraycopy(iv, 0, counter, 0, 16);
    }

    /** Makes key stream for at least {@code want} bytes (up to a full batch). */
    private void refill(int want) throws Exception {
        int blocks = Math.min(BATCH, (want + 15) / 16);
        for (int b = 0; b < blocks; b++) {
            System.arraycopy(counter, 0, counters, 16 * b, 16);
            for (int k = 15; k >= 0; k--) {
                if (++counter[k] != 0) break;
            }
        }
        int n = aesEcb.update(counters, 0, 16 * blocks, stream, 0);
        if (n != 16 * blocks) throw new IllegalStateException("AES block cipher returned " + n + " bytes");
        used = 0;
        filled = 16 * blocks;
    }

    /** XORs the next {@code len} key-stream bytes into {@code in}, writing to {@code out}; may be in place. */
    public void process(byte[] in, int inOff, int len, byte[] out, int outOff) throws Exception {
        while (len > 0) {
            if (used == filled) refill(len);
            int n = Math.min(len, filled - used);
            final byte[] ks = stream;
            int u = used;
            for (int i = 0; i < n; i++) {
                out[outOff + i] = (byte) (in[inOff + i] ^ ks[u + i]);
            }
            used += n;
            inOff += n;
            outOff += n;
            len -= n;
        }
    }
}
