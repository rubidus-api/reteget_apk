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

    private final Cipher aesEcb;
    private final byte[] counter = new byte[16];
    private final byte[] stream = new byte[16];
    private int used = 16;

    public AesCtr(byte[] key, byte[] iv) throws Exception {
        if (key.length != 16 && key.length != 32) throw new IllegalArgumentException("AES key must be 16 or 32 bytes");
        if (iv.length < 16) throw new IllegalArgumentException("AES-CTR IV must be 16 bytes");
        aesEcb = Cipher.getInstance("AES/ECB/NoPadding");
        aesEcb.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));
        System.arraycopy(iv, 0, counter, 0, 16);
    }

    /** XORs the next {@code len} key-stream bytes into {@code in}, writing to {@code out}; may be in place. */
    public void process(byte[] in, int inOff, int len, byte[] out, int outOff) throws Exception {
        for (int i = 0; i < len; i++) {
            if (used == 16) {
                aesEcb.update(counter, 0, 16, stream, 0);
                for (int k = 15; k >= 0; k--) {
                    if (++counter[k] != 0) break;
                }
                used = 0;
            }
            out[outOff + i] = (byte) (in[inOff + i] ^ stream[used++]);
        }
    }
}
