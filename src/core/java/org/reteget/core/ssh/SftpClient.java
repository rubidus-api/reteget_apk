package org.reteget.core.ssh;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * The read-only part of SFTP version 3 (draft-ietf-secsh-filexfer-02), the version OpenSSH,
 * Dropbear's sftp-server and most NAS boxes speak: stat, open, read, close.
 *
 * <p>Reads are pipelined: several READ requests are in flight at once, so a link with a long
 * round trip is not limited to one 32 KiB block per round trip. Answers are written out strictly
 * in file order whatever order they arrive in.
 */
final class SftpClient {

    /** Receives the file's bytes in order. */
    interface Sink {
        void write(byte[] b, int off, int len) throws IOException;
    }

    /** The attributes a download needs. */
    static final class Attrs {
        /** -1 when the server did not say. */
        long size = -1;
        long mtime = -1;
        boolean directory;
    }

    private static final int FXP_INIT = 1;
    private static final int FXP_VERSION = 2;
    private static final int FXP_OPEN = 3;
    private static final int FXP_CLOSE = 4;
    private static final int FXP_READ = 5;
    private static final int FXP_STAT = 17;
    private static final int FXP_STATUS = 101;
    private static final int FXP_HANDLE = 102;
    private static final int FXP_DATA = 103;
    private static final int FXP_ATTRS = 105;

    private static final int FX_OK = 0;
    private static final int FX_EOF = 1;
    private static final int FX_NO_SUCH_FILE = 2;
    private static final int FX_PERMISSION_DENIED = 3;

    private static final int ATTR_SIZE = 1;
    private static final int ATTR_UIDGID = 2;
    private static final int ATTR_PERMISSIONS = 4;
    private static final int ATTR_ACMODTIME = 8;

    static final int READ_SIZE = 32768;
    static final int MAX_IN_FLIGHT = 8;
    private static final int MAX_SFTP_PACKET = 256 * 1024;

    private final SshChannel channel;
    private long nextId = 1;

    SftpClient(SshChannel channel) {
        this.channel = channel;
    }

    void init() throws IOException {
        send(new SshBuf.Writer().u8(FXP_INIT).u32(3).bytes());
        byte[] p = receive();
        if ((p[0] & 0xff) != FXP_VERSION) throw new SshException("the server's SFTP did not start (message " + (p[0] & 0xff) + ")");
        long version = new SshBuf.Reader(p, 1, p.length - 1).u32();
        if (version < 3) throw new SshException("the server speaks SFTP version " + version + " (3 needed)");
    }

    Attrs stat(String path) throws IOException {
        long id = nextId++;
        send(new SshBuf.Writer().u8(FXP_STAT).u32(id).string(path).bytes());
        SshBuf.Reader r = response(id, FXP_ATTRS, path);
        Attrs a = new Attrs();
        long flags = r.u32();
        if ((flags & ATTR_SIZE) != 0) a.size = r.u64();
        if ((flags & ATTR_UIDGID) != 0) {
            r.u32();
            r.u32();
        }
        if ((flags & ATTR_PERMISSIONS) != 0) a.directory = (r.u32() & 0170000) == 0040000;
        if ((flags & ATTR_ACMODTIME) != 0) {
            r.u32();
            a.mtime = r.u32();
        }
        return a;
    }

    byte[] open(String path) throws IOException {
        long id = nextId++;
        send(new SshBuf.Writer().u8(FXP_OPEN).u32(id).string(path).u32(1 /* SSH_FXF_READ */).u32(0).bytes());
        return response(id, FXP_HANDLE, path).string();
    }

    void close(byte[] handle) throws IOException {
        long id = nextId++;
        send(new SshBuf.Writer().u8(FXP_CLOSE).u32(id).string(handle).bytes());
        response(id, FXP_STATUS, null);
    }

    /**
     * Reads the file from {@code offset} into {@code sink}. With {@code size} >= 0 exactly the
     * bytes up to {@code size} are fetched and a shorter file is an error; with -1 it reads to
     * the end of the file.
     */
    void read(byte[] handle, long offset, long size, Sink sink) throws IOException {
        Map<Long, long[]> inFlight = new HashMap<Long, long[]>(); // id -> {offset, length}
        Map<Long, byte[]> ready = new HashMap<Long, byte[]>();    // offset -> data
        long nextOffset = offset;
        long writeOffset = offset;
        boolean eof = false;

        while (true) {
            while (inFlight.size() < MAX_IN_FLIGHT && !eof && (size < 0 || nextOffset < size)) {
                int n = size < 0 ? READ_SIZE : (int) Math.min(READ_SIZE, size - nextOffset);
                requestRead(handle, nextOffset, n, inFlight);
                nextOffset += n;
            }
            if (inFlight.isEmpty()) break;

            byte[] p = receive();
            int type = p[0] & 0xff;
            SshBuf.Reader r = new SshBuf.Reader(p, 1, p.length - 1);
            long[] req = inFlight.remove(Long.valueOf(r.u32()));
            if (req == null) throw new SshException("the server answered an SFTP request that was not made");
            if (type == FXP_DATA) {
                byte[] data = r.string();
                if (data.length == 0 || data.length > req[1]) throw new SshException("invalid SFTP read answer");
                ready.put(Long.valueOf(req[0]), data);
                if (data.length < req[1]) { // a short read: ask for the rest of this block
                    requestRead(handle, req[0] + data.length, (int) (req[1] - data.length), inFlight);
                }
                byte[] next;
                while ((next = ready.remove(Long.valueOf(writeOffset))) != null) {
                    sink.write(next, 0, next.length);
                    writeOffset += next.length;
                }
            } else if (type == FXP_STATUS) {
                long code = r.u32();
                if (code != FX_EOF) throw statusError(code, r, null);
                if (size >= 0) {
                    throw new SshException("the file on the server is shorter than its listed size (" + size + " bytes)");
                }
                eof = true;
            } else {
                throw new SshException("unexpected SFTP answer " + type);
            }
        }
        if (!ready.isEmpty() || (size >= 0 && writeOffset != size)) {
            throw new SshException("the SFTP download is incomplete");
        }
    }

    private void requestRead(byte[] handle, long offset, int len, Map<Long, long[]> inFlight) throws IOException {
        long id = nextId++;
        inFlight.put(Long.valueOf(id), new long[] { offset, len });
        send(new SshBuf.Writer().u8(FXP_READ).u32(id).string(handle).u64(offset).u32(len).bytes());
    }

    /** The answer to request {@code id}, which must be of {@code type}; a STATUS becomes an error. */
    private SshBuf.Reader response(long id, int type, String path) throws IOException {
        byte[] p = receive();
        SshBuf.Reader r = new SshBuf.Reader(p, 1, p.length - 1);
        if (r.u32() != id) throw new SshException("the server answered SFTP requests out of order");
        int got = p[0] & 0xff;
        if (got == FXP_STATUS) {
            long code = r.u32();
            if (type == FXP_STATUS && code == FX_OK) return r;
            throw statusError(code, r, path);
        }
        if (got != type) throw new SshException("unexpected SFTP answer " + got);
        return r;
    }

    private static SshException statusError(long code, SshBuf.Reader r, String path) {
        String what = path == null ? "" : ": " + path;
        if (code == FX_NO_SUCH_FILE) return new SshException("No such file on the server" + what);
        if (code == FX_PERMISSION_DENIED) return new SshException("Permission denied by the server" + what);
        String text = "";
        try {
            text = SshHostKey.printable(r.text());
        } catch (IOException ignored) {
        }
        return new SshException("SFTP error " + code + (text.length() > 0 ? " (" + text + ")" : "") + what);
    }

    private void send(byte[] body) throws IOException {
        channel.write(new SshBuf.Writer().string(body).bytes());
    }

    private byte[] receive() throws IOException {
        byte[] len = new byte[4];
        channel.readFully(len, 0, 4);
        long n = new SshBuf.Reader(len).u32();
        if (n < 1 || n > MAX_SFTP_PACKET) throw new SshException("invalid SFTP packet length " + n);
        byte[] p = new byte[(int) n];
        channel.readFully(p, 0, p.length);
        return p;
    }
}
