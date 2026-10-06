package org.reteget.core.ssh;

import java.io.EOFException;
import java.io.IOException;
import java.util.LinkedList;

/**
 * One "session" channel running a subsystem (RFC 4254): flow control in both directions and a
 * byte stream of the channel data. Other connection-layer traffic (global requests, channel
 * requests such as exit-status, extended data) is answered or dropped here.
 */
final class SshChannel {

    static final int MSG_GLOBAL_REQUEST = 80;
    static final int MSG_REQUEST_FAILURE = 82;
    static final int MSG_OPEN = 90;
    static final int MSG_OPEN_CONFIRMATION = 91;
    static final int MSG_OPEN_FAILURE = 92;
    static final int MSG_WINDOW_ADJUST = 93;
    static final int MSG_DATA = 94;
    static final int MSG_EXTENDED_DATA = 95;
    static final int MSG_EOF = 96;
    static final int MSG_CLOSE = 97;
    static final int MSG_REQUEST = 98;
    static final int MSG_SUCCESS = 99;
    static final int MSG_FAILURE = 100;

    private static final int LOCAL_ID = 0;
    private static final long LOCAL_WINDOW = 2L * 1024 * 1024;
    private static final int LOCAL_MAX_PACKET = 64 * 1024;

    private final SshTransport t;
    private long remoteId;
    private long remoteWindow;
    private long remoteMaxPacket;
    private long localWindow = LOCAL_WINDOW;
    private boolean eof;

    private final LinkedList<byte[]> incoming = new LinkedList<byte[]>();
    private int headOffset;

    private SshChannel(SshTransport t) {
        this.t = t;
    }

    /** Opens a session channel and starts {@code subsystem} on it. */
    static SshChannel openSubsystem(SshTransport t, String subsystem) throws IOException {
        SshChannel c = new SshChannel(t);
        t.send(new SshBuf.Writer().u8(MSG_OPEN).string("session").u32(LOCAL_ID).u32(LOCAL_WINDOW)
                .u32(LOCAL_MAX_PACKET).bytes());
        byte[] p = c.await(MSG_OPEN_CONFIRMATION, MSG_OPEN_FAILURE);
        SshBuf.Reader r = new SshBuf.Reader(p, 1, p.length - 1);
        if ((p[0] & 0xff) == MSG_OPEN_FAILURE) {
            r.u32();
            r.u32();
            throw new SshException("the server refused to open a session: " + SshHostKey.printable(r.text()));
        }
        r.u32(); // our id
        c.remoteId = r.u32();
        c.remoteWindow = r.u32();
        c.remoteMaxPacket = r.u32();
        if (c.remoteMaxPacket < 1024) throw new SshException("the server's packet size limit is too small");

        t.send(new SshBuf.Writer().u8(MSG_REQUEST).u32(c.remoteId).string("subsystem").bool(true)
                .string(subsystem).bytes());
        p = c.await(MSG_SUCCESS, MSG_FAILURE);
        if ((p[0] & 0xff) == MSG_FAILURE) {
            throw new SshException("the server has no " + subsystem + " subsystem (SFTP is not enabled there)");
        }
        return c;
    }

    /** Waits for one of two channel messages, handling everything else meanwhile. */
    private byte[] await(int a, int b) throws IOException {
        while (true) {
            byte[] p = t.receive();
            int type = p[0] & 0xff;
            if (type == a || type == b) return p;
            dispatch(p);
        }
    }

    /** Handles one incoming message; channel data lands in the incoming queue. */
    private void dispatch(byte[] p) throws IOException {
        int type = p[0] & 0xff;
        SshBuf.Reader r = new SshBuf.Reader(p, 1, p.length - 1);
        switch (type) {
            case MSG_GLOBAL_REQUEST: {
                r.string();
                if (r.bool()) t.send(new byte[] { MSG_REQUEST_FAILURE });
                break;
            }
            case MSG_WINDOW_ADJUST:
                r.u32();
                remoteWindow += r.u32();
                break;
            case MSG_DATA:
            case MSG_EXTENDED_DATA: {
                r.u32();
                if (type == MSG_EXTENDED_DATA) r.u32();
                byte[] data = r.string();
                if (data.length > localWindow) throw new SshException("the server sent more than the window allows");
                localWindow -= data.length;
                if (type == MSG_DATA && data.length > 0) incoming.addLast(data);
                if (localWindow < LOCAL_WINDOW / 2) {
                    t.send(new SshBuf.Writer().u8(MSG_WINDOW_ADJUST).u32(remoteId).u32(LOCAL_WINDOW - localWindow).bytes());
                    localWindow = LOCAL_WINDOW;
                }
                break;
            }
            case MSG_EOF:
            case MSG_CLOSE:
                eof = true;
                break;
            case MSG_REQUEST: {
                r.u32();
                r.string();
                if (r.bool()) t.send(new SshBuf.Writer().u8(MSG_FAILURE).u32(remoteId).bytes());
                break;
            }
            case MSG_SUCCESS:
            case MSG_FAILURE:
                break;
            default:
                throw new SshException("unexpected SSH message " + type);
        }
    }

    /** Sends channel data, split to the server's packet size and waiting for window when it runs out. */
    void write(byte[] data) throws IOException {
        int off = 0;
        while (off < data.length) {
            while (remoteWindow <= 0) {
                if (eof) throw new EOFException("the server closed the SFTP channel");
                dispatch(t.receive());
            }
            int n = (int) Math.min(Math.min(data.length - off, remoteWindow), remoteMaxPacket);
            t.send(new SshBuf.Writer().u8(MSG_DATA).u32(remoteId).string(data, off, n).bytes());
            remoteWindow -= n;
            off += n;
        }
    }

    /** Fills {@code b[off..off+len)} with channel data, reading from the network as needed. */
    void readFully(byte[] b, int off, int len) throws IOException {
        while (len > 0) {
            while (incoming.isEmpty()) {
                if (eof) throw new EOFException("the server closed the SFTP channel");
                dispatch(t.receive());
            }
            byte[] head = incoming.getFirst();
            int n = Math.min(len, head.length - headOffset);
            System.arraycopy(head, headOffset, b, off, n);
            headOffset += n;
            off += n;
            len -= n;
            if (headOffset == head.length) {
                incoming.removeFirst();
                headOffset = 0;
            }
        }
    }
}
