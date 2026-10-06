package org.reteget.core.ssh;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * One SFTP connection for one download: TCP, SSH transport with the host key check, user
 * authentication, a session channel with the sftp subsystem.
 */
public final class SftpSession {

    /** Receives the file's bytes in order. */
    public interface Sink {
        void write(byte[] b, int off, int len) throws IOException;
    }

    /** Size and modification time of the remote file; -1 where the server did not say. */
    public static final class FileInfo {
        public final long size;
        public final long mtime;

        FileInfo(long size, long mtime) {
            this.size = size;
            this.mtime = mtime;
        }
    }

    public static final int DEFAULT_PORT = 22;

    private final Socket socket;
    private SshTransport transport;
    private SftpClient sftp;
    /** Tests lower the re-key limit through this. */
    long rekeyBytesForTest = -1;

    private SftpSession(Socket socket) {
        this.socket = socket;
    }

    /** A socket not yet connected, so that {@link #abort} can be called from another thread at any time. */
    public static SftpSession create() {
        return new SftpSession(new Socket());
    }

    /**
     * Connects, checks the host key through {@code hostKeyCheck}, and logs in.
     *
     * @param preferredHostKeyType the key type on record for this server, or null
     * @param password             null when there is none
     * @param identity             the key chosen for this address, or null
     */
    public void connect(String host, int port, int connectTimeoutMs, int readTimeoutMs, String user, String password,
                        SshIdentity identity, SshTransport.HostKeyCheck hostKeyCheck, String preferredHostKeyType)
            throws IOException {
        socket.connect(new InetSocketAddress(host, port), connectTimeoutMs);
        socket.setSoTimeout(readTimeoutMs);
        socket.setTcpNoDelay(true);
        transport = new SshTransport(new BufferedInputStream(socket.getInputStream(), 65536),
                new BufferedOutputStream(socket.getOutputStream(), 65536), hostKeyCheck, preferredHostKeyType);
        if (rekeyBytesForTest > 0) transport.rekeyBytes = rekeyBytesForTest;
        transport.connect();
        SshAuth.authenticate(transport, user, password, identity);
        sftp = new SftpClient(SshChannel.openSubsystem(transport, "sftp"));
        sftp.init();
    }

    /** Completed key exchanges on this connection (tests). */
    int kexCount() {
        return transport.kexCount;
    }

    /** One line for the user, e.g. "SSH curve25519-sha256 aes128-ctr ssh-ed25519". */
    public String summary() {
        return transport == null ? null : transport.summary();
    }

    /** The file's size and time; an SshException when it is missing or is a directory. */
    public FileInfo stat(String path) throws IOException {
        SftpClient.Attrs a = sftp.stat(path);
        if (a.directory) throw new SshException("This is a directory, not a file: " + path);
        return new FileInfo(a.size, a.mtime);
    }

    /** Downloads {@code path} from {@code offset} (to {@code size} when it is >= 0) into {@code sink}. */
    public void read(String path, long offset, long size, final Sink sink) throws IOException {
        byte[] handle = sftp.open(path);
        sftp.read(handle, offset, size, new SftpClient.Sink() {
            public void write(byte[] b, int off, int len) throws IOException {
                sink.write(b, off, len);
            }
        });
        try {
            sftp.close(handle);
        } catch (IOException ignored) {
            // every byte arrived; a failing close changes nothing
        }
    }

    /** Ends the session politely. */
    public void close() {
        if (transport != null) transport.disconnect();
        abort();
    }

    /** Closes the socket at once; safe from any thread (cancel). */
    public void abort() {
        try {
            socket.close();
        } catch (IOException ignored) {
        }
    }

    /**
     * The remote path for the path part of an sftp:// URL, as curl reads it: "/~/x" is "x"
     * relative to the home directory, anything else is absolute. Percent-decoding is the caller's.
     */
    public static String remotePath(String decodedUrlPath) {
        if (decodedUrlPath.startsWith("/~/")) return decodedUrlPath.substring(3);
        return decodedUrlPath;
    }
}
