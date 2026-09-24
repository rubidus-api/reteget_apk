package org.reteget.core;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Pure Java RFC 959 passive mode FTP client for downloading files from FTP servers.
 * Requires no external dependencies.
 */
public class FtpDownloader {

    private static final Pattern PASV_PATTERN =
            Pattern.compile("\\((\\d{1,3}),(\\d{1,3}),(\\d{1,3}),(\\d{1,3}),(\\d{1,3}),(\\d{1,3})\\)");

    public interface DownloadCallback {
        void onStart(String filename, long totalBytes);
        void onProgress(long bytesDownloaded, long totalBytes);
        boolean isCancelled();
    }

    public static File download(String ftpUrlStr, File destinationDir, DownloadCallback callback)
            throws IOException {
        URI uri;
        try {
            uri = URI.create(ftpUrlStr);
        } catch (Exception e) {
            throw new IOException("Invalid FTP URL: " + ftpUrlStr, e);
        }

        String host = uri.getHost();
        if (host == null || host.isEmpty()) {
            throw new IOException("Missing FTP host in: " + ftpUrlStr);
        }
        int port = uri.getPort() > 0 ? uri.getPort() : 21;

        String user = "anonymous";
        String pass = "anonymous@reteget.org";
        String userInfo = uri.getUserInfo();
        if (userInfo != null && !userInfo.isEmpty()) {
            int colon = userInfo.indexOf(':');
            if (colon >= 0) {
                user = userInfo.substring(0, colon);
                pass = userInfo.substring(colon + 1);
            } else {
                user = userInfo;
            }
        }

        String path = uri.getPath();
        if (path == null || path.isEmpty() || path.equals("/")) {
            throw new IOException("FTP path must point to a file: " + ftpUrlStr);
        }

        String filename = path.substring(path.lastIndexOf('/') + 1);
        if (filename.isEmpty()) {
            filename = "download.bin";
        }

        if (!destinationDir.exists()) {
            destinationDir.mkdirs();
        }
        File targetFile = new File(destinationDir, filename);

        Socket controlSocket = null;
        BufferedReader reader = null;
        PrintWriter writer = null;
        Socket dataSocket = null;
        FileOutputStream fos = null;

        try {
            controlSocket = new Socket(host, port);
            controlSocket.setSoTimeout(20000);
            reader = new BufferedReader(new InputStreamReader(controlSocket.getInputStream(), "ISO-8859-1"));
            writer = new PrintWriter(new OutputStreamWriter(controlSocket.getOutputStream(), "ISO-8859-1"), true);

            String reply = readReply(reader);
            if (!reply.startsWith("220")) {
                throw new IOException("FTP connection rejected: " + reply);
            }

            sendCommand(writer, "USER " + user);
            reply = readReply(reader);
            if (reply.startsWith("331")) {
                sendCommand(writer, "PASS " + pass);
                reply = readReply(reader);
            }
            if (!reply.startsWith("230")) {
                throw new IOException("FTP authentication failed: " + reply);
            }

            sendCommand(writer, "TYPE I");
            reply = readReply(reader);
            if (!reply.startsWith("200")) {
                throw new IOException("Failed to set binary mode: " + reply);
            }

            long totalBytes = -1;
            sendCommand(writer, "SIZE " + path);
            reply = readReply(reader);
            if (reply.startsWith("213")) {
                try {
                    totalBytes = Long.parseLong(reply.substring(4).trim());
                } catch (Exception ignored) {}
            }

            if (callback != null) {
                callback.onStart(filename, totalBytes);
            }

            sendCommand(writer, "PASV");
            reply = readReply(reader);
            if (!reply.startsWith("227")) {
                throw new IOException("PASV command rejected: " + reply);
            }

            Matcher m = PASV_PATTERN.matcher(reply);
            if (!m.find()) {
                throw new IOException("Cannot parse PASV response: " + reply);
            }
            String dataIp = m.group(1) + "." + m.group(2) + "." + m.group(3) + "." + m.group(4);
            int dataPort = (Integer.parseInt(m.group(5)) << 8) + Integer.parseInt(m.group(6));

            dataSocket = new Socket(dataIp, dataPort);
            dataSocket.setSoTimeout(30000);

            sendCommand(writer, "RETR " + path);
            reply = readReply(reader);
            if (!reply.startsWith("150") && !reply.startsWith("125")) {
                throw new IOException("RETR failed: " + reply);
            }

            InputStream dataIn = dataSocket.getInputStream();
            fos = new FileOutputStream(targetFile);
            byte[] buf = new byte[8192];
            int read;
            long downloaded = 0;

            while ((read = dataIn.read(buf)) != -1) {
                if (callback != null && callback.isCancelled()) {
                    throw new IOException("Download cancelled by user");
                }
                fos.write(buf, 0, read);
                downloaded += read;
                if (callback != null) {
                    callback.onProgress(downloaded, totalBytes);
                }
            }

            fos.flush();
            fos.close();
            fos = null;

            dataSocket.close();
            dataSocket = null;

            reply = readReply(reader);
            if (!reply.startsWith("226") && !reply.startsWith("250")) {
                System.err.println("Warning: unexpected transfer finish reply: " + reply);
            }

            sendCommand(writer, "QUIT");
            return targetFile;

        } catch (IOException e) {
            if (targetFile.exists()) {
                targetFile.delete();
            }
            throw e;
        } finally {
            if (fos != null) {
                try { fos.close(); } catch (Exception ignored) {}
            }
            if (dataSocket != null) {
                try { dataSocket.close(); } catch (Exception ignored) {}
            }
            if (controlSocket != null) {
                try { controlSocket.close(); } catch (Exception ignored) {}
            }
        }
    }

    private static void sendCommand(PrintWriter writer, String cmd) {
        writer.print(cmd + "\r\n");
        writer.flush();
    }

    private static String readReply(BufferedReader reader) throws IOException {
        String line = reader.readLine();
        if (line == null) {
            throw new IOException("Connection closed prematurely by FTP server");
        }
        if (line.length() >= 4 && line.charAt(3) == '-') {
            String code = line.substring(0, 3);
            while (true) {
                String next = reader.readLine();
                if (next == null) break;
                if (next.startsWith(code) && next.length() >= 4 && next.charAt(3) == ' ') {
                    return next;
                }
            }
        }
        return line;
    }
}
