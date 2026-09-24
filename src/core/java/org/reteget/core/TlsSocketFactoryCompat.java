package org.reteget.core;

import java.io.IOException;
import java.lang.reflect.Method;
import java.net.InetAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

/**
 * Custom SSLSocketFactory that enables modern TLS protocols (TLSv1.2, TLSv1.1)
 * on legacy Android platforms (API 16-19) where they are supported by OpenSSL
 * but disabled by default. Also enables SNI (Server Name Indication) via reflection.
 */
public class TlsSocketFactoryCompat extends SSLSocketFactory {

    private static final String[] PREFERRED_PROTOCOLS = new String[] {
        "TLSv1.2", "TLSv1.1", "TLSv1"
    };

    private final SSLSocketFactory delegate;

    public TlsSocketFactoryCompat(SSLSocketFactory delegate) {
        if (delegate == null) {
            throw new IllegalArgumentException("delegate SSLSocketFactory cannot be null");
        }
        this.delegate = delegate;
    }

    @Override
    public String[] getDefaultCipherSuites() {
        return delegate.getDefaultCipherSuites();
    }

    @Override
    public String[] getSupportedCipherSuites() {
        return delegate.getSupportedCipherSuites();
    }

    @Override
    public Socket createSocket() throws IOException {
        return patchSocket(delegate.createSocket(), null);
    }

    @Override
    public Socket createSocket(Socket s, String host, int port, boolean autoClose) throws IOException {
        return patchSocket(delegate.createSocket(s, host, port, autoClose), host);
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException, UnknownHostException {
        return patchSocket(delegate.createSocket(host, port), host);
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress localHost, int localPort)
            throws IOException, UnknownHostException {
        return patchSocket(delegate.createSocket(host, port, localHost, localPort), host);
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        return patchSocket(delegate.createSocket(host, port), host != null ? host.getHostName() : null);
    }

    @Override
    public Socket createSocket(InetAddress address, int port, InetAddress localAddress, int localPort)
            throws IOException {
        return patchSocket(delegate.createSocket(address, port, localAddress, localPort),
                address != null ? address.getHostName() : null);
    }

    private Socket patchSocket(Socket socket, String host) {
        if (socket instanceof SSLSocket) {
            SSLSocket ssl = (SSLSocket) socket;
            enableTlsProtocols(ssl);
            enableSni(ssl, host);
        }
        return socket;
    }

    private void enableTlsProtocols(SSLSocket ssl) {
        try {
            String[] supported = ssl.getSupportedProtocols();
            if (supported == null || supported.length == 0) {
                return;
            }

            List<String> enabled = new ArrayList<String>();
            for (String wanted : PREFERRED_PROTOCOLS) {
                for (String s : supported) {
                    if (wanted.equalsIgnoreCase(s)) {
                        enabled.add(wanted);
                        break;
                    }
                }
            }

            if (!enabled.isEmpty()) {
                ssl.setEnabledProtocols(enabled.toArray(new String[enabled.size()]));
            }
        } catch (Exception ignored) {
        }
    }

    private void enableSni(SSLSocket ssl, String host) {
        if (host == null || host.length() == 0) {
            return;
        }
        try {
            // Android OpenSSLSocketImpl supports setHostname(String)
            Method setHostnameMethod = ssl.getClass().getMethod("setHostname", String.class);
            setHostnameMethod.invoke(ssl, host);
        } catch (Exception ignored) {
            // Reflection failed or unsupported on this platform; continue without failing
        }
    }
}
