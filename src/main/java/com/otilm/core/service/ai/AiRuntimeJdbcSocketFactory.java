package com.otilm.core.service.ai;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Proxy;
import java.net.Socket;
import javax.net.SocketFactory;

/** Public pgjdbc extension; sockets belong only to the current AI connection attempt. */
public final class AiRuntimeJdbcSocketFactory extends SocketFactory {
    private final AiRuntimeJdbcDeadline.Attempt attempt;

    public AiRuntimeJdbcSocketFactory() throws IOException {
        attempt = AiRuntimeJdbcDeadline.connecting();
    }

    @Override
    public Socket createSocket() throws IOException {
        var socket = new Socket(Proxy.NO_PROXY);
        attempt.register(socket);
        return socket;
    }

    @Override
    public Socket createSocket(String host, int port) throws IOException {
        throw unsupported();
    }

    @Override
    public Socket createSocket(String host, int port, InetAddress local, int localPort) throws IOException {
        throw unsupported();
    }

    @Override
    public Socket createSocket(InetAddress host, int port) throws IOException {
        throw unsupported();
    }

    @Override
    public Socket createSocket(InetAddress host, int port, InetAddress local, int localPort) throws IOException {
        throw unsupported();
    }

    private static IOException unsupported() {
        return new IOException("AI JDBC requires an owned unconnected socket");
    }
}
