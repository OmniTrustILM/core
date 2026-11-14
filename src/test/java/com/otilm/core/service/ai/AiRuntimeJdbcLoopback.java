package com.otilm.core.service.ai;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

/** Finite synthetic PostgreSQL peer for the pinned real driver, with no database or credentials. */
final class AiRuntimeJdbcLoopback implements AutoCloseable {
    enum Mode {
        NORMAL,
        STARTUP_DRIP,
        VALIDATION_DRIP,
        QUERY_DRIP
    }

    private final ServerSocket listener = new ServerSocket(0, 4, InetAddress.getByName("127.0.0.1"));
    private final java.util.concurrent.ExecutorService workers = Executors.newFixedThreadPool(4);
    private final java.util.concurrent.ScheduledExecutorService clock = Executors.newSingleThreadScheduledExecutor();
    private final Set<Socket> peers = ConcurrentHashMap.newKeySet();
    private final AtomicReference<Throwable> failure = new AtomicReference<>();
    private final java.util.concurrent.atomic.AtomicInteger backendIds = new java.util.concurrent.atomic.AtomicInteger(
            100);
    private final java.util.Map<Integer, PendingQuery> pending = new ConcurrentHashMap<>();
    final java.util.concurrent.atomic.AtomicInteger cancellations = new java.util.concurrent.atomic.AtomicInteger();
    private volatile boolean closed;
    volatile Mode mode = Mode.NORMAL;
    volatile boolean holdCancellation;

    AiRuntimeJdbcLoopback() throws IOException {
        workers.submit(() -> {
            while (!closed) {
                try {
                    Socket socket = listener.accept();
                    peers.add(socket);
                    workers.submit(() -> serve(socket));
                } catch (IOException problem) {
                    if (!closed) {
                        failure.compareAndSet(null, problem);
                    }
                }
            }
        });
    }

    String url() {
        return "jdbc:postgresql://127.0.0.1:" + listener.getLocalPort()
                + "/synthetic?gssEncMode=disable&sslmode=disable&assumeMinServerVersion=17&preferQueryMode=simple";
    }

    private void serve(Socket socket) {
        int backend = -1;
        try (socket) {
            socket.setSoTimeout(3000);
            var input = new DataInputStream(socket.getInputStream());
            var output = new DataOutputStream(socket.getOutputStream());
            int startup = input.readInt();
            if (startup < 8 || startup > 8192) {
                throw new IOException("Startup length");
            }
            byte[] startupBody = input.readNBytes(startup - 4);
            if (startup == 16 && java.nio.ByteBuffer.wrap(startupBody).getInt() == 80877102) {
                int target = java.nio.ByteBuffer.wrap(startupBody).getInt(4);
                var query = pending.get(target);
                if (query != null) {
                    cancellations.incrementAndGet();
                    if (holdCancellation) {
                        while (input.read() != -1) {
                            // The captured borrow deadline must close this exact cancellation socket.
                        }
                        return;
                    }
                    pending.remove(target, query);
                    query.timer.cancel(false);
                    message(query.output, 'E',
                            "SERROR\0C57014\0Msynthetic query cancellation\0\0".getBytes(StandardCharsets.UTF_8));
                    ready(query.output);
                    query.output.flush();
                }
                return;
            }
            message(output, 'R', new byte[]{0, 0, 0, 0});
            parameter(output, "server_version", "17.0");
            parameter(output, "client_encoding", "UTF8");
            parameter(output, "standard_conforming_strings", "on");
            parameter(output, "integer_datetimes", "on");
            backend = backendIds.incrementAndGet();
            message(output, 'K', java.nio.ByteBuffer.allocate(8).putInt(backend).putInt(123456).array());
            if (mode == Mode.STARTUP_DRIP) {
                drip(output);
            } else {
                ready(output);
            }
            output.flush();
            while (!closed) {
                int kind = input.read();
                if (kind == -1) {
                    return;
                }
                int size = input.readInt();
                if (size < 4 || size > 8192) {
                    throw new IOException("Query length");
                }
                byte[] body = input.readNBytes(size - 4);
                if (kind == 'X') {
                    return;
                }
                if (kind != 'Q') {
                    throw new IOException("Expected simple query");
                }
                String query = new String(body, 0, body.length - 1, StandardCharsets.UTF_8);
                if (query.isEmpty()) {
                    if (mode == Mode.VALIDATION_DRIP) {
                        drip(output);
                        continue;
                    }
                    message(output, 'I', new byte[0]);
                } else if (query.toLowerCase(java.util.Locale.ROOT).contains("transaction isolation")) {
                    isolation(output);
                } else if (mode == Mode.QUERY_DRIP && query.startsWith("SELECT")) {
                    pending.put(backend, new PendingQuery(output, drip(output)));
                    continue;
                } else {
                    message(output, 'C', "SET\0".getBytes(StandardCharsets.UTF_8));
                }
                ready(output);
                output.flush();
            }
        } catch (IOException expectedOnCancellation) {
            // Exact owned peer closure is the cancellation oracle; no shared server exists.
        } finally {
            var query = pending.remove(backend);
            if (query != null) {
                query.timer.cancel(false);
            }
            peers.remove(socket);
        }
    }

    private java.util.concurrent.ScheduledFuture<?> drip(DataOutputStream output) {
        return clock.scheduleAtFixedRate(() -> {
            try {
                message(output, 'N', "SNOTICE\0C00000\0Msynthetic heartbeat\0\0".getBytes(StandardCharsets.UTF_8));
                output.flush();
            } catch (IOException expectedOnCancellation) {
                // The registered socket was closed by the connection deadline.
            }
        }, 0, 25, TimeUnit.MILLISECONDS);
    }

    private record PendingQuery(DataOutputStream output, java.util.concurrent.ScheduledFuture<?> timer) {
    }

    private static void isolation(DataOutputStream output) throws IOException {
        var bytes = new ByteArrayOutputStream();
        var row = new DataOutputStream(bytes);
        row.writeShort(1);
        row.write("transaction_isolation\0".getBytes(StandardCharsets.UTF_8));
        row.writeInt(0);
        row.writeShort(0);
        row.writeInt(25);
        row.writeShort(-1);
        row.writeInt(-1);
        row.writeShort(0);
        message(output, 'T', bytes.toByteArray());
        bytes.reset();
        row.writeShort(1);
        byte[] value = "read committed".getBytes(StandardCharsets.UTF_8);
        row.writeInt(value.length);
        row.write(value);
        message(output, 'D', bytes.toByteArray());
        message(output, 'C', "SHOW\0".getBytes(StandardCharsets.UTF_8));
    }

    private static void parameter(DataOutputStream output, String name, String value) throws IOException {
        message(output, 'S', (name + '\0' + value + '\0').getBytes(StandardCharsets.UTF_8));
    }

    private static void ready(DataOutputStream output) throws IOException {
        message(output, 'Z', new byte[]{'I'});
    }

    private static void message(DataOutputStream output, char type, byte[] payload) throws IOException {
        synchronized (output) {
            output.writeByte(type);
            output.writeInt(payload.length + 4);
            output.write(payload);
        }
    }

    @Override
    public void close() throws Exception {
        closed = true;
        listener.close();
        clock.shutdownNow();
        for (var peer : peers) {
            peer.close();
        }
        workers.shutdownNow();
        if (!clock.awaitTermination(1, TimeUnit.SECONDS) || !workers.awaitTermination(1, TimeUnit.SECONDS)) {
            throw new AssertionError("Synthetic PostgreSQL workers did not terminate");
        }
        if (failure.get() != null) {
            throw new AssertionError("Synthetic PostgreSQL fixture failed", failure.get());
        }
    }
}
