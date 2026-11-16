package com.otilm.core.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeoutException;
import org.springframework.web.reactive.function.client.WebClientRequestException;

/**
 * Which causes of a connector communication failure come from the transport: the connection, a timeout, an interruption
 * or an exhausted connection pool, which a retry may get past. The same failure also reports a response that could not
 * be read, which a retry would only repeat.
 */
public final class ConnectorTransportFailures {

    private static final List<Class<? extends Throwable>> TRANSPORT_FAILURES = List
            .of(IOException.class, WebClientRequestException.class, TimeoutException.class,
                    io.netty.handler.timeout.TimeoutException.class, InterruptedException.class);

    /** Matched by name, as the connector client matches it, because its type is shaded inside reactor-netty. */
    private static final String POOL_ACQUIRE_EXHAUSTED = "PoolAcquirePendingLimitException";

    private ConnectorTransportFailures() {
    }

    /**
     * Whether the cause is a transport failure. An answer Core could not parse is not one, though Jackson reports it as
     * an {@link IOException}.
     */
    @SuppressWarnings("java:S1872")
    public static boolean isTransportFailure(Throwable cause) {
        return cause != null && !(cause instanceof JsonProcessingException)
                && (TRANSPORT_FAILURES.stream().anyMatch(type -> type.isInstance(cause))
                        || POOL_ACQUIRE_EXHAUSTED.equals(cause.getClass().getSimpleName()));
    }
}
