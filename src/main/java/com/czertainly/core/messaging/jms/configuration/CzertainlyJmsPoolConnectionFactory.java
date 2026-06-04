package com.czertainly.core.messaging.jms.configuration;

import jakarta.jms.Connection;
import org.apache.qpid.jms.JmsConnection;
import org.messaginghub.pooled.jms.JmsPoolConnectionFactory;
import org.messaginghub.pooled.jms.pool.PooledConnection;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Custom pool factory that works around a bug in pooled-jms where {@code validateObject()}
 * fails to evict dead Qpid JMS connections.
 *
 * <p>When Azure ServiceBus sends {@code amqp:connection:forced}, Qpid sets
 * {@code failureCause} atomically on the {@link JmsConnection}. However, pooled-jms's
 * {@code validateObject()} only catches {@code IllegalStateException} to detect dead
 * connections. Qpid throws {@code JmsConnectionFailedException} (extends {@code JMSException}),
 * which falls into a generic {@code catch (Exception)} block that assumes the connection
 * is still valid.</p>
 *
 * <p>This subclass overrides {@code isClosed()} on the {@link PooledConnection} to also
 * check {@link JmsConnection#isFailed()} and {@link JmsConnection#isClosed()}, making
 * dead connections visible to the pool's own validation and borrow logic without any
 * external workarounds.</p>
 */
public class CzertainlyJmsPoolConnectionFactory extends JmsPoolConnectionFactory {

    private static final Logger logger = LoggerFactory.getLogger(CzertainlyJmsPoolConnectionFactory.class);

    @Override
    protected PooledConnection createPooledConnection(Connection connection) {
        logger.info("Creating pooled connection wrapping: {} (type: {})", connection, connection.getClass().getName());
        return new PooledConnection(connection) {
            @Override
            public boolean isClosed() {
                boolean superClosed = super.isClosed();
                if (superClosed) {
                    logger.debug("PooledConnection.isClosed(): super.isClosed()=true (delegate is null)");
                    return true;
                }
                try {
                    Connection underlying = getConnection();
                    if (underlying instanceof JmsConnection jmsConnection) {
                        boolean failed = jmsConnection.isFailed();
                        boolean closed = jmsConnection.isClosed();
                        if (failed || closed) {
                            logger.warn("Qpid JmsConnection is {} — reporting as closed to trigger pool eviction (failed={}, closed={})",
                                    failed ? "failed" : "closed", failed, closed);
                            return true;
                        }
                    } else {
                        logger.warn("Underlying connection is not JmsConnection: {} (type: {})",
                                underlying, underlying != null ? underlying.getClass().getName() : "null");
                    }
                } catch (Exception e) {
                    logger.debug("Unexpected exception inspecting underlying JmsConnection state", e);
                }
                return false;
            }
        };
    }
}
