package com.otilm.core.service.ai;

import java.io.IOException;
import java.net.Socket;
import java.sql.Connection;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class AiRuntimeJdbcCleanupFailureTest {
    @Test
    void socketCloseFailureNeverQualifiesOwnedCleanup() throws Exception {
        var owner = new AiRuntimeJdbcDeadline();
        Connection connection = owner.connect(() -> {
            try {
                AiRuntimeJdbcDeadline.connecting().register(new Socket() {
                    @Override
                    public void close() throws IOException {
                        throw new IOException("Synthetic close failure");
                    }
                });
            } catch (IOException failure) {
                throw new java.sql.SQLException(failure);
            }
            return mock(Connection.class);
        });
        connection.close();
        assertThatThrownBy(owner::closeConnections).isInstanceOf(IllegalStateException.class);
        assertThatThrownBy(owner::close).isInstanceOf(IllegalStateException.class);
    }
}
