package com.otilm.core.service.ai;

import java.io.IOException;
import java.net.Socket;
import java.sql.Connection;
import java.sql.SQLException;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class AiRuntimeJdbcCleanupFailureTest {
    @Mock
    private Connection delegateConnection;

    @Test
    void failsConnectionCleanup_whenSocketCloseFails() throws Exception {
        // given
        var owner = ownerWithFailingSocketClose();

        // when
        ThrowingCallable closeConnections = owner::closeConnections;

        // then
        assertThatThrownBy(closeConnections).isInstanceOf(IllegalStateException.class);
    }

    @Test
    void failsOwnerClose_whenSocketCloseFails() throws Exception {
        // given
        var owner = ownerWithFailingSocketClose();

        // when
        ThrowingCallable closeOwner = owner::close;

        // then
        assertThatThrownBy(closeOwner).isInstanceOf(IllegalStateException.class);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private AiRuntimeJdbcDeadline ownerWithFailingSocketClose() throws Exception {
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
                throw new SQLException(failure);
            }
            return delegateConnection;
        });
        connection.close();
        return owner;
    }
}
