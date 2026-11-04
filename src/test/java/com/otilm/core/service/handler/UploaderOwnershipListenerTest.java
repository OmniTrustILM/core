package com.otilm.core.service.handler;

import com.otilm.core.events.transaction.UploaderOwnershipEvent;
import java.lang.reflect.Method;
import org.junit.jupiter.api.Test;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.transaction.event.TransactionPhase;
import org.springframework.transaction.event.TransactionalEventListener;

import static org.assertj.core.api.Assertions.assertThat;

class UploaderOwnershipListenerTest {

    @Test
    void runsAheadOfOtherAfterCommitListeners_whenHandlingTheEvent() throws Exception {
        // given
        Method handler = UploaderOwnershipListener.class
                .getMethod("handleUploaderOwnership", UploaderOwnershipEvent.class);

        // when
        Order order = handler.getAnnotation(Order.class);
        TransactionalEventListener listener = handler.getAnnotation(TransactionalEventListener.class);

        // then
        assertThat(listener.phase()).isEqualTo(TransactionPhase.AFTER_COMMIT);
        assertThat(order.value()).isEqualTo(Ordered.HIGHEST_PRECEDENCE);
    }
}
