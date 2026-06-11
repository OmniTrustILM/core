package com.otilm.core.signing.record;

import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * The scheduler holds no logic of its own: each scheduled tick must delegate to {@link SigningRecordOutboxDrainer}.
 * The drain behaviour itself is covered in {@link SigningRecordOutboxDrainerUnitTest}.
 */
class SigningRecordOutboxDrainSchedulerTest {

    @Test
    void drainScheduled_delegatesToTheDrainer() {
        // given
        var drainer = mock(SigningRecordOutboxDrainer.class);
        var scheduler = new SigningRecordOutboxDrainScheduler(drainer);

        // when
        scheduler.drainScheduled();

        // then
        verify(drainer).drainOnce();
    }
}
