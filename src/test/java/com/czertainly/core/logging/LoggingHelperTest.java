package com.czertainly.core.logging;

import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.records.ActorRecord;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.slf4j.MDC;

class LoggingHelperTest {

    @AfterEach
    void clearMdc() {
        MDC.clear();
    }

    @Test
    void getActorInfoFallsBackToNoneWhenAuthMethodMissing() {
        LoggingHelper.putActorInfoWhenNull(ActorType.PROTOCOL, null, "acme");

        ActorRecord actor = LoggingHelper.getActorInfo();

        Assertions.assertEquals(ActorType.PROTOCOL, actor.type());
        Assertions.assertEquals(AuthMethod.NONE, actor.authMethod());
        Assertions.assertEquals("acme", actor.name());
        Assertions.assertNull(actor.uuid());
    }

    @Test
    void getActorInfoReturnsCoreActorWhenNoActorInMdc() {
        ActorRecord actor = LoggingHelper.getActorInfo();

        Assertions.assertEquals(ActorType.CORE, actor.type());
        Assertions.assertEquals(AuthMethod.NONE, actor.authMethod());
    }
}
