package com.otilm.core.logging;

import com.otilm.api.model.core.logging.enums.ActorType;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.logging.records.ActorRecord;
import com.otilm.api.model.core.logging.records.DelegateRecord;
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
    void delegateBelongsToTheRequestActorAndClearsWithIt() {
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, AuthMethod.TOKEN);
        LoggingHelper.putDelegateInfo(new DelegateRecord("mcp", "service-account"));
        Assertions.assertEquals(new DelegateRecord("mcp", "service-account"), LoggingHelper.getActorInfo().delegate());
        LoggingHelper.clearActorInfo();
        Assertions.assertNull(LoggingHelper.getActorInfo().delegate());
    }

    @Test
    void actorSnapshotRestoresDelegationAfterAnElevation() {
        LoggingHelper.putActorInfoWhenNull(ActorType.USER, AuthMethod.TOKEN);
        LoggingHelper.putDelegateInfo(new DelegateRecord("mcp", "service-account"));
        var caller = LoggingHelper.snapshotActorInfo();
        LoggingHelper.clearActorInfo();
        LoggingHelper.putActorInfoWhenNull(ActorType.CORE, null, "system");
        Assertions.assertNull(LoggingHelper.getActorInfo().delegate());
        LoggingHelper.restoreActorInfo(caller);
        Assertions.assertEquals(new DelegateRecord("mcp", "service-account"), LoggingHelper.getActorInfo().delegate());
        LoggingHelper.putDelegateInfo(null);
        Assertions.assertNull(LoggingHelper.getActorInfo().delegate());
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
