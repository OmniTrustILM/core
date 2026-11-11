package com.otilm.core.aop;

import com.otilm.api.model.core.logging.enums.Operation;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuditOperationOverrideTest {

    @Test
    void returnsNothing_whenNothingWasSet() {
        // given
        var auditOperationOverride = new AuditOperationOverride();

        // when
        Operation operation = auditOperationOverride.consume();

        // then
        assertThat(operation).isNull();
    }

    @Test
    void returnsTheOperation_whenOneWasSet() {
        // given
        var auditOperationOverride = new AuditOperationOverride();
        auditOperationOverride.set(Operation.ISSUE);

        // when
        Operation operation = auditOperationOverride.consume();

        // then
        assertThat(operation).isEqualTo(Operation.ISSUE);
    }

    @Test
    void returnsNothing_whenReadASecondTime() {
        // given
        var auditOperationOverride = new AuditOperationOverride();
        auditOperationOverride.set(Operation.ISSUE);
        auditOperationOverride.consume();

        // when
        Operation secondRead = auditOperationOverride.consume();

        // then
        assertThat(secondRead).isNull();
    }
}
