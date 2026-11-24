package com.otilm.core.integration.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.workflows.ExecutionDto;
import com.otilm.api.model.core.workflows.ExecutionItemRequestDto;
import com.otilm.api.model.core.workflows.ExecutionRequestDto;
import com.otilm.api.model.core.workflows.ExecutionType;
import com.otilm.api.model.core.workflows.UpdateExecutionRequestDto;
import com.otilm.core.enums.FilterField;
import com.otilm.core.service.ActionExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.List;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ActionServiceRenewExecutionITest extends BaseSpringBootTest {

    @Autowired
    private ActionExternalService actionService;

    @Test
    void createsARenewExecution_whenItHasNoItems() throws Exception {
        // given
        ExecutionRequestDto request = request("renew", ExecutionType.RENEW_CERTIFICATE);

        // when
        ExecutionDto created = actionService.createExecution(request);

        // then
        assertThat(created.getType()).isEqualTo(ExecutionType.RENEW_CERTIFICATE);
        assertThat(created.getItems()).isEmpty();
    }

    @Test
    void updatesARenewExecution_whenItHasNoItems() throws Exception {
        // given
        ExecutionDto created = actionService.createExecution(request("renew", ExecutionType.RENEW_CERTIFICATE));
        UpdateExecutionRequestDto update = new UpdateExecutionRequestDto();
        update.setDescription("renews due certificates");

        // when
        ExecutionDto updated = actionService.updateExecution(created.getUuid(), update);

        // then
        assertThat(updated.getDescription()).isEqualTo("renews due certificates");
        assertThat(updated.getItems()).isEmpty();
    }

    @Test
    void refusesARenewExecution_whenItHasItems() {
        // given
        ExecutionRequestDto request = request("renew", ExecutionType.RENEW_CERTIFICATE);
        request.setItems(List.of(setFieldItem()));

        // when
        ThrowingCallable create = () -> actionService.createExecution(request);

        // then
        assertThatThrownBy(create).isInstanceOf(ValidationException.class).hasMessageContaining("takes no execution");
    }

    @Test
    void refusesASetFieldExecution_whenItHasNoItems() {
        // given
        ExecutionRequestDto request = request("set", ExecutionType.SET_FIELD);

        // when
        ThrowingCallable create = () -> actionService.createExecution(request);

        // then
        assertThatThrownBy(create).isInstanceOf(ValidationException.class).hasMessageContaining("without any");
    }

    @Test
    void refusesToUpdateASetFieldExecution_whenTheUpdateHasNoItems() throws Exception {
        // given
        ExecutionRequestDto request = request("set", ExecutionType.SET_FIELD);
        request.setItems(List.of(setFieldItem()));
        ExecutionDto created = actionService.createExecution(request);
        UpdateExecutionRequestDto emptyUpdate = new UpdateExecutionRequestDto();

        // when
        ThrowingCallable update = () -> actionService.updateExecution(created.getUuid(), emptyUpdate);

        // then
        assertThatThrownBy(update).isInstanceOf(ValidationException.class).hasMessageContaining("without any");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ExecutionRequestDto request(String name, ExecutionType type) {
        ExecutionRequestDto request = new ExecutionRequestDto();
        request.setName(name);
        request.setType(type);
        request.setResource(Resource.CERTIFICATE);
        return request;
    }

    private static ExecutionItemRequestDto setFieldItem() {
        ExecutionItemRequestDto item = new ExecutionItemRequestDto();
        item.setFieldSource(FilterFieldSource.PROPERTY);
        item.setFieldIdentifier(FilterField.RA_PROFILE_NAME.name());
        return item;
    }
}
