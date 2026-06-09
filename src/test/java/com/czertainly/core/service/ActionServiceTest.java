package com.czertainly.core.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.workflows.*;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.Serializable;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ActionServiceTest extends BaseSpringBootTest {

    @Autowired
    private ActionExternalService actionService;

    @Test
    void sourceReferenceValid_noException() {
        var request = buildRequest(FilterFieldSource.CUSTOM, "sourceAttr|STRING", null);
        assertDoesNotThrow(() -> actionService.createExecution(request));
    }

    @Test
    void sourceReferenceMetaValid_noException() {
        var request = buildRequest(FilterFieldSource.META, "someMetaAttr|STRING", null);
        assertDoesNotThrow(() -> actionService.createExecution(request));
    }

    @Test
    void sourceContentTypeMismatch_throwsValidation() {
        var request = buildRequest(FilterFieldSource.META, "someAttr|INTEGER", null);
        assertThrows(ValidationException.class, () -> actionService.createExecution(request));
    }

    @Test
    void sourceAndDataBothSet_throwsValidation() {
        var request = buildRequest(FilterFieldSource.META, "someAttr|STRING", "staticValue");
        assertThrows(ValidationException.class, () -> actionService.createExecution(request));
    }

    @Test
    void sourceSetButTargetNotCustom_throwsValidation() {
        var request = buildRequestPropertyTarget();
        assertThrows(ValidationException.class, () -> actionService.createExecution(request));
    }

    @Test
    void sourceIdentifierBadFormat_throwsValidation() {
        var request = buildRequest(FilterFieldSource.META, "noSeparatorHere", null);
        assertThrows(ValidationException.class, () -> actionService.createExecution(request));
    }

    @Test
    void sourceIdentifierInvalidContentType_throwsValidation() {
        var request = buildRequest(FilterFieldSource.META, "someAttr|NOTAVALIDTYPE", null);
        assertThrows(ValidationException.class, () -> actionService.createExecution(request));
    }

    private ExecutionRequestDto buildRequest(FilterFieldSource sourceFieldSource, String sourceFieldIdentifier,
                                             Serializable data) {
        ExecutionItemRequestDto item = new ExecutionItemRequestDto();
        item.setFieldSource(FilterFieldSource.CUSTOM);
        item.setFieldIdentifier("targetCustomAttr|STRING");
        item.setSourceFieldSource(sourceFieldSource);
        item.setSourceFieldIdentifier(sourceFieldIdentifier);
        item.setData(data);

        ExecutionRequestDto request = new ExecutionRequestDto();
        request.setName("testExecution_" + System.nanoTime());
        request.setResource(Resource.CERTIFICATE);
        request.setType(ExecutionType.SET_FIELD);
        request.setItems(List.of(item));
        return request;
    }

    private ExecutionRequestDto buildRequestPropertyTarget() {
        ExecutionItemRequestDto item = new ExecutionItemRequestDto();
        item.setFieldSource(FilterFieldSource.PROPERTY);
        item.setFieldIdentifier("RA_PROFILE_NAME");
        item.setSourceFieldSource(FilterFieldSource.META);
        item.setSourceFieldIdentifier("someAttr|STRING");

        ExecutionRequestDto request = new ExecutionRequestDto();
        request.setName("testExecution_" + System.nanoTime());
        request.setResource(Resource.CERTIFICATE);
        request.setType(ExecutionType.SET_FIELD);
        request.setItems(List.of(item));
        return request;
    }
}
