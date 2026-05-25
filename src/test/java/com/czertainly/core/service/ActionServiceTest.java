package com.czertainly.core.service;

import com.czertainly.api.exception.AlreadyExistException;
import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.custom.CustomAttributeCreateRequestDto;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.api.model.core.workflows.*;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.Serializable;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ActionServiceTest extends BaseSpringBootTest {

    @Autowired
    private ActionService actionService;

    @Autowired
    private AttributeService attributeService;

    private static final String TARGET_ATTR = "targetCustomAttr";
    private static final String SOURCE_ATTR = "sourceCustomAttr";

    @BeforeEach
    void setUp() throws AlreadyExistException, AttributeException {
        CustomAttributeCreateRequestDto target = new CustomAttributeCreateRequestDto();
        target.setName(TARGET_ATTR);
        target.setLabel("Target");
        target.setContentType(AttributeContentType.STRING);
        target.setResources(List.of(Resource.CERTIFICATE));
        attributeService.createCustomAttribute(target);

        CustomAttributeCreateRequestDto source = new CustomAttributeCreateRequestDto();
        source.setName(SOURCE_ATTR);
        source.setLabel("Source");
        source.setContentType(AttributeContentType.STRING);
        source.setResources(List.of(Resource.CERTIFICATE));
        attributeService.createCustomAttribute(source);
    }

    @Test
    void sourceReferenceValid_noException() {
        assertDoesNotThrow(() -> actionService.createExecution(buildRequest(
                FilterFieldSource.CUSTOM, SOURCE_ATTR + "|STRING",
                null)));
    }

    @Test
    void sourceReferenceMetaValid_noException() {
        assertDoesNotThrow(() -> actionService.createExecution(buildRequest(
                FilterFieldSource.META, "someMetaAttr|STRING",
                null)));
    }

    @Test
    void sourceContentTypeMismatch_throwsValidation() {
        // INTEGER source vs STRING target
        assertThrows(ValidationException.class, () -> actionService.createExecution(buildRequest(
                FilterFieldSource.META, "someAttr|INTEGER",
                null)));
    }

    @Test
    void sourceAndDataBothSet_throwsValidation() {
        assertThrows(ValidationException.class, () -> actionService.createExecution(buildRequest(
                FilterFieldSource.META, "someAttr|STRING",
                "staticValue")));
    }

    @Test
    void sourceSetButTargetNotCustom_throwsValidation() {
        assertThrows(ValidationException.class, () -> actionService.createExecution(buildRequestPropertyTarget(
        )));
    }

    @Test
    void sourceIdentifierBadFormat_throwsValidation() {
        assertThrows(ValidationException.class, () -> actionService.createExecution(buildRequest(
                FilterFieldSource.META, "noSeparatorHere",
                null)));
    }

    @Test
    void sourceIdentifierInvalidContentType_throwsValidation() {
        assertThrows(ValidationException.class, () -> actionService.createExecution(buildRequest(
                FilterFieldSource.META, "someAttr|NOTAVALIDTYPE",
                null)));
    }

    // Helper: builds an ExecutionRequestDto with a single SET_FIELD item using source reference
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

    // Helper: builds request with PROPERTY as target (to test that source reference requires CUSTOM target)
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