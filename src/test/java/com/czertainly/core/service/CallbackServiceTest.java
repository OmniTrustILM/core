package com.czertainly.core.service;

import com.czertainly.api.exception.AttributeException;
import com.czertainly.api.exception.ConnectorException;
import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallback;
import com.czertainly.api.model.common.attribute.common.callback.AttributeCallbackMapping;
import com.czertainly.api.model.common.attribute.common.callback.AttributeValueTarget;
import com.czertainly.api.model.common.attribute.common.callback.RequestAttributeCallback;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.czertainly.api.model.common.attribute.v2.DataAttributeV2;
import com.czertainly.api.model.common.attribute.v2.GroupAttributeV2;
import com.czertainly.api.model.common.attribute.v3.DataAttributeV3;
import com.czertainly.api.model.common.attribute.v3.GroupAttributeV3;
import com.czertainly.api.model.core.auth.AttributeResource;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.FunctionGroupCode;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateContent;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.repository.CertificateContentRepository;
import com.czertainly.core.dao.repository.CertificateRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.BaseSpringBootTest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.Serializable;
import java.util.*;

class CallbackServiceTest extends BaseSpringBootTest {

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private CallbackExternalService callbackService;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private AttributeEngine attributeEngine;

    private WireMockServer mockServer;
    private Connector connector;


    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/callback")).willReturn(WireMock.okJson("{\"property\": \"value\"}")));

        connector = new Connector();
        connector.setUrl(mockServer.baseUrl());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.save(connector);
    }

    @AfterEach
    void stop() {
        mockServer.stop();
    }


    @Test
    void testCallback() throws ConnectorException, NotFoundException, AttributeException {
        GroupAttributeV2 groupAttributeV2 = new GroupAttributeV2();
        groupAttributeV2.setName("name");
        AttributeCallback callback = new AttributeCallback();
        callback.setCallbackContext("/callback");
        callback.setCallbackMethod("GET");
        groupAttributeV2.setAttributeCallback(callback);

        GroupAttributeV3 groupAttributeV3 = new GroupAttributeV3();
        groupAttributeV3.setName("name");
        groupAttributeV3.setAttributeCallback(callback);
        DataAttributeV2 extraAttribute = new DataAttributeV2();
        extraAttribute.setName("extra");
        extraAttribute.setAttributeCallback(callback);
        extraAttribute.setProperties(new DataAttributeProperties());
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/[^/]+/[^/]+/attributes")).willReturn(WireMock.okJson(AttributeDefinitionUtils.serialize(List.of(groupAttributeV2, extraAttribute, groupAttributeV3)))));

        RequestAttributeCallback requestAttributeCallback = new RequestAttributeCallback();
        requestAttributeCallback.setName(groupAttributeV2.getName());
        Object callbackObject = callbackService.callback(connector.getUuid().toString(), FunctionGroupCode.AUTHORITY_PROVIDER, "kind", requestAttributeCallback);
        Assertions.assertEquals("value", ((LinkedHashMap<String, String>) callbackObject).get("property"));

        requestAttributeCallback.setName(extraAttribute.getName());
        callbackObject = callbackService.callback(connector.getUuid().toString(), FunctionGroupCode.AUTHORITY_PROVIDER, "kind", requestAttributeCallback);
        Assertions.assertEquals("value", ((LinkedHashMap<String, String>) callbackObject).get("property"));

        requestAttributeCallback.setName(groupAttributeV3.getName());
        callbackObject = callbackService.callback(connector.getUuid().toString(), FunctionGroupCode.AUTHORITY_PROVIDER, "kind", requestAttributeCallback);
        Assertions.assertEquals("value", ((LinkedHashMap<String, String>) callbackObject).get("property"));

    }

    @Test
    void testCallbackV2() throws AttributeException, NotFoundException, ConnectorException, JsonProcessingException {
        DataAttributeV2 dataAttributeV2 = new DataAttributeV2();
        dataAttributeV2.setName("name");
        dataAttributeV2.setUuid(UUID.randomUUID().toString());
        dataAttributeV2.setContentType(AttributeContentType.STRING);
        AttributeCallback callback = new AttributeCallback();
        callback.setCallbackContext("/callback");
        callback.setCallbackMethod("GET");
        dataAttributeV2.setAttributeCallback(callback);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("label");
        dataAttributeV2.setProperties(properties);
        GroupAttributeV3 groupAttributeV3 = new GroupAttributeV3();
        groupAttributeV3.setName("groupName");
        groupAttributeV3.setUuid(UUID.randomUUID().toString());
        groupAttributeV3.setAttributeCallback(callback);
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(dataAttributeV2, groupAttributeV3));
        RequestAttributeCallback requestAttributeCallback = new RequestAttributeCallback();
        requestAttributeCallback.setName("randomName");
        Assertions.assertThrows(NotFoundException.class, () -> callbackService.callback(connector.getUuid(), requestAttributeCallback));

        requestAttributeCallback.setName(dataAttributeV2.getName());
        Object callbackObject = callbackService.callback(connector.getUuid(), requestAttributeCallback);
        Assertions.assertEquals("value", ((LinkedHashMap<String, String>) callbackObject).get("property"));

        ObjectMapper objectMapper = new ObjectMapper();
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/callback")).willReturn(WireMock.okJson(objectMapper.writeValueAsString(List.of(dataAttributeV2)))));
        requestAttributeCallback.setName(groupAttributeV3.getName());
        callbackObject = callbackService.callback(connector.getUuid(), requestAttributeCallback);
        List<DataAttributeV2> callbackList = objectMapper.convertValue(callbackObject, objectMapper.getTypeFactory().constructCollectionType(List.class, DataAttributeV2.class));
        Assertions.assertEquals(1, callbackList.size());
        Assertions.assertEquals(dataAttributeV2.getName(), callbackList.getFirst().getName());
    }

    @Test
    void testCallbackWithLoadResourceToBody() throws ConnectorException, NotFoundException, AttributeException {
        Certificate certificate = new Certificate();
        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("content");
        certificateContentRepository.save(certificateContent);
        certificate.setCertificateContent(certificateContent);
        certificateRepository.save(certificate);

        DataAttributeV3 dataAttributeToLoadFrom = new DataAttributeV3();
        dataAttributeToLoadFrom.setName("toLoad");
        dataAttributeToLoadFrom.setUuid(UUID.randomUUID().toString());
        dataAttributeToLoadFrom.setContentType(AttributeContentType.RESOURCE);
        DataAttributeProperties properties = new DataAttributeProperties();
        properties.setLabel("label");
        properties.setResource(AttributeResource.CERTIFICATE);
        dataAttributeToLoadFrom.setAttributeCallback(new AttributeCallback());
        dataAttributeToLoadFrom.setProperties(properties);

        DataAttributeV3 dataAttributeWithCallback = new DataAttributeV3();
        dataAttributeWithCallback.setName("withCallback");
        dataAttributeWithCallback.setUuid(UUID.randomUUID().toString());
        dataAttributeWithCallback.setContentType(AttributeContentType.STRING);
        AttributeCallback callback = new AttributeCallback();
        callback.setCallbackMethod("POST");
        callback.setCallbackContext("/callback");
        AttributeCallbackMapping callbackMapping = new AttributeCallbackMapping(dataAttributeToLoadFrom.getName(), "to", AttributeValueTarget.BODY);
        callbackMapping.setAttributeContentType(AttributeContentType.RESOURCE);
        callback.setMappings(Set.of(callbackMapping));
        dataAttributeWithCallback.setAttributeCallback(callback);
        DataAttributeProperties properties2 = new DataAttributeProperties();
        properties2.setLabel("label2");
        dataAttributeWithCallback.setProperties(properties2);

        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/v1/[^/]+/[^/]+/attributes")).willReturn(WireMock.okJson(AttributeDefinitionUtils.serialize(List.of(dataAttributeWithCallback, dataAttributeToLoadFrom)))));

        RequestAttributeCallback requestAttributeCallback = new RequestAttributeCallback();
        requestAttributeCallback.setName(dataAttributeWithCallback.getName());
        requestAttributeCallback.setUuid(connector.getUuid().toString());
        Map<String, Serializable> bodyMap = new HashMap<>();
        bodyMap.put("to", certificate.getUuid().toString());
        requestAttributeCallback.setBody(bodyMap);


        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/callback")).withRequestBody(WireMock.containing(certificateContent.getContent())).willReturn(WireMock.okJson("{\"property\": \"value2\"}")));

        Object callbackObject = callbackService.callback(connector.getUuid().toString(), FunctionGroupCode.AUTHORITY_PROVIDER, "kind", requestAttributeCallback);
        Assertions.assertEquals("value2", ((LinkedHashMap<String, String>) callbackObject).get("property"));

        bodyMap.put("to", certificate.getUuid().toString());
        attributeEngine.updateDataAttributeDefinitions(connector.getUuid(), null, List.of(dataAttributeWithCallback, dataAttributeToLoadFrom));
        callbackObject = callbackService.callback(connector.getUuid(), requestAttributeCallback);
        Assertions.assertEquals("value2", ((LinkedHashMap<String, String>) callbackObject).get("property"));

    }
}
