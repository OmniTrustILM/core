package com.czertainly.core.service;

import com.czertainly.api.clients.BaseApiClient;
import com.czertainly.api.exception.ValidationException;
import com.czertainly.api.model.client.attribute.*;
import com.czertainly.api.model.common.attribute.common.DataAttribute;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.content.data.FileAttributeContentData;
import com.czertainly.api.model.common.attribute.v2.content.BaseAttributeContentV2;
import com.czertainly.api.model.common.attribute.v2.content.FileAttributeContentV2;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.core.connector.AuthType;
import com.czertainly.core.util.BaseSpringBootTest;
import com.czertainly.core.service.ConnectorAuthExternalService;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.io.InputStream;
import java.util.*;

import static com.czertainly.api.clients.BaseApiClient.ATTRIBUTE_KEYSTORE;
import static com.czertainly.api.clients.BaseApiClient.ATTRIBUTE_KEYSTORE_PASSWORD;
import static com.czertainly.api.clients.BaseApiClient.ATTRIBUTE_KEYSTORE_TYPE;
import static com.czertainly.api.clients.BaseApiClient.ATTRIBUTE_PASSWORD;
import static com.czertainly.api.clients.BaseApiClient.ATTRIBUTE_USERNAME;

@SpringBootTest
@Transactional
@Rollback
class ConnectorAuthServiceTest extends BaseSpringBootTest {

    @Autowired
    private ConnectorAuthExternalService connectorAuthService;

    @Test
    void testGetAuthenticationTypes() {
        Set<AuthType> types = connectorAuthService.getAuthenticationTypes();
        Assertions.assertNotNull(types);
        Assertions.assertFalse(types.isEmpty());
    }

    @Test
    void testGetAuthAttributes() {
        Assertions.assertDoesNotThrow(() -> connectorAuthService.getAuthAttributes(AuthType.BASIC));
        Assertions.assertDoesNotThrow(() -> connectorAuthService.getAuthAttributes(AuthType.CERTIFICATE));
        Assertions.assertDoesNotThrow(() -> connectorAuthService.getAuthAttributes(AuthType.API_KEY));
        Assertions.assertThrows(ValidationException.class, () -> connectorAuthService.getAuthAttributes(AuthType.JWT));
    }


    @Test
    void testGetBasicAuthAttributes() {
        List<DataAttribute> attrs = connectorAuthService.getBasicAuthAttributes();
        Assertions.assertNotNull(attrs);
        Assertions.assertFalse(attrs.isEmpty());
    }

    @Test
    void testValidateBasicAuthAttributes() {
        List<RequestAttribute> attrs = new ArrayList<>();
        attrs.addAll(createAttributes(ATTRIBUTE_USERNAME, List.of(new StringAttributeContentV2("username"))));
        attrs.addAll(createAttributes(ATTRIBUTE_PASSWORD, List.of(new StringAttributeContentV2("password"))));

        boolean result = connectorAuthService.validateBasicAuthAttributes(attrs);
        Assertions.assertTrue(result);

        result = connectorAuthService.validateAuthAttributes(AuthType.BASIC, attrs);
        Assertions.assertTrue(result);
    }

    @Test
    void testGetCertificateAttributes() {
        List<DataAttribute> attrs = connectorAuthService.getCertificateAttributes();
        Assertions.assertNotNull(attrs);
        Assertions.assertFalse(attrs.isEmpty());
    }

    @Test
    void testValidateCertificateAttributes() throws IOException {
        InputStream keyStoreStream = CertificateServiceTest.class.getClassLoader().getResourceAsStream("client1.p12");
        byte[] keyStoreData = keyStoreStream.readAllBytes();

        List<RequestAttribute> attrs = new ArrayList<>(createAttributes(ATTRIBUTE_KEYSTORE_TYPE, List.of(new StringAttributeContentV2("PKCS12"))));
        FileAttributeContentData data = new FileAttributeContentData();
        data.setContent(Base64.getEncoder().encodeToString(keyStoreData));
        attrs.addAll(createAttributes(ATTRIBUTE_KEYSTORE, List.of(new FileAttributeContentV2("", data))));
        attrs.addAll(createAttributes(ATTRIBUTE_KEYSTORE_PASSWORD, List.of(new StringAttributeContentV2("123456"))));

        boolean result = connectorAuthService.validateCertificateAttributes(attrs);
        Assertions.assertTrue(result);

        result = connectorAuthService.validateAuthAttributes(AuthType.CERTIFICATE, attrs);
        Assertions.assertTrue(result);
    }

    @Test
    void testGetApiKeyAuthAttributes() {
        List<DataAttribute> attrs = connectorAuthService.getApiKeyAuthAttributes();
        Assertions.assertNotNull(attrs);
        Assertions.assertFalse(attrs.isEmpty());
    }

    @Test
    void testValidateApiKeyAuthAttributes() {
        List<RequestAttribute> attrs = new ArrayList<>();
        BaseAttributeContentV2 base = new StringAttributeContentV2();
        base.setData("apiKetTesting");

        BaseAttributeContentV2 header = new StringAttributeContentV2();
        header.setData("X-API-KEY");

        attrs.addAll(createAttributes(BaseApiClient.ATTRIBUTE_API_KEY, List.of(base)));
        attrs.addAll(createAttributes(BaseApiClient.ATTRIBUTE_API_KEY_HEADER, List.of(header)));

        boolean result = connectorAuthService.validateApiKeyAuthAttributes(attrs);
        Assertions.assertTrue(result);

        result = connectorAuthService.validateAuthAttributes(AuthType.API_KEY, attrs);
        Assertions.assertTrue(result);
    }

    @Test
    void testGetJWTAuthAttributes() {
        Assertions.assertThrows(ValidationException.class, () -> connectorAuthService.getJWTAuthAttributes());
    }

    @Test
    void testValidateJWTAuthAttributes() {
        List<RequestAttribute> attributes = List.of();
        Assertions.assertThrows(ValidationException.class, () -> connectorAuthService.validateBasicAuthAttributes(attributes));
        Assertions.assertThrows(ValidationException.class, () -> connectorAuthService.validateAuthAttributes(AuthType.JWT, attributes));
    }

    private static List<RequestAttributeV2> createAttributes(String name, List<BaseAttributeContentV2<?>> content) {
        return createAttributes(UUID.randomUUID(), name, content);
    }

    private static List<RequestAttributeV2> createAttributes(UUID uuid, String name, List<BaseAttributeContentV2<?>> content) {
        RequestAttributeV2 attribute = new RequestAttributeV2(uuid, name, AttributeContentType.STRING, content);
        return List.of(attribute);
    }
}
