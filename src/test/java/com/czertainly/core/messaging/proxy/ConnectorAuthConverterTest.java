package com.czertainly.core.messaging.proxy;

import com.czertainly.api.clients.BaseApiClient;
import com.czertainly.api.clients.mq.model.ConnectorAuth;
import com.czertainly.api.model.client.attribute.ResponseAttribute;
import com.czertainly.api.model.client.attribute.ResponseAttributeV2;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.v2.content.FileAttributeContentV2;
import com.czertainly.api.model.common.attribute.common.content.data.FileAttributeContentData;
import com.czertainly.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.czertainly.api.model.core.connector.AuthType;
import com.czertainly.api.model.core.connector.ConnectorDto;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for {@link ConnectorAuthConverter}.
 * Tests conversion of ConnectorDto authentication to proxy ConnectorAuth format.
 */
class ConnectorAuthConverterTest {

    private ConnectorAuthConverter converter;

    @BeforeEach
    void setUp() {
        converter = new ConnectorAuthConverter();
    }

    // ==================== NONE Auth Type Tests ====================

    @Test
    void convert_withAuthTypeNone_returnsNoneAuth() {
        ConnectorDto connector = createConnector(AuthType.NONE, null);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("NONE");
        assertThat(result.getAttributes()).isEmpty();
    }

    @Test
    void convert_withNullAuthType_returnsNoneAuthAsDefault() {
        ConnectorDto connector = createConnector(null, null);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("NONE");
        assertThat(result.getAttributes()).isEmpty();
    }

    @Test
    void convert_withNoneAuthAndAttributes_ignoresAttributes() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        attributes.add(createStringAttribute(BaseApiClient.ATTRIBUTE_USERNAME, "ignored-user"));
        ConnectorDto connector = createConnector(AuthType.NONE, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("NONE");
        assertThat(result.getAttributes()).isEmpty();
    }

    // ==================== BASIC Auth Type Tests ====================

    @Test
    void convert_withBasicAuth_returnsBasicAuthWithCredentials() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        attributes.add(createStringAttribute(BaseApiClient.ATTRIBUTE_USERNAME, "testuser"));
        attributes.add(createSecretAttribute(BaseApiClient.ATTRIBUTE_PASSWORD, "testpass"));
        ConnectorDto connector = createConnector(AuthType.BASIC, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("BASIC");
        assertThat(result.getAttributes().get("username")).isEqualTo("testuser");
        assertThat(result.getAttributes().get("password")).isEqualTo("testpass");
    }

    @Test
    void convert_withBasicAuth_missingUsername_returnsPartialAttributes() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        attributes.add(createSecretAttribute(BaseApiClient.ATTRIBUTE_PASSWORD, "testpass"));
        ConnectorDto connector = createConnector(AuthType.BASIC, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("BASIC");
        assertThat(result.getAttributes()).doesNotContainKey("username");
        assertThat(result.getAttributes().get("password")).isEqualTo("testpass");
    }

    @Test
    void convert_withBasicAuth_missingPassword_returnsPartialAttributes() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        attributes.add(createStringAttribute(BaseApiClient.ATTRIBUTE_USERNAME, "testuser"));
        ConnectorDto connector = createConnector(AuthType.BASIC, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("BASIC");
        assertThat(result.getAttributes().get("username")).isEqualTo("testuser");
        assertThat(result.getAttributes()).doesNotContainKey("password");
    }

    @Test
    void convert_withBasicAuth_nullAttributeContent_handlesGracefully() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        ResponseAttributeV2 usernameAttr = new ResponseAttributeV2();
        usernameAttr.setName(BaseApiClient.ATTRIBUTE_USERNAME);
        usernameAttr.setType(AttributeType.DATA);
        usernameAttr.setContent(null);
        attributes.add(usernameAttr);
        ConnectorDto connector = createConnector(AuthType.BASIC, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("BASIC");
        // Should not throw, just not include the attribute
    }

    @Test
    void convert_withBasicAuth_emptyAttributes_returnsEmptyAttributesMap() {
        ConnectorDto connector = createConnector(AuthType.BASIC, new ArrayList<>());

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("BASIC");
        assertThat(result.getAttributes()).isEmpty();
    }

    @Test
    void convert_withBasicAuth_nullAttributes_throwsNullPointerException() {
        ConnectorDto connector = createConnector(AuthType.BASIC, null);

        // AttributeDefinitionUtils.getAttributeContent throws NPE when attributes is null
        // This is expected behavior - the converter relies on valid input
        assertThatThrownBy(() -> converter.convert(connector))
                .isInstanceOf(NullPointerException.class);
    }

    // ==================== API_KEY Auth Type Tests ====================

    @Test
    void convert_withApiKeyAuth_returnsApiKeyAuthWithHeaderAndKey() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        attributes.add(createStringAttribute(BaseApiClient.ATTRIBUTE_API_KEY_HEADER, "X-API-Key"));
        attributes.add(createSecretAttribute(BaseApiClient.ATTRIBUTE_API_KEY, "secret-key-123"));
        ConnectorDto connector = createConnector(AuthType.API_KEY, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("API_KEY");
        assertThat(result.getAttributes().get("headerName")).isEqualTo("X-API-Key");
        assertThat(result.getAttributes().get("apiKey")).isEqualTo("secret-key-123");
    }

    @Test
    void convert_withApiKeyAuth_missingApiKey_returnsPartialAttributes() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        attributes.add(createStringAttribute(BaseApiClient.ATTRIBUTE_API_KEY_HEADER, "X-API-Key"));
        ConnectorDto connector = createConnector(AuthType.API_KEY, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("API_KEY");
        assertThat(result.getAttributes().get("headerName")).isEqualTo("X-API-Key");
        assertThat(result.getAttributes()).doesNotContainKey("apiKey");
    }

    @Test
    void convert_withApiKeyAuth_missingHeaderName_returnsPartialAttributes() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        attributes.add(createSecretAttribute(BaseApiClient.ATTRIBUTE_API_KEY, "secret-key-123"));
        ConnectorDto connector = createConnector(AuthType.API_KEY, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("API_KEY");
        assertThat(result.getAttributes()).doesNotContainKey("headerName");
        assertThat(result.getAttributes().get("apiKey")).isEqualTo("secret-key-123");
    }

    // ==================== CERTIFICATE Auth Type Tests ====================

    @Test
    void convert_withCertificateAuth_returnsAllCertificateAttributes() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        attributes.add(createFileAttribute(BaseApiClient.ATTRIBUTE_KEYSTORE, "keystore-base64-content"));
        attributes.add(createSecretAttribute(BaseApiClient.ATTRIBUTE_KEYSTORE_PASSWORD, "keystore-pass"));
        attributes.add(createFileAttribute(BaseApiClient.ATTRIBUTE_TRUSTSTORE, "truststore-base64-content"));
        attributes.add(createSecretAttribute(BaseApiClient.ATTRIBUTE_TRUSTSTORE_PASSWORD, "truststore-pass"));
        ConnectorDto connector = createConnector(AuthType.CERTIFICATE, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("CERTIFICATE");
        assertThat(result.getAttributes().get("keystore")).isEqualTo("keystore-base64-content");
        assertThat(result.getAttributes().get("keystorePassword")).isEqualTo("keystore-pass");
        assertThat(result.getAttributes().get("truststore")).isEqualTo("truststore-base64-content");
        assertThat(result.getAttributes().get("truststorePassword")).isEqualTo("truststore-pass");
    }

    @Test
    void convert_withCertificateAuth_missingKeystore_returnsPartialAttributes() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        attributes.add(createSecretAttribute(BaseApiClient.ATTRIBUTE_KEYSTORE_PASSWORD, "keystore-pass"));
        attributes.add(createFileAttribute(BaseApiClient.ATTRIBUTE_TRUSTSTORE, "truststore-base64-content"));
        ConnectorDto connector = createConnector(AuthType.CERTIFICATE, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("CERTIFICATE");
        assertThat(result.getAttributes()).doesNotContainKey("keystore");
        assertThat(result.getAttributes().get("keystorePassword")).isEqualTo("keystore-pass");
        assertThat(result.getAttributes().get("truststore")).isEqualTo("truststore-base64-content");
    }

    @Test
    void convert_withCertificateAuth_missingTruststore_returnsOnlyKeystoreAttributes() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        attributes.add(createFileAttribute(BaseApiClient.ATTRIBUTE_KEYSTORE, "keystore-base64-content"));
        attributes.add(createSecretAttribute(BaseApiClient.ATTRIBUTE_KEYSTORE_PASSWORD, "keystore-pass"));
        ConnectorDto connector = createConnector(AuthType.CERTIFICATE, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("CERTIFICATE");
        assertThat(result.getAttributes().get("keystore")).isEqualTo("keystore-base64-content");
        assertThat(result.getAttributes().get("keystorePassword")).isEqualTo("keystore-pass");
        assertThat(result.getAttributes()).doesNotContainKey("truststore");
        assertThat(result.getAttributes()).doesNotContainKey("truststorePassword");
    }

    @Test
    void convert_withCertificateAuth_withOnlyPasswords_returnsPasswordsOnly() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        attributes.add(createSecretAttribute(BaseApiClient.ATTRIBUTE_KEYSTORE_PASSWORD, "keystore-pass"));
        attributes.add(createSecretAttribute(BaseApiClient.ATTRIBUTE_TRUSTSTORE_PASSWORD, "truststore-pass"));
        ConnectorDto connector = createConnector(AuthType.CERTIFICATE, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("CERTIFICATE");
        assertThat(result.getAttributes().get("keystorePassword")).isEqualTo("keystore-pass");
        assertThat(result.getAttributes().get("truststorePassword")).isEqualTo("truststore-pass");
        assertThat(result.getAttributes()).doesNotContainKey("keystore");
        assertThat(result.getAttributes()).doesNotContainKey("truststore");
    }

    @Test
    void convert_withCertificateAuth_fileAttributeWithNullData_handlesGracefully() {
        List<ResponseAttribute> attributes = new ArrayList<>();
        ResponseAttributeV2 keystoreAttr = new ResponseAttributeV2();
        keystoreAttr.setName(BaseApiClient.ATTRIBUTE_KEYSTORE);
        keystoreAttr.setType(AttributeType.DATA);
        FileAttributeContentV2 fileContent = new FileAttributeContentV2();
        fileContent.setData(null);
        keystoreAttr.setContent(List.of(fileContent));
        attributes.add(keystoreAttr);
        ConnectorDto connector = createConnector(AuthType.CERTIFICATE, attributes);

        ConnectorAuth result = converter.convert(connector);

        assertThat(result.getType()).isEqualTo("CERTIFICATE");
        assertThat(result.getAttributes()).doesNotContainKey("keystore");
    }

    // ==================== JWT Auth Type Tests ====================

    @Test
    void convert_withJwtAuth_throwsUnsupportedOperationException() {
        ConnectorDto connector = createConnector(AuthType.JWT, null);

        assertThatThrownBy(() -> converter.convert(connector))
                .isInstanceOf(UnsupportedOperationException.class)
                .hasMessage("JWT authentication not yet implemented");
    }

    // ==================== Helper Methods ====================

    private ConnectorDto createConnector(AuthType authType, List<ResponseAttribute> authAttributes) {
        ConnectorDto connector = new ConnectorDto();
        connector.setAuthType(authType);
        connector.setAuthAttributes(authAttributes);
        connector.setUrl("http://connector.example.com");
        return connector;
    }

    private ResponseAttribute createStringAttribute(String name, String value) {
        ResponseAttributeV2 attr = new ResponseAttributeV2();
        attr.setName(name);
        attr.setType(AttributeType.DATA);
        StringAttributeContentV2 content = new StringAttributeContentV2();
        content.setData(value);
        attr.setContent(List.of(content));
        return attr;
    }

    private ResponseAttribute createSecretAttribute(String name, String secret) {
        ResponseAttributeV2 attr = new ResponseAttributeV2();
        attr.setName(name);
        attr.setType(AttributeType.DATA);
        SecretAttributeContentV2 content = new SecretAttributeContentV2();
        content.setData(new SecretAttributeContentData(secret));
        attr.setContent(List.of(content));
        return attr;
    }

    private ResponseAttribute createFileAttribute(String name, String base64Content) {
        ResponseAttributeV2 attr = new ResponseAttributeV2();
        attr.setName(name);
        attr.setType(AttributeType.DATA);
        FileAttributeContentV2 content = new FileAttributeContentV2();
        FileAttributeContentData data = new FileAttributeContentData();
        data.setContent(base64Content);
        content.setData(data);
        attr.setContent(List.of(content));
        return attr;
    }
}
