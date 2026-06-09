package com.czertainly.core.util;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.NameAndIdDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.CredentialAttributeContentV2;
import com.otilm.api.model.common.attribute.common.content.data.CredentialAttributeContentData;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.otilm.core.util.AttributeDefinitionUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.time.LocalDateTime;
import java.util.*;

class JsonSerializationTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        MAPPER.findAndRegisterModules();
        MAPPER.configure(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS, false);
    }

    @Test
    void testSerializeMap() {
        Map<Object, Object> data = new HashMap<>();
        LocalDateTime now = LocalDateTime.now();
        data.put("testKey", now);
        data.put("nullKey", null);

        Assertions.assertDoesNotThrow(() -> MAPPER.writeValueAsString(data));
    }

    @Test
    void testSerializeArray() throws JsonProcessingException {
        Object[][] data = new Object[][]{
                new Object[]{"testKey", "testValue"}
        };

        String json = MAPPER.writeValueAsString(data);
        Assertions.assertEquals("[[\"testKey\",\"testValue\"]]", json);
    }

    @Test
    void testSerializeKeystore() throws IOException {
        InputStream is = this.getClass().getClassLoader().getResourceAsStream("client1.p12");
        byte[] array = is.readAllBytes();
        Assertions.assertDoesNotThrow(() -> Base64.getEncoder().encodeToString(array));
    }

    @Test
    void testDeserializeRAProfileAttributes() {
        String attrData = """
                [{"name": "tokenType", "content": [{"data": "PEM"}], "type": "data"},
                {"name": "description", "content": [{"data": "DEMO RA Profile"}], "type": "data", "version": 2},
                {"name": "endEntityProfile", "content": [{"reference": "DemoTLSServerEndEntityProfile", "data": {"id": 0, "name": "DemoTLSServerEndEntityProfile"}}], "type": "data", "version": 2},
                {"name": "certificateProfile", "content": [{"reference": "DemoTLSServerEECertificateProfile", "data": {"id": 0, "name": "DemoTLSServerEECertificateProfile"}}], "type": "data", "version": 2},
                {"name": "certificationAuthority", "content": [{"reference": "DemoServerSubCA", "data": {"id": 0, "name": "DemoServerSubCA"}}], "type": "data", "version": 2},
                {"name": "sendNotifications", "content": [{"data": false}], "type": "data", "version": 2},
                {"name": "keyRecoverable", "content": [{"data": true}], "type": "data", "version": 2}]
                """;

        List<BaseAttribute> attrs = AttributeDefinitionUtils.deserialize(attrData, BaseAttribute.class);
        Assertions.assertNotNull(attrs);
        Assertions.assertEquals(7, attrs.size());

        NameAndIdDto endEntityProfile = AttributeDefinitionUtils.getNameAndIdData("endEntityProfile", AttributeDefinitionUtils.getClientAttributes(attrs));
        Assertions.assertNotNull(endEntityProfile);
        Assertions.assertEquals(0, endEntityProfile.getId());
        Assertions.assertEquals("DemoTLSServerEndEntityProfile", endEntityProfile.getName());
    }

    @Test
    void testSerializeCredential() {
        CredentialAttributeContentData credential = new CredentialAttributeContentData();
        credential.setName("test");

        List<RequestAttribute> requestAttributes = new ArrayList<>();
        requestAttributes.add(new RequestAttributeV2(UUID.randomUUID(), "credential", AttributeContentType.CREDENTIAL, List.of(new CredentialAttributeContentV2("test", credential))));
        List<BaseAttribute> attrs = AttributeDefinitionUtils.clientAttributeConverter(requestAttributes);

        String serialized = AttributeDefinitionUtils.serialize(attrs);

        List<DataAttributeV2> deserialized = AttributeDefinitionUtils.deserialize(serialized, DataAttributeV2.class);

        CredentialAttributeContentData value = AttributeDefinitionUtils.getCredentialContent("credential", AttributeDefinitionUtils.getClientAttributes(deserialized));
        Assertions.assertNotNull(value);
    }

}
