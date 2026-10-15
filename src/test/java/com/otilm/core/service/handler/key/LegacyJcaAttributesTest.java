package com.otilm.core.service.handler.key;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import java.util.List;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.junit.jupiter.api.Assertions.assertEquals;

class LegacyJcaAttributesTest {
    @ParameterizedTest
    @CsvSource({
            "SHA256withRSA,PKCS1-v1_5,SHA-256",
            "SHA384withRSA/PSS,PSS,SHA-384",
            "SHA512withECDSA,,SHA-512",
            "NONEwithRSA,PKCS1-v1_5,"})
    void signature_preservesTheRequestedSchemeAndDigest(String algorithm, String expectedScheme,
            String expectedDigest) {
        // given
        // when
        List<RequestAttribute> attributes = LegacyJcaAttributes.signature(algorithm);

        // then
        assertEquals(expectedScheme, value(attributes, "data_rsaSigScheme"));
        assertEquals(expectedDigest, value(attributes, "data_sigDigest"));
    }

    private static Object value(List<RequestAttribute> attributes, String name) {
        return attributes.stream().filter(attribute -> name.equals(attribute.getName())).findFirst().map(attribute -> {
            List<? extends AttributeContent> content = attribute.getContent();
            return content.getFirst().getData();
        }).orElse(null);
    }
}
