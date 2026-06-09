package com.czertainly.core.util;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.czertainly.core.attribute.CsrAttributes;
import org.bouncycastle.asn1.x500.X500Name;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

class CertificateRequestUtilsTest {

    @Test
    void testBuildSubject() {
        List<RequestAttribute> attributes = new ArrayList<>();
        attributes.add(createRequestAttribute(CsrAttributes.COMMON_NAME_ATTRIBUTE_NAME, "+,\\\"><;123ěščřžýáíé"));
        attributes.add(createRequestAttribute(CsrAttributes.ORGANIZATION_UNIT_ATTRIBUTE_NAME, " ou"));
        attributes.add(createRequestAttribute(CsrAttributes.ORGANIZATION_ATTRIBUTE_NAME, "#o"));
        attributes.add(createRequestAttribute(CsrAttributes.LOCALITY_ATTRIBUTE_NAME, "locality "));
        attributes.add(createRequestAttribute(CsrAttributes.STATE_ATTRIBUTE_NAME, "state, C=country"));
        X500Principal x500Principal = CertificateRequestUtils.buildSubject(attributes);
        Assertions.assertEquals("CN=\\+\\,\\\\\\\"\\>\\<\\;123ěščřžýáíé,OU=\\ ou,O=\\#o,L=locality\\ ,ST=state\\, C\\=country", x500Principal.getName());
        X500Name x500Name = new X500Name(x500Principal.getName());
        Assertions.assertEquals(5, x500Name.getRDNs().length);
    }

    private RequestAttribute createRequestAttribute(String name, String data) {
        RequestAttributeV3 attributeDto = new RequestAttributeV3();
        attributeDto.setUuid(UUID.randomUUID());
        attributeDto.setName(name);
        attributeDto.setContentType(AttributeContentType.STRING);
        attributeDto.setContent(List.of(new StringAttributeContentV3(data)));
        return attributeDto;
    }
}
