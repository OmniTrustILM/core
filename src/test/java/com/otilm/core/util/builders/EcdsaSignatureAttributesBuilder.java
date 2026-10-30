package com.otilm.core.util.builders;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.core.attribute.EcdsaSignatureAttributes;

import java.util.List;
import java.util.UUID;

public class EcdsaSignatureAttributesBuilder {

    private DigestAlgorithm digest = DigestAlgorithm.SHA_256;

    public static EcdsaSignatureAttributesBuilder ecdsaSignatureAttributes() {
        return new EcdsaSignatureAttributesBuilder();
    }

    public EcdsaSignatureAttributesBuilder withDigest(DigestAlgorithm digest) {
        this.digest = digest;
        return this;
    }

    public List<RequestAttribute> build() {
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setUuid(UUID.fromString(EcdsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID));
        attr.setName(EcdsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST);
        attr.setContentType(AttributeContentType.STRING);
        attr.setContent(List.of(new StringAttributeContentV2(digest.getLabel(), digest.getCode())));
        return List.of(attr);
    }
}
