package com.czertainly.core.util.builders;

import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaSignatureScheme;
import com.czertainly.core.attribute.RsaSignatureAttributes;

import java.util.List;
import java.util.UUID;

public class RsaSignatureAttributesBuilder {

    private RsaSignatureScheme scheme = RsaSignatureScheme.PKCS1_v1_5;
    private DigestAlgorithm digest = DigestAlgorithm.SHA_256;

    public static RsaSignatureAttributesBuilder rsaSignatureAttributes() {
        return new RsaSignatureAttributesBuilder();
    }

    private static RequestAttribute attribute(String uuid, String name, String reference, String data) {
        RequestAttributeV2 attr = new RequestAttributeV2();
        attr.setUuid(UUID.fromString(uuid));
        attr.setName(name);
        attr.setContentType(AttributeContentType.STRING);
        attr.setContent(List.of(new StringAttributeContentV2(reference, data)));
        return attr;
    }

    public RsaSignatureAttributesBuilder withScheme(RsaSignatureScheme scheme) {
        this.scheme = scheme;
        return this;
    }

    public RsaSignatureAttributesBuilder withDigest(DigestAlgorithm digest) {
        this.digest = digest;
        return this;
    }

    public List<RequestAttribute> build() {
        return List.of(
                attribute(RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME_UUID,
                        RsaSignatureAttributes.ATTRIBUTE_DATA_RSA_SIG_SCHEME,
                        scheme.getLabel(), scheme.getCode()),
                attribute(RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST_UUID,
                        RsaSignatureAttributes.ATTRIBUTE_DATA_SIG_DIGEST,
                        digest.getLabel(), digest.getCode())
        );
    }
}
