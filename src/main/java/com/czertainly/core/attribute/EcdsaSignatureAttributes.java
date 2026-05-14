package com.czertainly.core.attribute;

import com.czertainly.api.model.client.attribute.RequestAttributeV2;
import com.czertainly.api.model.common.attribute.common.AttributeType;
import com.czertainly.api.model.common.attribute.common.BaseAttribute;
import com.czertainly.api.model.common.attribute.common.content.AttributeContentType;
import com.czertainly.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.czertainly.api.model.common.attribute.v2.DataAttributeV2;
import com.czertainly.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.czertainly.api.model.common.enums.cryptography.DigestAlgorithm;
import com.czertainly.core.attribute.engine.AttributeOperation;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

@Component
public class EcdsaSignatureAttributes {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private EcdsaSignatureAttributes(){}

    public static final String ATTRIBUTE_DATA_SIG_DIGEST = "data_sigDigest";
    public static final String ATTRIBUTE_DATA_SIG_DIGEST_UUID = "46bfdc2f-a96f-4f5d-a218-d538fde92e6d";
    public static final String ATTRIBUTE_DATA_SIG_DIGEST_LABEL = "Digest Algorithm";
    public static final String ATTRIBUTE_DATA_SIG_DIGEST_DESCRIPTION = "Select on of the available digest (hash) algorithm";

    @CoreAttributeDefinitions(operation = AttributeOperation.SIGN)
    public static List<BaseAttribute> getEcdsaSignatureAttributes() {
        return List.of(
                buildDataDigest()
        );
    }

    public static BaseAttribute buildDataDigest() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_SIG_DIGEST_UUID);
        attribute.setName(ATTRIBUTE_DATA_SIG_DIGEST);
        attribute.setDescription(ATTRIBUTE_DATA_SIG_DIGEST_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_SIG_DIGEST_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        // set content
        attribute.setContent(
                Stream.of(DigestAlgorithm.values())
                        .map(item -> new StringAttributeContentV2(item.getLabel(), item.getCode()))
                        .toList()
        );

        return attribute;
    }

    public static RequestAttributeV2 buildRequestDigest(DigestAlgorithm value) {
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(UUID.fromString(ATTRIBUTE_DATA_SIG_DIGEST_UUID));
        attribute.setName(ATTRIBUTE_DATA_SIG_DIGEST);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2(value.getCode())));
        return attribute;
    }

}
