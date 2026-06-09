package com.czertainly.core.attribute;

import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.BooleanAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.RsaEncryptionScheme;
import com.czertainly.core.attribute.engine.AttributeOperation;
import org.springframework.stereotype.Component;

import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;

@Component
public class RsaEncryptionAttributes {

    /**
     * Private constructor to prevent instantiation of utility class.
     */
    private RsaEncryptionAttributes() {}

    public static final String ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME = "data_rsaEncScheme"; // this would be OAEP or PKCS1-v1_5 according the RFC 8017
    public static final String ATTRIBUTE_DATA_RSA_ENC_SCHEME_UUID = "6a93364c-d9d4-11ed-afa1-0242ac120002";
    public static final String ATTRIBUTE_DATA_RSA_ENC_SCHEME_LABEL = "RSA Encryption Scheme";
    public static final String ATTRIBUTE_DATA_RSA_ENC_SCHEME_DESCRIPTION = "RSA Encryption Scheme to use";

    // additional attributes for OAEP only

    public static final String ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME = "data_rsaOaepHash"; // this would be SHA-1, SHA-256, SHA-384, SHA-512
    public static final String ATTRIBUTE_DATA_RSA_OAEP_HASH_UUID = "6a933a52-d9d4-11ed-afa1-0242ac120002";
    public static final String ATTRIBUTE_DATA_RSA_OAEP_HASH_LABEL = "OAEP Hash";
    public static final String ATTRIBUTE_DATA_RSA_OAEP_HASH_DESCRIPTION = "OAEP Hash Function";

    public static final String ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME = "data_rsaOaepMgf"; // true or false, because only MGF1 is supported by the RFC 8017
    public static final String ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_UUID = "6a933c32-d9d4-11ed-afa1-0242ac120002";
    public static final String ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_LABEL = "OAEP MGF";
    public static final String ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_DESCRIPTION = "Usage of OAEP MGF";


    @CoreAttributeDefinitions(operation = AttributeOperation.ENCRYPT)
    public static List<BaseAttribute> getRsaEncryptionAttributes() {
        return List.of(
                buildDataEncryptionScheme(),
                buildDataOaepHash(),
                buildDataOaepMgf()
        );
    }

    public static BaseAttribute buildDataEncryptionScheme() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_RSA_ENC_SCHEME_UUID);
        attribute.setName(ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME);
        attribute.setDescription(ATTRIBUTE_DATA_RSA_ENC_SCHEME_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(
                Stream.of(RsaEncryptionScheme.values())
                        .map(item -> new StringAttributeContentV2(item.getLabel(), item.getCode()))
                        .toList()
        );
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_RSA_ENC_SCHEME_LABEL);
        attributeProperties.setRequired(false);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        return attribute;
    }

    public static BaseAttribute buildDataOaepMgf() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_UUID);
        attribute.setName(ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME);
        attribute.setDescription(ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.BOOLEAN);
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_LABEL);
        attributeProperties.setRequired(false);
        attributeProperties.setVisible(true);
        attributeProperties.setList(false);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        return attribute;
    }

    public static BaseAttribute buildDataOaepHash() {
        // define Data Attribute
        DataAttributeV2 attribute = new DataAttributeV2();
        attribute.setUuid(ATTRIBUTE_DATA_RSA_OAEP_HASH_UUID);
        attribute.setName(ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME);
        attribute.setDescription(ATTRIBUTE_DATA_RSA_OAEP_HASH_DESCRIPTION);
        attribute.setType(AttributeType.DATA);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(
                Stream.of(DigestAlgorithm.values())
                        .map(item -> new StringAttributeContentV2(item.getLabel(), item.getCode()))
                        .toList()
        );
        // create properties
        DataAttributeProperties attributeProperties = new DataAttributeProperties();
        attributeProperties.setLabel(ATTRIBUTE_DATA_RSA_OAEP_HASH_LABEL);
        attributeProperties.setRequired(true);
        attributeProperties.setVisible(true);
        attributeProperties.setList(true);
        attributeProperties.setMultiSelect(false);
        attributeProperties.setReadOnly(false);
        attribute.setProperties(attributeProperties);
        return attribute;
    }

    public static RequestAttributeV2 buildRequestEncryptionScheme(RsaEncryptionScheme value) {
        // define Data Attribute
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(UUID.fromString(ATTRIBUTE_DATA_RSA_ENC_SCHEME_UUID));
        attribute.setName(ATTRIBUTE_DATA_RSA_ENC_SCHEME_NAME);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2(value.getCode())));
        return attribute;
    }

    public static RequestAttributeV2 buildRequestOaepHash(DigestAlgorithm value) {
        // define Data Attribute
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(UUID.fromString(ATTRIBUTE_DATA_RSA_OAEP_HASH_UUID));
        attribute.setName(ATTRIBUTE_DATA_RSA_OAEP_HASH_NAME);
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV2(value.getCode())));
        return attribute;
    }

    public static RequestAttributeV2 buildRequestOaepMgf(boolean value) {
        // define Data Attribute
        RequestAttributeV2 attribute = new RequestAttributeV2();
        attribute.setUuid(UUID.fromString(ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_UUID));
        attribute.setName(ATTRIBUTE_DATA_RSA_OAEP_USE_MGF_NAME);
        attribute.setContentType(AttributeContentType.BOOLEAN);
        attribute.setContent(List.of(new BooleanAttributeContentV2(value)));
        return attribute;
    }
}
