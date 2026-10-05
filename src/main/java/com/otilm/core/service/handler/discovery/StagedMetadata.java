package com.otilm.core.service.handler.discovery;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.SecretEncodingVersion;
import com.otilm.core.util.SecretsUtil;
import java.util.ArrayList;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * How discovery holds a connector's metadata between staging and import. Attributes the connector declares
 * {@link ProtectionLevel#ENCRYPTED} are kept apart, encrypted as one value, the way the attribute engine holds them
 * once they reach an object.
 *
 * <p>
 * A row staged before the split has no separate value, and its metadata reads as stored. Code that predates the split
 * reads only the visible part, so during a rolling upgrade it imports a certificate without its protected metadata
 * rather than with a ciphertext in its place.
 */
public final class StagedMetadata {

    private static final Logger logger = LoggerFactory.getLogger(StagedMetadata.class);

    private StagedMetadata() {
    }

    /**
     * Metadata as staged.
     *
     * @param meta the attributes stored in the clear
     * @param protectedMeta the encrypted rest, or null when there is none
     */
    public record Sealed(List<MetadataAttribute> meta, String protectedMeta) {
    }

    public static Sealed seal(List<MetadataAttribute> meta) {
        if (meta == null || meta.isEmpty()) {
            return new Sealed(meta, null);
        }
        List<MetadataAttribute> visible = new ArrayList<>();
        List<MetadataAttribute> protectedAttributes = new ArrayList<>();
        for (MetadataAttribute attribute : meta) {
            if (isProtected(attribute)) {
                protectedAttributes.add(attribute);
            } else {
                visible.add(attribute);
            }
        }
        if (protectedAttributes.isEmpty()) {
            return new Sealed(meta, null);
        }
        return new Sealed(visible,
                SecretsUtil
                        .encryptAndEncodeSecretString(AttributeDefinitionUtils.serialize(protectedAttributes),
                                SecretEncodingVersion.V1));
    }

    /**
     * The metadata a staged row carries, protected attributes included. An unreadable protected value costs those
     * attributes, not the row.
     */
    public static List<MetadataAttribute> unseal(List<MetadataAttribute> meta, String protectedMeta) {
        if (protectedMeta == null) {
            return meta;
        }
        List<MetadataAttribute> protectedAttributes;
        try {
            protectedAttributes = AttributeDefinitionUtils
                    .deserialize(SecretsUtil.decodeAndDecryptSecretString(protectedMeta, SecretEncodingVersion.V1),
                            MetadataAttribute.class);
        } catch (IllegalArgumentException | IllegalStateException e) {
            logger.warn("Protected discovery metadata could not be read and is left out: {}", e.getMessage());
            return meta;
        }
        List<MetadataAttribute> all = new ArrayList<>(meta == null ? List.of() : meta);
        all.addAll(protectedAttributes);
        return all;
    }

    private static boolean isProtected(MetadataAttribute attribute) {
        return attribute.getProperties() != null
                && attribute.getProperties().getProtectionLevel() == ProtectionLevel.ENCRYPTED;
    }
}
