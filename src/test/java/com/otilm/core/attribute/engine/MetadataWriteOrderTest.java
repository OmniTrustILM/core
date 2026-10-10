package com.otilm.core.attribute.engine;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataWriteOrderTest {

    @Test
    void metadataSharingAUuidIsWrittenInNameOrder() {
        String uuid = UUID.randomUUID().toString();

        List<String> names = Stream
                .of(metadata(uuid, "b"), metadata(uuid, "a"))
                .sorted(AttributeEngine.METADATA_WRITE_ORDER)
                .map(MetadataAttribute::getName)
                .toList();

        assertThat(names).containsExactly("a", "b");
    }

    private static MetadataAttribute metadata(String uuid, String name) {
        MetadataAttributeV2 metadata = new MetadataAttributeV2();
        metadata.setUuid(uuid);
        metadata.setName(name);
        metadata.setProperties(new MetadataAttributeProperties());
        return metadata;
    }
}
