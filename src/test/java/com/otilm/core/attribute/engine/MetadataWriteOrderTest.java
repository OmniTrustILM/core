package com.otilm.core.attribute.engine;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.MetadataAttributeV2;
import java.util.Comparator;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MetadataWriteOrderTest {

    private static final String LOWER_A = "aaaaaaaa-0000-0000-0000-000000000001";
    private static final String UPPER_B = "BBBBBBBB-0000-0000-0000-000000000002";

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

    /**
     * The database compares UUIDs whatever their case, so two writers of the same definitions must order them alike.
     */
    @Test
    void metadataIsWrittenInUuidOrderWhateverTheCase() {
        List<String> mixedCase = names(AttributeEngine.METADATA_WRITE_ORDER, metadata(UPPER_B, "b"),
                metadata(LOWER_A, "a"));
        List<String> lowerCase = names(AttributeEngine.METADATA_WRITE_ORDER, metadata(UPPER_B.toLowerCase(), "b"),
                metadata(LOWER_A, "a"));

        assertThat(mixedCase).isEqualTo(lowerCase);
    }

    @Test
    void definitionsAreRegisteredInUuidOrderWhateverTheCase() {
        List<String> mixedCase = names(AttributeEngine.DEFINITION_WRITE_ORDER, data(UPPER_B, "b"), data(LOWER_A, "a"));
        List<String> lowerCase = names(AttributeEngine.DEFINITION_WRITE_ORDER, data(UPPER_B.toLowerCase(), "b"),
                data(LOWER_A, "a"));

        assertThat(mixedCase).isEqualTo(lowerCase);
    }

    @SafeVarargs
    private static <T extends BaseAttribute> List<String> names(Comparator<? super T> order, T... attributes) {
        return Stream.of(attributes).sorted(order).map(BaseAttribute::getName).toList();
    }

    private static DataAttributeV2 data(String uuid, String name) {
        DataAttributeV2 data = new DataAttributeV2();
        data.setUuid(uuid);
        data.setName(name);
        data.setType(AttributeType.DATA);
        return data;
    }

    private static MetadataAttribute metadata(String uuid, String name) {
        MetadataAttributeV2 metadata = new MetadataAttributeV2();
        metadata.setUuid(uuid);
        metadata.setName(name);
        metadata.setProperties(new MetadataAttributeProperties());
        return metadata;
    }
}
