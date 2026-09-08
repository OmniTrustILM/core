package com.otilm.core.attribute.engine;

import com.otilm.api.model.client.certificate.SearchColumnRequestDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.AttributeProjectable;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.attribute.engine.AttributeEngine.CustomAttributeContentFilter;
import com.otilm.core.attribute.engine.records.ProjectedAttributeContent;
import com.otilm.core.dao.repository.AttributeContent2ObjectRepository;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Which loaded content rows reach a column: a row of ciphertext, and a row of a content type no list cell renders, are
 * dropped even when the query returns them.
 */
class ProjectedContentWithholdingTest {

    private static final UUID OBJECT_UUID = UUID.randomUUID();

    private static final String ATTRIBUTE_NAME = "environment";

    private static final String FIELD_IDENTIFIER = ATTRIBUTE_NAME + "|STRING";

    private AttributeContent2ObjectRepository attributeContent2ObjectRepository;

    private AttributeColumnProjector projector;

    @BeforeEach
    void setUp() {
        attributeContent2ObjectRepository = mock(AttributeContent2ObjectRepository.class);
        projector = new AttributeColumnProjector(attributeContent2ObjectRepository);
    }

    @Test
    void anOrdinaryRowIsProjected() {
        Map<FilterFieldSource, Map<String, List<BaseAttributeContentV3<?>>>> values = project(
                row(AttributeContentType.STRING, null, "production"));

        assertEquals(Set.of(FilterFieldSource.CUSTOM), values.keySet());
        List<BaseAttributeContentV3<?>> projected = values.get(FilterFieldSource.CUSTOM).get(FIELD_IDENTIFIER);
        assertEquals(1, projected.size());
        assertEquals("production", projected.getFirst().getData());
    }

    @Test
    void aRowStoredAsCiphertextIsNotProjected() {
        assertNull(project(row(AttributeContentType.STRING, "ciphertext", "production")));
    }

    @ParameterizedTest
    @EnumSource(value = AttributeContentType.class, names = {"SECRET", "CODEBLOCK"})
    void aRowOfAWithheldContentTypeIsNotProjected(AttributeContentType withheld) {
        assertNull(project(row(withheld, null, "production")));
    }

    private Map<FilterFieldSource, Map<String, List<BaseAttributeContentV3<?>>>> project(
            ProjectedAttributeContent stored) {
        when(attributeContent2ObjectRepository
                .getProjectedAttributesContent(any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(List.of(stored));
        Entry entry = new Entry();

        projector
                .project(Resource.DISCOVERY,
                        List.of(new SearchColumnRequestDto(FilterFieldSource.CUSTOM, FIELD_IDENTIFIER)), List.of(entry),
                        listed -> OBJECT_UUID, () -> new CustomAttributeContentFilter(null, null));

        return entry.getAttributeValues();
    }

    private static ProjectedAttributeContent row(AttributeContentType contentType, String encryptedContent,
            String value) {
        return new ProjectedAttributeContent(OBJECT_UUID, AttributeType.CUSTOM, ATTRIBUTE_NAME, contentType,
                new StringAttributeContentV3(value), encryptedContent);
    }

    private static final class Entry implements AttributeProjectable {

        private Map<FilterFieldSource, Map<String, List<BaseAttributeContentV3<?>>>> attributeValues;

        @Override
        public Map<FilterFieldSource, Map<String, List<BaseAttributeContentV3<?>>>> getAttributeValues() {
            return attributeValues;
        }

        @Override
        public void setAttributeValues(
                Map<FilterFieldSource, Map<String, List<BaseAttributeContentV3<?>>>> attributeValues) {
            this.attributeValues = attributeValues;
        }
    }
}
