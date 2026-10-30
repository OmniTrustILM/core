package com.otilm.core.service.notifications;

import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.core.dao.entity.AttributeDefinition;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyCollection;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AttributeProtectionExclusionsTest {

    private static final UUID PLAIN = UUID.fromString("00000000-0000-0000-0000-000000000001");
    private static final UUID PROTECTED_COLUMN = UUID.fromString("00000000-0000-0000-0000-000000000002");
    private static final UUID PROTECTED_DECLARED = UUID.fromString("00000000-0000-0000-0000-000000000003");
    private static final UUID MISSING = UUID.fromString("00000000-0000-0000-0000-000000000004");
    private static final UUID UNREADABLE = UUID.fromString("00000000-0000-0000-0000-000000000005");
    private static final UUID NO_PROPERTIES = UUID.fromString("00000000-0000-0000-0000-000000000006");

    @Mock
    private AttributeDefinitionRepository repository;

    private AttributeProtectionExclusions exclusions() {
        return new AttributeProtectionExclusions(repository);
    }

    @Test
    void plainDefinitionsAreNotExcluded() {
        when(repository.findByAttributeUuidIn(anyCollection()))
                .thenReturn(List.of(definition(PLAIN, ProtectionLevel.NONE, declaredMetadata(ProtectionLevel.NONE))));

        assertTrue(exclusions().excludedFrom(List.of(PLAIN)).isEmpty());
    }

    @Test
    void entityColumnProtectionExcludes() {
        when(repository.findByAttributeUuidIn(anyCollection()))
                .thenReturn(List
                        .of(definition(PROTECTED_COLUMN, ProtectionLevel.ENCRYPTED,
                                declaredMetadata(ProtectionLevel.NONE))));

        assertEquals(Set.of(PROTECTED_COLUMN), exclusions().excludedFrom(List.of(PROTECTED_COLUMN)));
    }

    @Test
    void declaredMetadataProtectionExcludesEvenWhenTheColumnIsEmpty() {
        // The definition builder never copies declared metadata protection onto the entity
        // column, so the column alone under-reports -- the declared properties are authoritative.
        when(repository.findByAttributeUuidIn(anyCollection()))
                .thenReturn(List.of(definition(PROTECTED_DECLARED, null, declaredMetadata(ProtectionLevel.ENCRYPTED))));

        assertEquals(Set.of(PROTECTED_DECLARED), exclusions().excludedFrom(List.of(PROTECTED_DECLARED)));
    }

    @Test
    void unresolvableDefinitionIsExcludedFailClosed() {
        when(repository.findByAttributeUuidIn(anyCollection())).thenReturn(List.of());

        assertEquals(Set.of(MISSING), exclusions().excludedFrom(List.of(MISSING)));
    }

    @Test
    void unreadableDefinitionDocumentIsExcludedFailClosed() {
        AttributeDefinition definition = mock(AttributeDefinition.class);
        when(definition.getAttributeUuid()).thenReturn(UNREADABLE);
        when(definition.getProtectionLevel()).thenReturn(null);
        when(definition.getDefinition()).thenThrow(new IllegalStateException("corrupt document"));
        when(repository.findByAttributeUuidIn(anyCollection())).thenReturn(List.of(definition));

        assertEquals(Set.of(UNREADABLE), exclusions().excludedFrom(List.of(UNREADABLE)));
    }

    @Test
    void metadataWithoutDeclaredPropertiesIsExcludedFailClosed() {
        MetadataAttributeV3 document = new MetadataAttributeV3();
        document.setProperties(null);
        when(repository.findByAttributeUuidIn(anyCollection()))
                .thenReturn(List.of(definition(NO_PROPERTIES, null, document)));

        assertEquals(Set.of(NO_PROPERTIES), exclusions().excludedFrom(List.of(NO_PROPERTIES)));
    }

    @Test
    void emptyInputYieldsEmptyOutput() {
        assertTrue(exclusions().excludedFrom(null).isEmpty());
        assertTrue(exclusions().excludedFrom(List.of()).isEmpty());
    }

    private static AttributeDefinition definition(UUID attributeUuid, ProtectionLevel columnLevel,
            MetadataAttributeV3 document) {
        AttributeDefinition definition = new AttributeDefinition();
        definition.setAttributeUuid(attributeUuid);
        definition.setProtectionLevel(columnLevel);
        definition.setDefinition(document);
        return definition;
    }

    private static MetadataAttributeV3 declaredMetadata(ProtectionLevel level) {
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setProtectionLevel(level);
        MetadataAttributeV3 document = new MetadataAttributeV3();
        document.setProperties(properties);
        return document;
    }
}
