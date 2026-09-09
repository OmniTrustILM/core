package com.otilm.core.util;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.model.SearchFieldObject;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The column flags an attribute-sourced catalogue field carries. A property field's flags come from the JPA static
 * metamodel, and reading {@code FilterField} without a persistence context fails, so those are asserted in
 * {@code ColumnCatalogueFlagsITest} rather than here.
 */
class SearchHelperColumnFlagsTest {

    /** A resource whose listing applies a requested sort, so the sortable flag is not switched off by the resource. */
    private static final Resource RESOURCE = Resource.DISCOVERY;

    private static SearchFieldObject attributeField(AttributeContentType contentType, ProtectionLevel protectionLevel) {
        SearchFieldObject field = new SearchFieldObject("cost-centre", contentType, AttributeType.CUSTOM);
        field.setLabel("Cost centre");
        field.setProtectionLevel(protectionLevel);
        field.setContentItems(List.of());
        return field;
    }

    private static SearchFieldDataDto prepare(AttributeContentType contentType, ProtectionLevel protectionLevel) {
        return SearchHelper.prepareSearchForJSON(attributeField(contentType, protectionLevel), false, RESOURCE);
    }

    @Test
    void ordinaryAttributeIsOfferedAsAColumn() {
        Assertions.assertEquals(true, prepare(AttributeContentType.TEXT, ProtectionLevel.NONE).getDisplayable());
    }

    @Test
    void secretContentIsNeverOfferedAsAColumn() {
        Assertions.assertEquals(false, prepare(AttributeContentType.SECRET, ProtectionLevel.NONE).getDisplayable());
    }

    @Test
    void encryptedContentIsNeverOfferedAsAColumn() {
        // Stored as ciphertext only its own decryption path can read, and a listing does not take that path.
        Assertions.assertEquals(false, prepare(AttributeContentType.TEXT, ProtectionLevel.ENCRYPTED).getDisplayable());
    }

    @Test
    void codeBlockContentIsNeverOfferedAsAColumn() {
        // Multi-line by construction, so a single-line table cell cannot hold one without breaking the row.
        Assertions.assertEquals(false, prepare(AttributeContentType.CODEBLOCK, ProtectionLevel.NONE).getDisplayable());
    }

    /**
     * A listing outside the column pipeline never invokes the projector, so even an ordinary custom attribute of that
     * resource has nothing to fill the cells of a column asking for it.
     */
    @Test
    void noAttributeOfAnUnwiredListingIsOfferedAsAColumn() {
        Assertions
                .assertEquals(false,
                        SearchHelper
                                .prepareSearchForJSON(attributeField(AttributeContentType.TEXT, ProtectionLevel.NONE),
                                        false, Resource.LOCATION)
                                .getDisplayable());
    }

    @Test
    void anOrdinaryAttributeOfAWiredListingIsSortable() {
        Assertions.assertEquals(true, prepare(AttributeContentType.TEXT, ProtectionLevel.NONE).getSortable());
    }

    @Test
    void noAttributeOfAnUnwiredListingIsSortable() {
        // Locations do not pass a requested sort to the repository, so ordering there would be advertised and then
        // discarded.
        Assertions
                .assertEquals(false,
                        SearchHelper
                                .prepareSearchForJSON(attributeField(AttributeContentType.TEXT, ProtectionLevel.NONE),
                                        false, Resource.LOCATION)
                                .getSortable());
    }

    @ParameterizedTest
    @EnumSource(value = AttributeContentType.class, names = {"SECRET", "CODEBLOCK", "FILE", "RESOURCE"})
    void anAttributeWhoseCellIsNotItsSortKeyIsNotSortable(AttributeContentType contentType) {
        // Secret and code-block content is never rendered at all. A file cell reads its name and media type and a
        // resource cell the referenced object's name, none of which is the reference a sort key would order by.
        Assertions.assertEquals(false, prepare(contentType, ProtectionLevel.NONE).getSortable());
    }

    @Test
    void encryptedContentIsNeverSortable() {
        Assertions.assertEquals(false, prepare(AttributeContentType.TEXT, ProtectionLevel.ENCRYPTED).getSortable());
    }

    @ParameterizedTest
    @EnumSource(value = AttributeContentType.class, names = {"CREDENTIAL", "OBJECT"})
    void anAttributeWhoseCellIsItsReferenceIsSortable(AttributeContentType contentType) {
        // The projector reduces both to their reference and nothing else, which is exactly what the sort key reads.
        Assertions.assertEquals(true, prepare(contentType, ProtectionLevel.NONE).getSortable());
    }

    @ParameterizedTest
    @EnumSource(AttributeContentType.class)
    void everyAttributeFieldAnswersBothFlags(AttributeContentType contentType) {
        SearchFieldDataDto field = prepare(contentType, ProtectionLevel.NONE);

        // A flag left null would reach the picker as "unknown", and the frontend reads an absent flag as a no.
        Assertions.assertNotNull(field.getDisplayable());
        Assertions.assertNotNull(field.getSortable());
    }

    @Test
    void noContentTypeBeyondSecretAndCodeBlockIsWithheld() {
        Set<AttributeContentType> undisplayable = Arrays
                .stream(AttributeContentType.values())
                .filter(contentType -> !prepare(contentType, ProtectionLevel.NONE).getDisplayable())
                .collect(Collectors.toSet());

        Assertions.assertEquals(Set.of(AttributeContentType.SECRET, AttributeContentType.CODEBLOCK), undisplayable);
    }
}
