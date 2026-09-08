package com.otilm.core.integration.search;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.core.enums.FilterField;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SearchHelper;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.Set;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

/**
 * The property columns each configurable-column listing offers.
 *
 * <p>
 * A property field is displayable when its listing carries the value the column would show - a judgement made per field
 * against that listing's mapper, for the reasons the absent-from-listing set in {@link SearchHelper} records. So the
 * decision is written out here as a literal, and the assertion is that the catalogue matches it exactly.
 *
 * <p>
 * That exactness is the point. A field added to one of these listings is displayable by default, so it lands outside
 * this map and turns the test red until someone has read the mapper and either added the field here or added it to the
 * absent-from-listing set in {@link SearchHelper}. Neither a new blank column nor a quietly withdrawn one reaches the
 * picker without that.
 *
 * <p>
 * Property fields resolve their flags against the JPA metamodel, so this runs with a persistence context rather than as
 * a plain unit test.
 */
class PropertyColumnDisplayabilityITest extends BaseSpringBootTest {

    private static final Map<Resource, Set<FilterField>> OFFERED_COLUMNS = new EnumMap<>(Resource.class);

    static {
        OFFERED_COLUMNS
                .put(Resource.CERTIFICATE,
                        EnumSet
                                .of(FilterField.COMMON_NAME, FilterField.SERIAL_NUMBER, FilterField.RA_PROFILE_NAME,
                                        FilterField.CERTIFICATE_TYPE, FilterField.CERTIFICATE_STATE,
                                        FilterField.CERTIFICATE_VALIDATION_STATUS, FilterField.COMPLIANCE_STATUS,
                                        FilterField.GROUP_NAME, FilterField.OWNER, FilterField.ISSUER_COMMON_NAME,
                                        FilterField.SIGNATURE_ALGORITHM, FilterField.ALT_SIGNATURE_ALGORITHM,
                                        FilterField.FINGERPRINT, FilterField.NOT_AFTER, FilterField.NOT_BEFORE,
                                        FilterField.PUBLIC_KEY_ALGORITHM, FilterField.ALT_PUBLIC_KEY_ALGORITHM,
                                        FilterField.KEY_SIZE, FilterField.ALT_KEY_SIZE, FilterField.SUBJECTDN,
                                        FilterField.ISSUERDN, FilterField.ISSUER_SERIAL_NUMBER, FilterField.PRIVATE_KEY,
                                        FilterField.TRUSTED_CA, FilterField.HYBRID_CERTIFICATE, FilterField.ARCHIVED));

        OFFERED_COLUMNS
                .put(Resource.CRYPTOGRAPHIC_KEY, EnumSet
                        .of(FilterField.CKI_NAME, FilterField.CKI_TYPE, FilterField.CKI_FORMAT, FilterField.CKI_STATE,
                                FilterField.CKI_CRYPTOGRAPHIC_ALGORITHM, FilterField.CKI_USAGE, FilterField.CKI_LENGTH,
                                FilterField.CKI_ENABLED, FilterField.CKI_CREATED, FilterField.CK_TOKEN_PROFILE,
                                FilterField.CK_TOKEN_INSTANCE, FilterField.CK_GROUP, FilterField.CK_OWNER));

        OFFERED_COLUMNS
                .put(Resource.DISCOVERY,
                        EnumSet
                                .of(FilterField.DISCOVERY_NAME, FilterField.DISCOVERY_START_TIME,
                                        FilterField.DISCOVERY_END_TIME, FilterField.DISCOVERY_STATUS,
                                        FilterField.DISCOVERY_TOTAL_CERT_DISCOVERED,
                                        FilterField.DISCOVERY_CONNECTOR_NAME, FilterField.DISCOVERY_KIND));

        OFFERED_COLUMNS
                .put(Resource.CONNECTOR, EnumSet
                        .of(FilterField.CONNECTOR_NAME, FilterField.CONNECTOR_VERSION, FilterField.CONNECTOR_URL,
                                FilterField.CONNECTOR_STATUS, FilterField.CONNECTOR_INTERFACE,
                                FilterField.CONNECTOR_FEATURES, FilterField.CONNECTOR_FUNCTION_GROUP));

        OFFERED_COLUMNS
                .put(Resource.SECRET, EnumSet
                        .of(FilterField.SECRET_NAME, FilterField.SECRET_TYPE, FilterField.SECRET_STATE,
                                FilterField.SECRET_ENABLED, FilterField.SECRET_GROUP_NAME, FilterField.SECRET_OWNER,
                                FilterField.SECRET_COMPLIANCE_STATUS, FilterField.SECRET_SOURCE_VAULT_PROFILE));

        OFFERED_COLUMNS
                .put(Resource.CBOM, EnumSet
                        .of(FilterField.CBOM_SERIAL_NUMBER, FilterField.CBOM_VERSION, FilterField.CBOM_TIMESTAMP,
                                FilterField.CBOM_SOURCE, FilterField.CBOM_ALGORITHMS_COUNT,
                                FilterField.CBOM_CERTIFICATES_COUNT, FilterField.CBOM_PROTOCOLS_COUNT,
                                FilterField.CBOM_CRYPTO_MATERIAL_COUNT, FilterField.CBOM_TOTAL_ASSETS_COUNT,
                                FilterField.CBOM_ASSET_SYNC_STATE, FilterField.CBOM_ASSETS_SYNCED_AT));

        OFFERED_COLUMNS
                .put(Resource.SIGNING_RECORD, EnumSet
                        .of(FilterField.SIGNING_RECORD_NAME, FilterField.SIGNING_RECORD_SIGNING_PROFILE,
                                FilterField.SIGNING_RECORD_PROTOCOL, FilterField.SIGNING_RECORD_SIGNING_PROFILE_VERSION,
                                FilterField.SIGNING_RECORD_SIGNING_TIME, FilterField.SIGNING_RECORD_CREATED));
    }

    /**
     * A listing outside the map offers no columns at all: it returns a DTO the projector cannot fill, so every field of
     * it reports false, and a resource missing from the map yields the empty set that says so.
     */
    @ParameterizedTest
    @EnumSource(FilterField.class)
    void thePublishedColumnsAreExactlyTheDecidedOnes(FilterField filterField) {
        Set<FilterField> offered = OFFERED_COLUMNS.getOrDefault(filterField.getRootResource(), Set.of());

        Assertions
                .assertEquals(offered.contains(filterField), SearchHelper.isDisplayable(filterField),
                        filterField.name());
    }

    /**
     * On a listing that publishes columns a sort is triggered by clicking a column header, so a field that cannot be a
     * column cannot be ordered on either, however orderable its path is. {@code CERTIFICATE_PROTOCOL} is the case that
     * would otherwise disagree with itself: it resolves to one scalar the repository can order by, and shows nothing.
     */
    @Test
    void aFieldThatCannotBeAColumnIsNotSortable() {
        SearchFieldDataDto field = SearchHelper.prepareSearch(FilterField.CERTIFICATE_PROTOCOL);

        Assertions.assertTrue(SearchHelper.isOrderableField(FilterField.CERTIFICATE_PROTOCOL));
        Assertions.assertEquals(false, field.getDisplayable());
        Assertions.assertEquals(false, field.getSortable());
        Assertions.assertFalse(SearchHelper.isOrderableOnListing(FilterField.CERTIFICATE_PROTOCOL));
    }

    /**
     * A listing outside the pipeline orders from its own code rather than from a column header, so withholding the
     * column must not withhold the ordering: the OID entries listing orders by a field no picker ever offered.
     */
    @Test
    void aListingWithoutColumnsStillOrdersByItsOwnFields() {
        Assertions.assertFalse(SearchHelper.isDisplayable(FilterField.OID_ENTRY_CODE));
        Assertions.assertTrue(SearchHelper.isOrderableOnListing(FilterField.OID_ENTRY_CODE));
    }
}
