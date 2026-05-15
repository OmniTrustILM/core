package com.czertainly.core.search;

import com.czertainly.api.model.client.certificate.SearchRequestDto;
import com.czertainly.api.model.client.connector.v2.ConnectorInterface;
import com.czertainly.api.model.client.connector.v2.ConnectorVersion;
import com.czertainly.api.model.client.connector.v2.FeatureFlag;
import com.czertainly.api.model.common.PaginationResponseDto;
import com.czertainly.api.model.core.connector.AuthType;
import com.czertainly.api.model.core.connector.ConnectorStatus;
import com.czertainly.api.model.core.connector.v2.ConnectorDto;
import com.czertainly.api.model.core.oid.CustomOidEntryListResponseDto;
import com.czertainly.api.model.core.oid.OidCategory;
import com.czertainly.api.model.core.search.FilterConditionOperator;
import com.czertainly.api.model.core.search.FilterFieldSource;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.ConnectorInterfaceEntity;
import com.czertainly.core.dao.entity.oid.RdnAttributeTypeCustomOidEntry;
import com.czertainly.core.dao.repository.ConnectorInterfaceRepository;
import com.czertainly.core.dao.repository.ConnectorRepository;
import com.czertainly.core.dao.repository.CustomOidEntryRepository;
import com.czertainly.core.enums.FilterField;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.service.CustomOidEntryService;
import com.czertainly.core.service.v2.ConnectorService;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Integration tests for NATIVE_ARRAY filter operators.
 * <p>
 * Covers EQUALS, NOT_EQUALS, CONTAINS, NOT_CONTAINS, EMPTY, NOT_EMPTY on native
 * PostgreSQL text[] columns — tested against:
 * <ul>
 *   <li>{@code OID_ENTRY_ALT_CODES} — {@code RdnAttributeTypeCustomOidEntry.altCodes}</li>
 *   <li>{@code CONNECTOR_FEATURES} — {@code ConnectorInterfaceEntity.features}</li>
 * </ul>
 */
class NativeArrayFilterSearchTest extends BaseSpringBootTest {
    @Autowired
    private CustomOidEntryService customOidEntryService;

    @Autowired
    private CustomOidEntryRepository customOidEntryRepository;

    @Nested
    class OidEntryAltCodesFilterTest {

        // altCodes = ["OFI", "OFI2"]
        private RdnAttributeTypeCustomOidEntry multiCode;
        // altCodes = ["ALONE"]
        private RdnAttributeTypeCustomOidEntry singleCode;
        // altCodes = [] (empty array stored as {})
        private RdnAttributeTypeCustomOidEntry noCode;

        @BeforeEach
        void setUp() {
            multiCode = rdnEntry("2.5.4.100", "Multi", "MULTI", List.of("OFI", "OFI2"));
            singleCode = rdnEntry("2.5.4.101", "Single", "SINGLE", List.of("ALONE"));
            noCode = rdnEntry("2.5.4.102", "NoCode", "NOCODE", new ArrayList<>());
        }

        // ─────────────────────────────────────────────
        // EQUALS (single value)
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] EQUALS ''{0}'' expects OIDs {1}")
        @MethodSource("equalsArgs")
        void filterByAltCodes_equals(String value, Set<String> expectedOids) {
            Assertions.assertEquals(expectedOids, new HashSet<>(searchOids(FilterConditionOperator.EQUALS, value)));
        }

        static Stream<Arguments> equalsArgs() {
            return Stream.of(
                    // Only singleCode contains "ALONE".
                    Arguments.of("ALONE", Set.of("2.5.4.101")),
                    // Only multiCode contains "OFI2".
                    Arguments.of("OFI2", Set.of("2.5.4.100")),
                    // Entry with empty altCodes must not match; only multiCode contains "OFI".
                    Arguments.of("OFI", Set.of("2.5.4.100")),
                    // No entry contains this value.
                    Arguments.of("NOSUCHCODE", Set.of())
            );
        }

        // ─────────────────────────────────────────────
        // NOT_EQUALS (single value)
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] NOT_EQUALS ''{0}'' expects OIDs {1}")
        @MethodSource("notEqualsArgs")
        void filterByAltCodes_notEquals(String value, Set<String> expectedOids) {
            Assertions.assertEquals(expectedOids, new HashSet<>(searchOids(FilterConditionOperator.NOT_EQUALS, value)));
        }

        static Stream<Arguments> notEqualsArgs() {
            return Stream.of(
                    // singleCode contains "ALONE" → excluded; multiCode and noCode (empty array) are included.
                    Arguments.of("ALONE", Set.of("2.5.4.100", "2.5.4.102")),
                    // multiCode contains "OFI" → excluded; singleCode and noCode (empty array) are included.
                    Arguments.of("OFI", Set.of("2.5.4.101", "2.5.4.102"))
            );
        }

        // ─────────────────────────────────────────────
        // EQUALS — multi-value (OR semantics)
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] EQUALS {0} expects OIDs {1}")
        @MethodSource("equalsMultiValueArgs")
        void filterByAltCodes_equals_multiValue(List<String> values, Set<String> expectedOids) {
            Assertions.assertEquals(expectedOids, new HashSet<>(searchOids(FilterConditionOperator.EQUALS, values)));
        }

        static Stream<Arguments> equalsMultiValueArgs() {
            return Stream.of(
                    // "ALONE" is in singleCode; "OFI2" is in multiCode — both matched via OR.
                    Arguments.of(List.of("ALONE", "OFI2"), Set.of("2.5.4.101", "2.5.4.100")),
                    // Neither value exists in any entry.
                    Arguments.of(List.of("NOSUCH1", "NOSUCH2"), Set.of())
            );
        }

        // ─────────────────────────────────────────────
        // NOT_EQUALS — multi-value (AND semantics: contains none)
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] NOT_EQUALS {0} expects OIDs {1}")
        @MethodSource("notEqualsMultiValueArgs")
        void filterByAltCodes_notEquals_multiValue(List<String> values, Set<String> expectedOids) {
            Assertions.assertEquals(expectedOids, new HashSet<>(searchOids(FilterConditionOperator.NOT_EQUALS, values)));
        }

        static Stream<Arguments> notEqualsMultiValueArgs() {
            return Stream.of(
                    // multiCode contains "OFI"; singleCode contains "ALONE" → both excluded; noCode survives.
                    Arguments.of(List.of("OFI", "ALONE"), Set.of("2.5.4.102")),
                    // multiCode contains "OFI2" → excluded; singleCode and noCode contain neither value.
                    Arguments.of(List.of("OFI2", "NOSUCH"), Set.of("2.5.4.101", "2.5.4.102"))
            );
        }

        // ─────────────────────────────────────────────
        // EMPTY / NOT_EMPTY
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] {0} expects OIDs {1}")
        @MethodSource("emptyArgs")
        void filterByAltCodes_emptyAndNotEmpty(FilterConditionOperator operator, Set<String> expectedOids) {
            Assertions.assertEquals(expectedOids, new HashSet<>(searchOids(operator, (String) null)));
        }

        static Stream<Arguments> emptyArgs() {
            return Stream.of(
                    // Only noCode has an empty altCodes array {}.
                    Arguments.of(FilterConditionOperator.EMPTY, Set.of("2.5.4.102")),
                    // multiCode and singleCode both have non-empty altCodes.
                    Arguments.of(FilterConditionOperator.NOT_EMPTY, Set.of("2.5.4.100", "2.5.4.101"))
            );
        }

        // ─────────────────────────────────────────────
        // CONTAINS (single value, substring on array items)
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] CONTAINS ''{0}'' expects OIDs {1}")
        @MethodSource("altCodesContainsArgs")
        void filterByAltCodes_contains_matchesEntriesWithElement(String value, List<String> expectedOids) {
            List<String> oids = searchOids(FilterConditionOperator.CONTAINS, value);
            Assertions.assertEquals(new HashSet<>(expectedOids), new HashSet<>(oids));
        }

        static Stream<Arguments> altCodesContainsArgs() {
            return Stream.of(
                    Arguments.of("OFI", List.of("2.5.4.100")),
                    Arguments.of("FI2", List.of("2.5.4.100")),
                    Arguments.of("OFI2", List.of("2.5.4.100")),
                    Arguments.of("ALONE", List.of("2.5.4.101")),
                    Arguments.of("NOSUCH", List.of())
            );
        }

        @ParameterizedTest(name = "[{index}] CONTAINS {0} expects OIDs {1}")
        @MethodSource("altCodesContainsMultiValueArgs")
        void filterByAltCodes_contains_multiValue(List<String> values, Set<String> expectedOids) {
            Assertions.assertEquals(expectedOids, new HashSet<>(searchOids(FilterConditionOperator.CONTAINS, values)));
        }

        static Stream<Arguments> altCodesContainsMultiValueArgs() {
            return Stream.of(
                    // "LON" matches ALONE and "FI2" matches OFI2, so both entries are returned.
                    Arguments.of(List.of("LON", "FI2"), Set.of("2.5.4.100", "2.5.4.101")),
                    Arguments.of(List.of("ZZZ", "YYY"), Set.of())
            );
        }

        // ─────────────────────────────────────────────
        // NOT_CONTAINS (single value, substring on array items)
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] NOT_CONTAINS ''{0}'' expects OIDs {1}")
        @MethodSource("altCodesNotContainsArgs")
        void filterByAltCodes_notContains_excludesEntriesWithElement(String value, List<String> expectedOids) {
            List<String> oids = searchOids(FilterConditionOperator.NOT_CONTAINS, value);
            Assertions.assertEquals(new HashSet<>(expectedOids), new HashSet<>(oids));
        }

        static Stream<Arguments> altCodesNotContainsArgs() {
            return Stream.of(
                    // multiCode {"OFI","OFI2"} is excluded; singleCode and noCode are included.
                    Arguments.of("OFI", List.of("2.5.4.101", "2.5.4.102")),
                    // partial match in OFI/OFI2 still excludes multiCode.
                    Arguments.of("FI", List.of("2.5.4.101", "2.5.4.102")),
                    Arguments.of("OFI2", List.of("2.5.4.101", "2.5.4.102")),
                    // singleCode {"ALONE"} is excluded; multiCode and noCode are included.
                    Arguments.of("ALONE", List.of("2.5.4.100", "2.5.4.102")),
                    // No entry contains "NOSUCH", so all three are included.
                    Arguments.of("NOSUCH", List.of("2.5.4.100", "2.5.4.101", "2.5.4.102"))
            );
        }

        @ParameterizedTest(name = "[{index}] NOT_CONTAINS {0} expects OIDs {1}")
        @MethodSource("altCodesNotContainsMultiValueArgs")
        void filterByAltCodes_notContains_multiValue(List<String> values, Set<String> expectedOids) {
            Assertions.assertEquals(expectedOids, new HashSet<>(searchOids(FilterConditionOperator.NOT_CONTAINS, values)));
        }

        static Stream<Arguments> altCodesNotContainsMultiValueArgs() {
            return Stream.of(
                    // multiCode matches "FI", singleCode matches "LON"; only empty-array entry survives.
                    Arguments.of(List.of("FI", "LON"), Set.of("2.5.4.102")),
                    Arguments.of(List.of("ZZZ", "YYY"), Set.of("2.5.4.100", "2.5.4.101", "2.5.4.102"))
            );
        }

        // ─────────────────────────────────────────────
        // Helpers
        // ─────────────────────────────────────────────

        private List<String> searchOids(FilterConditionOperator operator, String value) {
            SearchRequestDto request = new SearchRequestDto();
            request.setFilters(List.of(
                    new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY,
                            FilterField.OID_ENTRY_ALT_CODES.name(), operator, value)));
            CustomOidEntryListResponseDto response = customOidEntryService.listCustomOidEntries(request);
            return response.getOidEntries().stream()
                    .map(item -> item.getOid())
                    .toList();
        }

        private List<String> searchOids(FilterConditionOperator operator, List<String> values) {
            SearchRequestDto request = new SearchRequestDto();
            request.setFilters(List.of(
                    new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY,
                            FilterField.OID_ENTRY_ALT_CODES.name(), operator, new ArrayList<>(values))));
            CustomOidEntryListResponseDto response = customOidEntryService.listCustomOidEntries(request);
            return response.getOidEntries().stream()
                    .map(item -> item.getOid())
                    .toList();
        }

        private RdnAttributeTypeCustomOidEntry rdnEntry(String oid, String displayName, String code, List<String> altCodes) {
            RdnAttributeTypeCustomOidEntry entry = new RdnAttributeTypeCustomOidEntry();
            entry.setOid(oid);
            entry.setCategory(OidCategory.RDN_ATTRIBUTE_TYPE);
            entry.setDisplayName(displayName);
            entry.setDescription("test entry");
            entry.setCode(code);
            entry.setAltCodes(altCodes);
            return customOidEntryRepository.save(entry);
        }
    }

    /**
     * Parameterized integration tests for the {@code CONNECTOR_FEATURES} filter field.
     *
     * <p>Three connectors are created before each test:
     * <ul>
     *   <li>{@value #NAME_STATELESS}  — features = [STATELESS]</li>
     *   <li>{@value #NAME_MULTI_FLAG} — features = [STATELESS, OPEN_METRICS]</li>
     *   <li>{@value #NAME_NO_FLAG}    — features = [] (empty array)</li>
     * </ul>
     */
    @Nested
    class ConnectorFeaturesFilterTest {

        static final String NAME_STATELESS = "test-stateless";
        static final String NAME_MULTI_FLAG = "test-multi-flag";
        static final String NAME_NO_FLAG = "test-no-flag";

        @Autowired
        private ConnectorService connectorService;

        @Autowired
        private ConnectorRepository connectorRepository;

        @Autowired
        private ConnectorInterfaceRepository connectorInterfaceRepository;

        @BeforeEach
        void setUpConnectors() {
            saveConnector(NAME_STATELESS, List.of(FeatureFlag.STATELESS));
            saveConnector(NAME_MULTI_FLAG, List.of(FeatureFlag.STATELESS, FeatureFlag.OPEN_METRICS));
            saveConnector(NAME_NO_FLAG, new ArrayList<>());
        }

        // ─────────────────────────────────────────────
        // EQUALS
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] EQUALS ''{0}'' expects connectors {1}")
        @MethodSource("equalsArgs")
        void filterByFeatures_equals(String featureName, Set<String> expectedNames) {
            Set<String> names = searchConnectorNames(FilterConditionOperator.EQUALS, featureName);
            Assertions.assertEquals(expectedNames, names);
        }

        static Stream<Arguments> equalsArgs() {
            return Stream.of(
                    Arguments.of("stateless", Set.of(NAME_STATELESS, NAME_MULTI_FLAG)),
                    Arguments.of("openMetrics", Set.of(NAME_MULTI_FLAG)),
                    Arguments.of("timestamping", Set.of())
            );
        }

        // ─────────────────────────────────────────────
        // NOT_EQUALS
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] NOT_EQUALS ''{0}'' expects connectors {1}")
        @MethodSource("notEqualsArgs")
        void filterByFeatures_notEquals(String featureName, Set<String> expectedNames) {
            Set<String> names = searchConnectorNames(FilterConditionOperator.NOT_EQUALS, featureName);
            Assertions.assertEquals(expectedNames, names);
        }

        static Stream<Arguments> notEqualsArgs() {
            return Stream.of(
                    // Both stateless and multi-flag contain STATELESS → only no-flag survives.
                    Arguments.of("stateless", Set.of(NAME_NO_FLAG)),
                    // Only multi-flag contains OPEN_METRICS → stateless and no-flag survive.
                    Arguments.of("openMetrics", Set.of(NAME_STATELESS, NAME_NO_FLAG)),
                    // No connector contains TIMESTAMPING → all three survive.
                    Arguments.of("timestamping", Set.of(NAME_STATELESS, NAME_MULTI_FLAG, NAME_NO_FLAG))
            );
        }

        // ─────────────────────────────────────────────
        // CONTAINS
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] CONTAINS ''{0}'' expects connectors {1}")
        @MethodSource("containsArgs")
        void filterByFeatures_contains(String featureName, Set<String> expectedNames) {
            Set<String> names = searchConnectorNames(FilterConditionOperator.CONTAINS, featureName);
            Assertions.assertEquals(expectedNames, names);
        }

        static Stream<Arguments> containsArgs() {
            return Stream.of(
                    Arguments.of("stateless", Set.of(NAME_STATELESS, NAME_MULTI_FLAG)),
                    Arguments.of("openMetrics", Set.of(NAME_MULTI_FLAG)),
                    Arguments.of("timestamping", Set.of())
            );
        }

        // ─────────────────────────────────────────────
        // NOT_CONTAINS
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] NOT_CONTAINS ''{0}'' expects connectors {1}")
        @MethodSource("notContainsArgs")
        void filterByFeatures_notContains(String featureName, Set<String> expectedNames) {
            Set<String> names = searchConnectorNames(FilterConditionOperator.NOT_CONTAINS, featureName);
            Assertions.assertEquals(expectedNames, names);
        }

        static Stream<Arguments> notContainsArgs() {
            return Stream.of(
                    // Connectors whose features array does NOT contain STATELESS.
                    // no-flag has empty array → passes NOT_CONTAINS.
                    Arguments.of("stateless", Set.of(NAME_NO_FLAG)),
                    Arguments.of("openMetrics", Set.of(NAME_STATELESS, NAME_NO_FLAG)),
                    Arguments.of("timestamping", Set.of(NAME_STATELESS, NAME_MULTI_FLAG, NAME_NO_FLAG))
            );
        }

        // ─────────────────────────────────────────────
        // EMPTY / NOT_EMPTY
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] {0} expects connectors {1}")
        @MethodSource("emptyArgs")
        void filterByFeatures_emptyAndNotEmpty(FilterConditionOperator operator, Set<String> expectedNames) {
            Set<String> names = searchConnectorNames(operator, null);
            Assertions.assertEquals(expectedNames, names);
        }

        static Stream<Arguments> emptyArgs() {
            return Stream.of(
                    Arguments.of(FilterConditionOperator.EMPTY, Set.of(NAME_NO_FLAG)),
                    Arguments.of(FilterConditionOperator.NOT_EMPTY, Set.of(NAME_STATELESS, NAME_MULTI_FLAG))
            );
        }

        // ─────────────────────────────────────────────
        // NOT_EQUALS / NOT_CONTAINS with multiple connector interfaces
        // ─────────────────────────────────────────────

        @ParameterizedTest(name = "[{index}] {0} excludes connector if any interface contains the value")
        @MethodSource("notEqualsAndNotContainsArgs")
        void connectorWithMultipleInterfaces_excludedIfAnyInterfaceContainsValue(FilterConditionOperator operator) {
            // Connector with two interfaces: one has STATELESS, the other has OPEN_METRICS.
            String name = "test-multi-iface-" + operator.name().toLowerCase();
            Connector connector = new Connector();
            connector.setName(name);
            connector.setUrl("http://localhost:0/" + name);
            connector.setVersion(ConnectorVersion.V2);
            connector.setStatus(ConnectorStatus.CONNECTED);
            connector.setAuthType(AuthType.NONE);
            connector = connectorRepository.save(connector);

            ConnectorInterfaceEntity iface1 = new ConnectorInterfaceEntity();
            iface1.setConnectorUuid(connector.getUuid());
            iface1.setInterfaceCode(ConnectorInterface.AUTHORITY);
            iface1.setVersion("v2");
            iface1.setFeatures(List.of(FeatureFlag.STATELESS));
            connectorInterfaceRepository.save(iface1);

            ConnectorInterfaceEntity iface2 = new ConnectorInterfaceEntity();
            iface2.setConnectorUuid(connector.getUuid());
            iface2.setInterfaceCode(ConnectorInterface.METRICS);
            iface2.setVersion("v2");
            iface2.setFeatures(List.of(FeatureFlag.OPEN_METRICS));
            connectorInterfaceRepository.save(iface2);

            // STATELESS is in iface1 → excluded even though iface2 does not have it
            Assertions.assertFalse(
                    searchConnectorNames(operator, "stateless").contains(name),
                    "Connector must be excluded: iface1 contains STATELESS");

            // OPEN_METRICS is in iface2 → excluded even though iface1 does not have it
            Assertions.assertFalse(
                    searchConnectorNames(operator, "openMetrics").contains(name),
                    "Connector must be excluded: iface2 contains OPEN_METRICS");

            // No interface has TIMESTAMPING → connector must be included
            Assertions.assertTrue(
                    searchConnectorNames(operator, "timestamping").contains(name),
                    "Connector must be included: no interface contains TIMESTAMPING");
        }

        static Stream<Arguments> notEqualsAndNotContainsArgs() {
            return Stream.of(
                    Arguments.of(FilterConditionOperator.NOT_EQUALS),
                    Arguments.of(FilterConditionOperator.NOT_CONTAINS)
            );
        }

        // ─────────────────────────────────────────────
        // Helpers
        // ─────────────────────────────────────────────

        private Set<String> searchConnectorNames(FilterConditionOperator operator, String featureName) {
            SearchRequestDto request = new SearchRequestDto();
            request.setFilters(List.of(
                    new SearchFilterRequestDtoDummy(FilterFieldSource.PROPERTY,
                            FilterField.CONNECTOR_FEATURES.name(), operator, featureName)));
            PaginationResponseDto<ConnectorDto> response =
                    connectorService.listConnectors(SecurityFilter.create(), request);
            return response.getItems().stream()
                    .map(ConnectorDto::getName)
                    .collect(Collectors.toSet());
        }

        private void saveConnector(String name, List<FeatureFlag> features) {
            Connector connector = new Connector();
            connector.setName(name);
            connector.setUrl("http://localhost:0/" + name);
            connector.setVersion(ConnectorVersion.V2);
            connector.setStatus(ConnectorStatus.CONNECTED);
            connector.setAuthType(AuthType.NONE);
            connector = connectorRepository.save(connector);

            ConnectorInterfaceEntity iface = new ConnectorInterfaceEntity();
            iface.setConnectorUuid(connector.getUuid());
            iface.setInterfaceCode(ConnectorInterface.AUTHORITY);
            iface.setVersion("v2");
            iface.setFeatures(features);
            connectorInterfaceRepository.save(iface);
        }
    }
}
