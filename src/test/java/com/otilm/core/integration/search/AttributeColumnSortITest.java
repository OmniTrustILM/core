package com.otilm.core.integration.search;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.DateTimeAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.api.model.core.secret.SecretDto;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.SecretVersion;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.repository.AttributeDefinitionRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.SecretVersionRepository;
import com.otilm.core.dao.repository.VaultInstanceRepository;
import com.otilm.core.dao.repository.VaultProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.SecretExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.SqlCapture;
import com.otilm.core.util.SqlShape;
import java.nio.charset.StandardCharsets;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Ordering by an attribute-sourced column.
 *
 * <p>
 * Filtering an attribute is an order-agnostic {@code EXISTS} subquery, so it yields nothing to order by. These cases
 * cover the key table that does: that a listing orders by the stored value rather than by the raw document, that an
 * object holding no value is kept rather than dropped, and that a multi-valued attribute resolves to one key - its
 * smallest value ascending, its largest descending - instead of multiplying the row.
 */
class AttributeColumnSortITest extends BaseSpringBootTest {

    private static final String ENVIRONMENT = "environment";

    /** Distinct from the discovery probe: one definition per name is what the content write resolves by. */
    private static final String SECRET_ENVIRONMENT = "secret-environment";

    private static final String PRIORITY = "priority";
    private static final String DUE = "due";

    @Autowired
    private DiscoveryExternalService discoveryService;

    @Autowired
    private DiscoveryRepository discoveryRepository;

    @Autowired
    private SecretExternalService secretService;

    @Autowired
    private SecretRepository secretRepository;

    @Autowired
    private SecretVersionRepository secretVersionRepository;

    @Autowired
    private VaultProfileRepository vaultProfileRepository;

    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private ResourceObjectAssociationService resourceObjectAssociationService;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private AttributeDefinitionRepository attributeDefinitionRepository;

    private UUID definitionUuid;

    @BeforeEach
    void loadData() throws Exception {
        definitionUuid = registerCustomAttribute();

        // Seeded so the attribute order is neither the creation order nor the name order: a sort that never reached
        // the query, or one that ordered by the wrong column, cannot produce the expected sequence by accident.
        seedDiscovery("first-created", "charlie");
        seedDiscovery("second-created", "alpha");
        seedDiscovery("third-created", "bravo");
    }

    private UUID registerCustomAttribute() throws Exception {
        return registerCustomAttribute(ENVIRONMENT, AttributeContentType.TEXT, true, Resource.DISCOVERY);
    }

    private UUID registerCustomAttribute(String name, AttributeContentType contentType, boolean visible,
            Resource resource) throws Exception {
        CustomAttributeV3 attribute = new CustomAttributeV3();
        UUID uuid = UUID.randomUUID();
        attribute.setUuid(uuid.toString());
        attribute.setName(name);
        attribute.setType(AttributeType.CUSTOM);
        attribute.setContentType(contentType);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel(name);
        properties.setVisible(visible);
        attribute.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(attribute, List.of(resource));
        return uuid;
    }

    private Discovery seedDiscovery(String name, String... environmentValues) throws Exception {
        Discovery discovery = new Discovery();
        discovery.setName(name);
        discovery.setStatus(DiscoveryStatus.COMPLETED);
        discovery.setConnectorStatus(DiscoveryStatus.COMPLETED);
        // The list DTO reads both, so a discovery without them cannot be mapped for the response.
        discovery.setConnectorUuid(UUID.randomUUID());
        discovery.setConnectorName("attribute-sort-connector");
        discovery = discoveryRepository.save(discovery);

        if (environmentValues.length > 0) {
            attributeEngine
                    .updateObjectCustomAttributesContent(Resource.DISCOVERY, discovery.getUuid(),
                            List.of(customContent(environmentValues)));
        }
        return discovery;
    }

    private RequestAttributeV3 customContent(String... values) {
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(definitionUuid);
        requestAttribute.setName(ENVIRONMENT);
        List<BaseAttributeContentV3<?>> content = new ArrayList<>();
        for (String value : values) {
            content.add(new TextAttributeContentV3(null, value));
        }
        requestAttribute.setContent(content);
        return requestAttribute;
    }

    private List<String> listNames(SortDirection direction, int pageNumber, int itemsPerPage) {
        return listNamesSortedBy(ENVIRONMENT + "|" + AttributeContentType.TEXT.name(), direction, pageNumber,
                itemsPerPage);
    }

    private List<String> listNamesSortedBy(String fieldIdentifier, SortDirection direction, int pageNumber,
            int itemsPerPage) {
        return listNamesSortedBy(FilterFieldSource.CUSTOM, fieldIdentifier, direction, pageNumber, itemsPerPage);
    }

    private List<String> listNamesSortedBy(FilterFieldSource source, String fieldIdentifier, SortDirection direction) {
        return listNamesSortedBy(source, fieldIdentifier, direction, 1, 50);
    }

    private List<String> listNamesSortedBy(FilterFieldSource source, String fieldIdentifier, SortDirection direction,
            int pageNumber, int itemsPerPage) {
        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(pageNumber);
        request.setItemsPerPage(itemsPerPage);
        request.setSort(new SearchSortRequestDto(source, fieldIdentifier, direction));

        return discoveryService
                .listDiscoveries(SecurityFilter.create(), request)
                .getDiscoveries()
                .stream()
                .map(discovery -> discovery.getName())
                .toList();
    }

    @Test
    void ordersByTheAttributeValueAscending() {
        Assertions
                .assertEquals(List.of("second-created", "third-created", "first-created"),
                        listNames(SortDirection.ASC, 1, 10));
    }

    @Test
    void ordersByTheAttributeValueDescending() {
        Assertions
                .assertEquals(List.of("first-created", "third-created", "second-created"),
                        listNames(SortDirection.DESC, 1, 10));
    }

    @Test
    void orderingSpansTheWholeResultSetAcrossAPageBoundary() {
        List<String> paged = new ArrayList<>();
        paged.addAll(listNames(SortDirection.ASC, 1, 2));
        paged.addAll(listNames(SortDirection.ASC, 2, 2));

        Assertions.assertEquals(List.of("second-created", "third-created", "first-created"), paged);
    }

    /**
     * An object with no value for the sorted attribute yields a null key. It has to be kept and ordered consistently:
     * last in both directions, so reversing the sort does not lead the page with the rows the column cannot show.
     */
    @Test
    void anObjectWithoutAValueSortsLastInBothDirections() throws Exception {
        seedDiscovery("no-value");

        Assertions
                .assertEquals(List.of("second-created", "third-created", "first-created", "no-value"),
                        listNames(SortDirection.ASC, 1, 10));
        Assertions
                .assertEquals(List.of("first-created", "third-created", "second-created", "no-value"),
                        listNames(SortDirection.DESC, 1, 10));
    }

    /**
     * The sort key is computed once for the query, as a table of one key per object joined to the listing, instead of a
     * subquery run for every row under a GROUP BY over the whole result.
     */
    @Test
    void anAttributeSortJoinsOneKeyPerObjectInsteadOfGrouping() throws Exception {
        String page = SqlShape.pageQuery(SqlCapture.during(() -> listNames(SortDirection.ASC, 1, 10)).statements());

        assertThat(SqlShape.hasDerivedJoin(page)).describedAs(page).isTrue();
        assertThat(SqlShape.groupsByRootUuid(page)).describedAs(page).isFalse();
        assertThat(SqlShape.hasScalarSortSubquery(page)).describedAs(page).isFalse();
    }

    /**
     * A multi-valued attribute sorts on its smallest value ascending: stored "zulu" first, it still leads the page by
     * "able", and the row appears once rather than once per value.
     */
    @Test
    void aMultiValuedAttributeSortsOnItsSmallestValueAscending() throws Exception {
        seedDiscovery("multi", "zulu", "able");

        Assertions
                .assertEquals(List.of("multi", "second-created", "third-created", "first-created"),
                        listNames(SortDirection.ASC, 1, 10));
    }

    /** And on its largest value descending: stored "able" first, it leads the reversed page by "zulu". */
    @Test
    void aMultiValuedAttributeSortsOnItsLargestValueDescending() throws Exception {
        seedDiscovery("multi", "able", "zulu");

        Assertions
                .assertEquals(List.of("multi", "first-created", "third-created", "second-created"),
                        listNames(SortDirection.DESC, 1, 10));
    }

    /**
     * Walking every page returns each object exactly once, in the order one unpaged request gives, and objects without
     * a value close the walk in both directions.
     */
    @Test
    void walkingEveryPageReturnsEachObjectOnceInBothDirections() throws Exception {
        seedDiscovery("multi", "zulu", "able");
        seedDiscovery("no-value");
        seedDiscovery("delta-only", "delta");

        List<String> ascending = List
                .of("multi", "second-created", "third-created", "first-created", "delta-only", "no-value");
        List<String> descending = List
                .of("multi", "delta-only", "first-created", "third-created", "second-created", "no-value");
        for (SortDirection direction : SortDirection.values()) {
            List<String> walked = new ArrayList<>();
            for (int page = 1; page <= 3; page++) {
                walked.addAll(listNames(direction, page, 2));
            }
            Assertions.assertEquals(direction == SortDirection.ASC ? ascending : descending, walked);
        }
    }

    @Test
    void aRestrictedUserSeesTheirObjectsInKeyOrder() throws Exception {
        Discovery visibleFirst = seedDiscovery("visible-zulu", "zulu");
        Discovery visibleSecond = seedDiscovery("visible-able", "able");
        seedDiscovery("hidden-mike", "mike");
        restrictObjectAccess(Resource.DISCOVERY, ResourceAction.LIST,
                List.of(visibleFirst.getUuid(), visibleSecond.getUuid()));

        Assertions.assertEquals(List.of("visible-able", "visible-zulu"), listNames(SortDirection.ASC, 1, 10));
    }

    /**
     * Two connectors can register metadata under one name; the field collapses them, and so does its key: an object
     * holding a value under each definition sorts by the smallest of them ascending and the largest descending.
     * {@code mixed} keeps its larger value under the definition whose uuid sorts first and {@code spread} its smaller
     * one, so a key that read one definition only, or the first value in definition order, would misplace one of them
     * in each direction.
     */
    @Test
    void metadataSharedByTwoDefinitionsSortsAcrossBoth() throws Exception {
        Connector first = newConnector("region-connector-1");
        Connector second = newConnector("region-connector-2");
        // Both definitions exist before any value is placed, because which one sorts first is known only then.
        Discovery middle = seedDiscovery("middle");
        storeRegion(first, middle.getUuid(), "mike");
        storeRegion(second, middle.getUuid(), "mike");
        boolean firstSortsFirst = regionDefinition(first).toString().compareTo(regionDefinition(second).toString()) < 0;
        Connector sortsFirst = firstSortsFirst ? first : second;
        Connector sortsLast = firstSortsFirst ? second : first;

        Discovery mixed = seedDiscovery("mixed");
        storeRegion(sortsFirst, mixed.getUuid(), "yankee");
        storeRegion(sortsLast, mixed.getUuid(), "bravo");
        Discovery spread = seedDiscovery("spread");
        storeRegion(sortsFirst, spread.getUuid(), "alpha");
        storeRegion(sortsLast, spread.getUuid(), "zulu");

        String region = "region|" + AttributeContentType.STRING.name();
        Assertions
                .assertEquals(List.of("spread", "mixed", "middle"),
                        listNamesSortedBy(FilterFieldSource.META, region, SortDirection.ASC).subList(0, 3));
        Assertions
                .assertEquals(List.of("spread", "mixed", "middle"),
                        listNamesSortedBy(FilterFieldSource.META, region, SortDirection.DESC).subList(0, 3));
    }

    /**
     * A typed attribute sorts by its value rather than by its text: the key table casts the stored value before it
     * takes the smallest or the largest. As text, "10" would lead ascending and "9" descending.
     */
    @Test
    void anIntegerAttributeSortsByNumberNotByText() throws Exception {
        UUID priority = registerCustomAttribute(PRIORITY, AttributeContentType.INTEGER, true, Resource.DISCOVERY);
        storeCustomContent(seedDiscovery("priority-nine").getUuid(), priority, PRIORITY,
                new IntegerAttributeContentV3(9));
        storeCustomContent(seedDiscovery("priority-ten").getUuid(), priority, PRIORITY,
                new IntegerAttributeContentV3(10));
        storeCustomContent(seedDiscovery("priority-twelve-and-seven").getUuid(), priority, PRIORITY,
                new IntegerAttributeContentV3(12), new IntegerAttributeContentV3(7));
        String field = PRIORITY + "|" + AttributeContentType.INTEGER.name();

        Assertions
                .assertEquals(List.of("priority-twelve-and-seven", "priority-nine", "priority-ten"),
                        listNamesSortedBy(field, SortDirection.ASC, 1, 10).subList(0, 3));
        Assertions
                .assertEquals(List.of("priority-twelve-and-seven", "priority-ten", "priority-nine"),
                        listNamesSortedBy(field, SortDirection.DESC, 1, 10).subList(0, 3));
    }

    /**
     * A date-time attribute sorts by the instant it names. Noon at UTC+5 is earlier than nine at UTC, which its text
     * would place after it.
     */
    @Test
    void aDateTimeAttributeSortsByInstant() throws Exception {
        UUID due = registerCustomAttribute(DUE, AttributeContentType.DATETIME, true, Resource.DISCOVERY);
        storeCustomContent(seedDiscovery("due-nine-utc").getUuid(), due, DUE,
                new DateTimeAttributeContentV3(ZonedDateTime.of(2026, 3, 1, 9, 0, 0, 0, ZoneOffset.UTC)));
        storeCustomContent(seedDiscovery("due-noon-plus-five").getUuid(), due, DUE,
                new DateTimeAttributeContentV3(ZonedDateTime.of(2026, 3, 1, 12, 0, 0, 0, ZoneOffset.ofHours(5))));
        String field = DUE + "|" + AttributeContentType.DATETIME.name();

        Assertions
                .assertEquals(List.of("due-noon-plus-five", "due-nine-utc"),
                        listNamesSortedBy(field, SortDirection.ASC, 1, 10).subList(0, 2));
        Assertions
                .assertEquals(List.of("due-nine-utc", "due-noon-plus-five"),
                        listNamesSortedBy(field, SortDirection.DESC, 1, 10).subList(0, 2));
    }

    private void storeCustomContent(UUID discoveryUuid, UUID definitionUuid, String attributeName,
            BaseAttributeContentV3<?>... values) throws Exception {
        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(definitionUuid);
        requestAttribute.setName(attributeName);
        requestAttribute.setContent(List.of(values));
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.DISCOVERY, discoveryUuid, List.of(requestAttribute));
    }

    private Connector newConnector(String name) {
        Connector connector = new Connector();
        connector.setName(name);
        connector.setUrl("http://localhost:0/" + name);
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
        return connectorRepository.saveAndFlush(connector);
    }

    private void storeRegion(Connector connector, UUID discoveryUuid, String value) throws Exception {
        MetadataAttributeV3 meta = new MetadataAttributeV3();
        // One definition per connector: the metadata write resolves the definition by its uuid.
        meta.setUuid(regionAttributeUuid(connector).toString());
        meta.setName("region");
        meta.setType(AttributeType.META);
        meta.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel("Region");
        properties.setVisible(true);
        properties.setGlobal(false);
        meta.setProperties(properties);
        meta.setContent(List.of(new StringAttributeContentV3(value)));
        attributeEngine
                .updateMetadataAttribute(meta,
                        ObjectAttributeContentInfo
                                .builder(Resource.DISCOVERY, discoveryUuid)
                                .connector(connector.getUuid())
                                .build());
    }

    private static UUID regionAttributeUuid(Connector connector) {
        return UUID.nameUUIDFromBytes(("region-" + connector.getName()).getBytes(StandardCharsets.UTF_8));
    }

    /** The uuid of the definition a connector's region values are stored under, which decides definition order. */
    private UUID regionDefinition(Connector connector) {
        return attributeDefinitionRepository
                .findByConnectorUuidAndAttributeUuid(connector.getUuid(), regionAttributeUuid(connector))
                .orElseThrow()
                .getUuid();
    }

    /**
     * A field the catalogue reports as {@code sortable:false} is refused rather than answered with a page ordered by
     * something the response would never show. Secret content is the clearest case: the catalogue withholds it as a
     * column, so there is nothing for an ordering on it to be an ordering of.
     */
    @Test
    void aSecretAttributeCannotBeOrderedOn() throws Exception {
        registerCustomAttribute("sort-secret-probe", AttributeContentType.SECRET, true, Resource.DISCOVERY);

        ValidationException e = Assertions
                .assertThrows(ValidationException.class,
                        () -> listNamesSortedBy("sort-secret-probe|" + AttributeContentType.SECRET.name(),
                                SortDirection.ASC, 1, 10));
        Assertions.assertTrue(e.getMessage().contains("cannot be used to order"));
    }

    /** An attribute the definition says not to show a user is not one a page may be ordered by either. */
    @Test
    void aHiddenAttributeCannotBeOrderedOn() throws Exception {
        registerCustomAttribute("sort-hidden-probe", AttributeContentType.TEXT, false, Resource.DISCOVERY);

        Assertions
                .assertThrows(ValidationException.class,
                        () -> listNamesSortedBy("sort-hidden-probe|" + AttributeContentType.TEXT.name(),
                                SortDirection.ASC, 1, 10));
    }

    /**
     * A file cell renders the file's name and media type, and a resource cell the referenced object's name - neither is
     * the reference a sort key reads - so the catalogue withholds ordering on them and the request is refused.
     */
    @Test
    void anAttributeWhoseCellIsNotItsSortKeyCannotBeOrderedOn() throws Exception {
        registerCustomAttribute("sort-file-probe", AttributeContentType.FILE, true, Resource.DISCOVERY);

        Assertions
                .assertThrows(ValidationException.class,
                        () -> listNamesSortedBy("sort-file-probe|" + AttributeContentType.FILE.name(),
                                SortDirection.ASC, 1, 10));
    }

    /**
     * An identifier naming no registered definition would otherwise yield an all-null key and a silently unordered page
     * - the failure the property path already refuses.
     */
    @Test
    void anIdentifierNamingNoRegisteredAttributeIsRejected() {
        Assertions
                .assertThrows(ValidationException.class,
                        () -> listNamesSortedBy("not-registered|" + AttributeContentType.TEXT.name(), SortDirection.ASC,
                                1, 10));
    }

    /**
     * Ordering must not read further than the projection that renders a column does.
     *
     * <p>
     * With the caller restricted to an allow-list this definition is not on, the projection blanks the column - so the
     * sort key has to come back null for every row too. If it did not, reversing the sort would reorder the page by
     * values the caller may not read, which is a comparative oracle over exactly the content the allow-list withholds.
     * With every key null the uuid tie-break decides both directions, so the two pages are identical rather than
     * reversed.
     */
    @Test
    void anAttributeTheCallerMayNotReadCannotOrderThePage() {
        restrictObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS);

        List<String> ascending = listNames(SortDirection.ASC, 1, 10);
        List<String> descending = listNames(SortDirection.DESC, 1, 10);

        Assertions.assertEquals(3, ascending.size());
        Assertions.assertEquals(ascending, descending);
    }

    /** The values do decide the order when the caller may read them, which is what the case above removes. */
    @Test
    void anAttributeTheCallerMayReadOrdersThePage() {
        Assertions.assertEquals(listNames(SortDirection.ASC, 1, 10).reversed(), listNames(SortDirection.DESC, 1, 10));
    }

    /**
     * The secret listing carries attribute columns like any other, and its entity had no resource mapping of its own -
     * the correlation the sort key builds resolved to {@code objectType = null}, matched no stored row, and left every
     * key null while the catalogue advertised the field as sortable.
     */
    @Test
    void ordersASecretListingByTheAttributeValue() throws Exception {
        UUID secretDefinitionUuid = registerCustomAttribute(SECRET_ENVIRONMENT, AttributeContentType.TEXT, true,
                Resource.SECRET);
        VaultProfile vaultProfile = seedVaultProfile();

        seedSecret("secret-first", vaultProfile, secretDefinitionUuid, "charlie");
        seedSecret("secret-second", vaultProfile, secretDefinitionUuid, "alpha");
        seedSecret("secret-third", vaultProfile, secretDefinitionUuid, "bravo");

        Assertions.assertEquals(List.of("secret-second", "secret-third", "secret-first"), listSecretNames());
    }

    /**
     * A restricted user reaches a secret through each of their groups it sits in, and the access rule joins those
     * groups, so the listing sees the secret once per group. The key table must not turn that join into a repeated row.
     */
    @Test
    void anObjectInTwoOfTheCallersGroupsIsListedOnce() throws Exception {
        UUID secretDefinitionUuid = registerCustomAttribute(SECRET_ENVIRONMENT, AttributeContentType.TEXT, true,
                Resource.SECRET);
        VaultProfile vaultProfile = seedVaultProfile();
        Secret inBothGroups = seedSecret("secret-in-both-groups", vaultProfile, secretDefinitionUuid, "alpha");
        Secret inOneGroup = seedSecret("secret-in-one-group", vaultProfile, secretDefinitionUuid, "bravo");
        seedSecret("secret-in-no-group", vaultProfile, secretDefinitionUuid, "charlie");
        Group first = seedGroup("first-group");
        Group second = seedGroup("second-group");
        resourceObjectAssociationService.addGroup(Resource.SECRET, inBothGroups.getUuid(), first.getUuid());
        resourceObjectAssociationService.addGroup(Resource.SECRET, inBothGroups.getUuid(), second.getUuid());
        resourceObjectAssociationService.addGroup(Resource.SECRET, inOneGroup.getUuid(), second.getUuid());
        restrictObjectAccess(Resource.SECRET, ResourceAction.LIST, List.of());
        restrictObjectAccess(Resource.GROUP, ResourceAction.MEMBERS, List.of(first.getUuid(), second.getUuid()));

        Assertions.assertEquals(List.of("secret-in-both-groups", "secret-in-one-group"), listSecretNames());
    }

    private List<String> listSecretNames() {
        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(1);
        request.setItemsPerPage(10);
        request
                .setSort(new SearchSortRequestDto(FilterFieldSource.CUSTOM,
                        SECRET_ENVIRONMENT + "|" + AttributeContentType.TEXT.name(), SortDirection.ASC));

        PaginationResponseDto<SecretDto> response = secretService.listSecrets(request, SecurityFilter.create());
        return response.getItems().stream().map(SecretDto::getName).toList();
    }

    private Group seedGroup(String name) {
        Group group = new Group();
        group.setName(name);
        return groupRepository.save(group);
    }

    private VaultProfile seedVaultProfile() {
        VaultInstance vaultInstance = new VaultInstance();
        vaultInstance.setName("attribute-sort-vault");
        vaultInstanceRepository.saveAndFlush(vaultInstance);

        VaultProfile vaultProfile = new VaultProfile();
        vaultProfile.setName("attribute-sort-vault-profile");
        vaultProfile.setVaultInstance(vaultInstance);
        vaultProfile.setVaultInstanceUuid(vaultInstance.getUuid());
        vaultProfile.setEnabled(true);
        return vaultProfileRepository.saveAndFlush(vaultProfile);
    }

    private Secret seedSecret(String name, VaultProfile vaultProfile, UUID secretDefinitionUuid,
            String environmentValue) throws Exception {
        SecretVersion version = new SecretVersion();
        version.setVersion(1);
        version.setVaultProfile(vaultProfile);
        version.setFingerprint(name + "-fingerprint");
        secretVersionRepository.saveAndFlush(version);

        Secret secret = new Secret();
        secret.setName(name);
        secret.setType(SecretType.BASIC_AUTH);
        secret.setState(SecretState.ACTIVE);
        secret.setSourceVaultProfile(vaultProfile);
        secret.setSourceVaultProfileUuid(vaultProfile.getUuid());
        secret.setEnabled(true);
        secret.setLatestVersion(version);
        secret = secretRepository.saveAndFlush(secret);

        RequestAttributeV3 requestAttribute = new RequestAttributeV3();
        requestAttribute.setUuid(secretDefinitionUuid);
        requestAttribute.setName(SECRET_ENVIRONMENT);
        requestAttribute.setContent(List.of(new TextAttributeContentV3(null, environmentValue)));
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.SECRET, secret.getUuid(), List.of(requestAttribute));
        return secret;
    }
}
