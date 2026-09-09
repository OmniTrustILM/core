package com.otilm.core.integration.search;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.common.PaginationResponseDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.content.TextAttributeContentV3;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.discovery.DiscoveryStatus;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.api.model.core.secret.SecretDto;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Discovery;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.SecretVersion;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.repository.DiscoveryRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.SecretVersionRepository;
import com.otilm.core.dao.repository.VaultInstanceRepository;
import com.otilm.core.dao.repository.VaultProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.DiscoveryExternalService;
import com.otilm.core.service.SecretExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * Ordering by an attribute-sourced column.
 *
 * <p>
 * Filtering an attribute is an order-agnostic {@code EXISTS} subquery, so it yields nothing to order by. These cases
 * cover the correlated scalar subquery that does: that a listing orders by the stored value rather than by the raw
 * document, that an object holding no value is kept rather than dropped, and that a multi-valued attribute resolves to
 * one key instead of multiplying the row.
 */
class AttributeColumnSortITest extends BaseSpringBootTest {

    private static final String ENVIRONMENT = "environment";

    /** Distinct from the discovery probe: one definition per name is what the content write resolves by. */
    private static final String SECRET_ENVIRONMENT = "secret-environment";

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
        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(pageNumber);
        request.setItemsPerPage(itemsPerPage);
        request.setSort(new SearchSortRequestDto(FilterFieldSource.CUSTOM, fieldIdentifier, direction));

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
     * A multi-valued attribute has as many values as the object stores, which would leave the key ambiguous. It
     * resolves to the value at the lowest {@code item_order} - the one the cell shows first - and the row appears once
     * rather than once per value.
     */
    @Test
    void aMultiValuedAttributeSortsOnItsFirstStoredValue() throws Exception {
        seedDiscovery("multi", "aaa", "zzz");

        Assertions
                .assertEquals(List.of("multi", "second-created", "third-created", "first-created"),
                        listNames(SortDirection.ASC, 1, 10));
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

        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(1);
        request.setItemsPerPage(10);
        request
                .setSort(new SearchSortRequestDto(FilterFieldSource.CUSTOM,
                        SECRET_ENVIRONMENT + "|" + AttributeContentType.TEXT.name(), SortDirection.ASC));

        PaginationResponseDto<SecretDto> response = secretService.listSecrets(request, SecurityFilter.create());

        Assertions
                .assertEquals(List.of("secret-second", "secret-third", "secret-first"),
                        response.getItems().stream().map(SecretDto::getName).toList());
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

    private void seedSecret(String name, VaultProfile vaultProfile, UUID secretDefinitionUuid, String environmentValue)
            throws Exception {
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
    }
}
