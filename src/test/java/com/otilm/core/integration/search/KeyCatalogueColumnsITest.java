package com.otilm.core.integration.search;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyItemDto;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SearchFieldDataDto;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.WireMockPorts;
import com.otilm.core.util.seeders.CryptographicKeySeeder;
import com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;

import static com.otilm.core.integration.search.CatalogueFields.field;
import static com.otilm.core.integration.search.CatalogueFields.propertyFields;
import static com.otilm.core.util.builders.SearchFilterRequestDtoBuilder.aPropertyFilter;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The key columns the inventory renders but the catalogue did not carry.
 *
 * <p>
 * A column the catalogue does not publish can be neither picked, renamed nor sorted, however plainly the page shows it.
 * Publishing them makes them filters as well, which the keys listing had for neither field before.
 */
class KeyCatalogueColumnsITest extends BaseSpringBootTest {

    @Autowired
    private CryptographicKeyExternalService cryptographicKeyService;

    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    @Autowired
    private CryptographicKeySeeder keySeeder;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    /** The keys catalogue lists owners, so it reaches the user-management service the stub stands in for. */
    private WireMockServer authService;

    @BeforeEach
    void startAuthService() {
        authService = new WireMockServer(WireMockPorts.AUTH_SERVICE);
        authService.start();
        WireMock.configureFor("localhost", authService.port());
        authService
                .stubFor(WireMock
                        .get(WireMock.urlPathEqualTo("/auth/users"))
                        .willReturn(WireMock.okJson("{\"data\": []}")));
    }

    @AfterEach
    void stopAuthService() {
        authService.stop();
    }

    @Test
    void theCatalogueOffersTheEnabledColumn() {
        SearchFieldDataDto enabled = field(cryptographicKeyService.getSearchableFieldInformation(),
                FilterField.CKI_ENABLED.name()).orElseThrow();

        assertThat(enabled.getSortable()).isTrue();
        assertThat(enabled.getFieldLabel()).isEqualTo("Enabled");
    }

    @Test
    void theCatalogueOffersTheCreatedColumn() {
        SearchFieldDataDto created = field(cryptographicKeyService.getSearchableFieldInformation(),
                FilterField.CKI_CREATED.name()).orElseThrow();

        assertThat(created.getSortable()).isTrue();
        assertThat(created.getFieldLabel()).isEqualTo("Created At");
    }

    /**
     * The catalogue is assembled by naming fields one at a time, so a field present in {@code FilterField} and
     * forgotten there is published nowhere and nothing would report it.
     */
    @Test
    void theCatalogueCarriesEveryKeyField() {
        List<String> published = propertyFields(cryptographicKeyService.getSearchableFieldInformation())
                .stream()
                .map(SearchFieldDataDto::getFieldIdentifier)
                .toList();

        assertThat(published)
                .containsExactlyInAnyOrderElementsOf(FilterField
                        .getEnumsForResource(Resource.CRYPTOGRAPHIC_KEY)
                        .stream()
                        .map(FilterField::name)
                        .toList());
    }

    @Test
    void theListingCanBeFilteredAndOrderedByEnabled() {
        seedItem("enabled-one", true, OffsetDateTime.now().minusDays(3));
        seedItem("enabled-two", true, OffsetDateTime.now().minusDays(2));
        seedItem("disabled-one", false, OffsetDateTime.now().minusDays(1));

        assertThat(listNames(aPropertyFilter(FilterField.CKI_ENABLED, FilterConditionOperator.EQUALS, false), null))
                .containsExactly("disabled-one");
        assertThat(listNames(null, sortBy(FilterField.CKI_ENABLED, SortDirection.ASC))).startsWith("disabled-one");
        assertThat(listNames(null, sortBy(FilterField.CKI_ENABLED, SortDirection.DESC))).endsWith("disabled-one");
    }

    @Test
    void theListingCanBeFilteredAndOrderedByCreated() {
        seedItem("oldest", true, OffsetDateTime.now().minusDays(3));
        seedItem("newest", true, OffsetDateTime.now().minusDays(1));
        seedItem("middle", true, OffsetDateTime.now().minusDays(2));

        assertThat(listNames(null, sortBy(FilterField.CKI_CREATED, SortDirection.ASC)))
                .containsExactly("oldest", "middle", "newest");
        // The filter traverses the same join to the key and parses the bound as a datetime, which the sort does not.
        // The bound sits half a day from the nearest row, so no timezone the JDBC session might apply moves one
        // across it.
        assertThat(listNames(createdAfter(OffsetDateTime.now().minusHours(36)), null)).containsExactly("newest");
        assertThat(listNames(createdAfter(OffsetDateTime.now().minusHours(84)), null))
                .containsExactlyInAnyOrder("oldest", "middle", "newest");
    }

    private static SearchFilterRequestDto createdAfter(OffsetDateTime bound) {
        return aPropertyFilter(FilterField.CKI_CREATED, FilterConditionOperator.GREATER,
                bound.format(DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSXXX")));
    }

    private static SearchSortRequestDto sortBy(FilterField field, SortDirection direction) {
        return new SearchSortRequestDto(FilterFieldSource.PROPERTY, field.name(), direction);
    }

    private List<String> listNames(SearchFilterRequestDto filter, SearchSortRequestDto sort) {
        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(1);
        request.setItemsPerPage(10);
        if (filter != null) {
            request.setFilters(List.of(filter));
        }
        request.setSort(sort);

        return cryptographicKeyService
                .listCryptographicKeys(SecurityFilter.create(), request)
                .getCryptographicKeys()
                .stream()
                .map(KeyItemDto::getName)
                .toList();
    }

    private void seedItem(String name, boolean enabled, OffsetDateTime created) {
        CryptographicKey key = keySeeder.seedKey(name, null, null, KeyItemSpec.signingPrivateKey(KeyAlgorithm.RSA));
        CryptographicKeyItem item = key.getItems().iterator().next();
        item.setName(name);
        item.setEnabled(enabled);
        cryptographicKeyItemRepository.saveAndFlush(item);

        // A @CreationTimestamp cannot be set through the entity, and rows saved inside one test would otherwise share
        // the instant auditing stamps on them, leaving an ordering over equal values to the uuid tie-break.
        jdbcTemplate.update("UPDATE cryptographic_key SET i_cre = ? WHERE uuid = ?", created, key.getUuid());
    }
}
