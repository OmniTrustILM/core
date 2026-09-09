package com.otilm.core.integration.search;

import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.certificate.SearchSortRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyItemDto;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.api.model.core.search.SortDirection;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.seeders.CryptographicKeySeeder;
import com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

/**
 * The key listing fetches in two phases - a page of uuids in the requested order, then the items by {@code uuid IN
 * (...)}. An ordering named by the second query would replace the one the first established, so these cases are what
 * catches a sort that is accepted and then thrown away.
 */
class KeyListingSortITest extends BaseSpringBootTest {

    private static final List<String> SEEDED_NAMES = List.of("alpha", "bravo", "charlie", "delta");

    @Autowired
    private CryptographicKeyExternalService cryptographicKeyService;

    @Autowired
    private CryptographicKeySeeder keySeeder;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    private final Map<String, UUID> seededKeyUuids = new LinkedHashMap<>();

    @BeforeEach
    void loadData() {
        Connector connector = new Connector();
        connector.setName("key-sort-connector");
        connector.setUrl("http://localhost:0/key-sort");
        connector.setVersion(ConnectorVersion.V2);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.saveAndFlush(connector);

        TokenInstanceReference tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setName("key-sort-token");
        tokenInstanceReference.setTokenInstanceUuid("1l");
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReference.setStatus(TokenInstanceStatus.CONNECTED);
        tokenInstanceReferenceRepository.saveAndFlush(tokenInstanceReference);

        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("key-sort-profile");
        tokenProfile.setTokenInstanceReference(tokenInstanceReference);
        tokenProfile.setTokenInstanceName("key-sort-token");
        tokenProfile.setEnabled(true);
        tokenProfileRepository.saveAndFlush(tokenProfile);

        // Seeded newest-last, and each key carries one item, so the listing's default createdAt DESC order is the
        // reverse of the alphabetical one the sort asks for. A sort that never reached the query would return the
        // default order and pass an assertion that only checked the set of names.
        seedNamedItem("delta", tokenProfile, tokenInstanceReference);
        seedNamedItem("alpha", tokenProfile, tokenInstanceReference);
        seedNamedItem("charlie", tokenProfile, tokenInstanceReference);
        seedNamedItem("bravo", tokenProfile, tokenInstanceReference);
    }

    private void seedNamedItem(String name, TokenProfile tokenProfile, TokenInstanceReference tokenInstanceReference) {
        CryptographicKey key = keySeeder
                .seedKey(name, tokenProfile, tokenInstanceReference, KeyItemSpec.signingPrivateKey(KeyAlgorithm.RSA));
        CryptographicKeyItem item = key.getItems().iterator().next();
        item.setName(name);
        cryptographicKeyItemRepository.saveAndFlush(item);
        seededKeyUuids.put(name, key.getUuid());
    }

    private void seedCertificateUsing(UUID keyUuid, String commonName) {
        CertificateContent content = new CertificateContent();
        content.setContent("1234567890-" + UUID.randomUUID());
        content = certificateContentRepository.saveAndFlush(content);

        Certificate certificate = new Certificate();
        certificate.setCommonName(commonName);
        certificate.setSubjectDn("CN=" + commonName);
        certificate.setIssuerDn("CN=" + commonName + "Issuer");
        certificate.setSerialNumber(UUID.randomUUID().toString());
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setCertificateContentId(content.getId());
        certificate.setKeyUuid(keyUuid);
        certificateRepository.saveAndFlush(certificate);
    }

    private List<Integer> listAssociations(SearchSortRequestDto sort) {
        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(1);
        request.setItemsPerPage(10);
        request.setSort(sort);

        return cryptographicKeyService
                .listCryptographicKeys(SecurityFilter.create(), request)
                .getCryptographicKeys()
                .stream()
                .map(KeyItemDto::getAssociations)
                .toList();
    }

    private List<String> listNames(SearchSortRequestDto sort, int pageNumber, int itemsPerPage) {
        SearchRequestDto request = new SearchRequestDto();
        request.setPageNumber(pageNumber);
        request.setItemsPerPage(itemsPerPage);
        request.setSort(sort);

        return cryptographicKeyService
                .listCryptographicKeys(SecurityFilter.create(), request)
                .getCryptographicKeys()
                .stream()
                .map(KeyItemDto::getName)
                .toList();
    }

    private static SearchSortRequestDto sortByName(SortDirection direction) {
        return new SearchSortRequestDto(FilterFieldSource.PROPERTY, "CKI_NAME", direction);
    }

    @Test
    void ordersTheListingByTheRequestedFieldAscending() {
        Assertions.assertEquals(SEEDED_NAMES, listNames(sortByName(SortDirection.ASC), 1, 10));
    }

    @Test
    void ordersTheListingByTheRequestedFieldDescending() {
        Assertions.assertEquals(SEEDED_NAMES.reversed(), listNames(sortByName(SortDirection.DESC), 1, 10));
    }

    /**
     * The ordering has to span the result set rather than each page, so the second page continues where the first ended
     * instead of sorting its own rows.
     */
    @Test
    void pagingWalksTheSortedSet() {
        List<String> paged = new ArrayList<>();
        paged.addAll(listNames(sortByName(SortDirection.ASC), 1, 2));
        paged.addAll(listNames(sortByName(SortDirection.ASC), 2, 2));

        Assertions.assertEquals(SEEDED_NAMES, paged);
    }

    /**
     * The listing's own default is createdAt DESC, and it has to survive untouched for a request that names no sort.
     * The expectation is read back from the seeded rows rather than written out, because four rows saved in one test
     * can share a createdAt, and then the uuid tie-break rather than the seeding order decides.
     */
    @Test
    void aRequestWithoutASortKeepsTheListingDefaultOrder() {
        List<String> byDefaultOrder = seededItems()
                .stream()
                .sorted(Comparator
                        .comparing(CryptographicKeyItem::getCreatedAt)
                        .reversed()
                        .thenComparing(CryptographicKeyItem::getUuid))
                .map(CryptographicKeyItem::getName)
                .toList();

        Assertions.assertEquals(byDefaultOrder, listNames(null, 1, 10));
    }

    private List<CryptographicKeyItem> seededItems() {
        return cryptographicKeyItemRepository
                .findAll()
                .stream()
                .filter(item -> SEEDED_NAMES.contains(item.getName()))
                .toList();
    }

    /**
     * The association counts are loaded by a second query and have to land on the key item each belongs to.
     *
     * <p>
     * Two queries lined up by position agree only while both order the same way and neither has ties, and once the
     * listing orders by a field the request names they do not line up at all - so the counts are keyed by uuid. Each
     * seeded key carries a different number of certificates, and the sort reverses the order the counts are read in, so
     * a count rendered against the wrong key shows up as a mismatch rather than as a coincidence.
     */
    @Test
    void eachListedKeyCarriesItsOwnAssociationCount() {
        seedCertificateUsing(seededKeyUuids.get("alpha"), "alpha-cert-one");
        seedCertificateUsing(seededKeyUuids.get("alpha"), "alpha-cert-two");
        seedCertificateUsing(seededKeyUuids.get("charlie"), "charlie-cert");

        Assertions.assertEquals(SEEDED_NAMES, listNames(sortByName(SortDirection.ASC), 1, 10));
        Assertions.assertEquals(List.of(2, 0, 1, 0), listAssociations(sortByName(SortDirection.ASC)));
        Assertions.assertEquals(List.of(0, 1, 0, 2), listAssociations(sortByName(SortDirection.DESC)));
    }

    /** A key no certificate uses reports zero rather than being left unset. */
    @Test
    void aKeyWithoutCertificatesReportsNoAssociations() {
        Assertions.assertEquals(List.of(0, 0, 0, 0), listAssociations(sortByName(SortDirection.ASC)));
    }
}
