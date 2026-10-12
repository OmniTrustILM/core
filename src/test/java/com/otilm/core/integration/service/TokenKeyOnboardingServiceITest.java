package com.otilm.core.integration.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.cryptography.key.OnboardTokenKeysRequestDto;
import com.otilm.api.model.client.cryptography.key.TokenKeySelectionDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.v2.key.ListKeyPairsResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyPairV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.UnaddressableKeyV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.OnboardTokenKeysResponseDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyListResponseDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyOnboardingResultDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyStatus;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.KeyImportState;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyBasicModel;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.KeyImportTerms;
import com.otilm.core.model.crypto.KeyMaterial;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.ProviderKeyPair;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.TokenKeyOnboardingExternalService;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.writer.CertificateKeyWriter;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.service.writer.KeyImportWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.PqcKeyFixtures;
import com.otilm.core.util.SqlCapture;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.when;

@SpringBootTest
class TokenKeyOnboardingServiceITest extends BaseSpringBootTest {

    private static final ObjectMapper WIRE = ObjectMapperFactory.wire();

    @Autowired
    private V2TokenFixture v2TokenFixture;
    @Autowired
    private TokenKeyOnboardingExternalService tokenKeyOnboardingService;
    @Autowired
    private CryptographicKeyExternalService cryptographicKeyService;
    @Autowired
    private TokenProfileExternalService tokenProfileService;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    private CertificateKeyWriter certificateKeyWriter;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private ResourceObjectAssociationService objectAssociationService;
    @Autowired
    private KeyImportWriter keyImportWriter;
    @Autowired
    private CryptographicKeyWriter cryptographicKeyWriter;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private GroupRepository groupRepository;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private PlatformTransactionManager transactionManager;

    private V2TokenFixture.V2Token v2Token;
    private CryptographyProviderV2ConnectorMock connectorMock;
    private UUID tokenUuid;
    private UUID profileUuid;

    @BeforeEach
    void setUp() {
        v2Token = v2TokenFixture.start();
        v2TokenFixture.declare(v2Token, FeatureFlag.STATELESS, FeatureFlag.KEY_LIST);
        connectorMock = v2Token.connectorMock();
        TokenProfile profile = v2Token.profile();
        tokenUuid = v2Token.token().getUuid();
        profileUuid = profile.getUuid();
    }

    @AfterEach
    void tearDown() {
        connectorMock.stop();
    }

    @Test
    void listsEachKeyPairWithItsStatus() throws Exception {
        // given
        KeyPair onboardable = rsaKeyPair();
        KeyPair heldWithoutToken = rsaKeyPair();
        certificateKeyWriter
                .uploadCertificatePublicKey("certKey_held", heldWithoutToken.getPublic(), 2048,
                        fingerprintOf(heldWithoutToken));
        connectorMock
                .stubKeyPairListing(page(listed("0a", "signer", onboardable), listed("0b", "held", heldWithoutToken),
                        listed("0c", "orphan", null)));

        // when
        TokenKeyListResponseDto listing = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10);

        // then
        assertThat(listing.getTotalItems()).isEqualTo(3);
        assertThat(listing.getItems())
                .extracting(TokenKeyDto::getStatus)
                .containsExactly(TokenKeyStatus.ONBOARDABLE, TokenKeyStatus.ONBOARDABLE_INTO_KEY,
                        TokenKeyStatus.NO_PUBLIC_KEY);
        TokenKeyDto first = listing.getItems().get(0);
        assertThat(first.getSuggestedName()).isEqualTo("signer");
        assertThat(first.getFingerprint()).isEqualTo(fingerprintOf(onboardable));
        assertThat(first.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.RSA);
        assertThat(first.getReason()).isNull();
        TokenKeyDto intoRecord = listing.getItems().get(1);
        assertThat(intoRecord.getInventoryKeyName()).isEqualTo("certKey_held");
        assertThat(intoRecord.getSuggestedName()).isNull();
        assertThat(listing.getItems().get(2).getReason())
                .isEqualTo("The key storage holds no public key for this key pair.");
        connectorMock.verifyKeyPairListingRequestContaining("""
                {"offset": 0, "limit": 10}
                """);
    }

    @Test
    void listsAKeyPairOnboardableIntoAKeyTheCallerMayNotSeeWithoutNamingTheKey() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID hidden = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_hidden", pair.getPublic(), 2048, fingerprintOf(pair));
        denyOn(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, hidden);
        connectorMock.stubKeyPairListing(page(listed("0a", "signer", pair)));

        // when
        TokenKeyDto entry = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10).getItems().get(0);

        // then
        assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.ONBOARDABLE_INTO_KEY);
        assertThat(entry.getInventoryKeyUuid()).isNull();
        assertThat(entry.getInventoryKeyName()).isNull();
    }

    @Test
    void listsAKeyPairWhoseRecordTheCallerMayNotUpdateWithTheReason() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID record = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_locked", pair.getPublic(), 2048, fingerprintOf(pair));
        denyOn(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE, record);
        connectorMock.stubKeyPairListing(page(listed("0a", "signer", pair)));

        // when
        TokenKeyDto entry = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10).getItems().get(0);

        // then
        assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY_WITHOUT_TOKEN);
        assertThat(entry.getInventoryKeyName()).isEqualTo("certKey_locked");
        assertThat(entry.getReason()).isEqualTo(KeyImportGates.NOT_UPDATABLE.formatted("certKey_locked"));
    }

    @Test
    void listsAKeyPairWhoseRecordIsNotActiveWithTheReason() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID record = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_inactive", pair.getPublic(), 2048, fingerprintOf(pair));
        withItemsIn(record, KeyState.DEACTIVATED);
        connectorMock.stubKeyPairListing(page(listed("0a", "signer", pair)));

        // when
        TokenKeyDto entry = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10).getItems().get(0);

        // then
        assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY_WITHOUT_TOKEN);
        assertThat(entry.getReason()).startsWith("Key certKey_inactive holds this public key without a token instance");
    }

    @Test
    void listsAKeyPairTheInventoryHoldsWithTheReasonNamingTheKey() throws Exception {
        // given
        String listing = page(listed("0a", "signer", rsaKeyPair()));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        onboard(handleOfTheFirstListedPair());

        // when
        TokenKeyDto entry = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10).getItems().get(0);

        // then
        assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY);
        assertThat(entry.getInventoryKeyName()).isEqualTo("signer");
        assertThat(entry.getReason()).isEqualTo("Key signer already holds this key pair.");
    }

    @Test
    void listsAKeyPairHeldAsAPublicKeyInATokenWithTheReason() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        publicKeyInTheToken("certKey_in_token", pair);
        connectorMock.stubKeyPairListing(page(listed("0a", "signer", pair)));

        // when
        TokenKeyDto entry = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10).getItems().get(0);

        // then
        assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY);
        assertThat(entry.getReason()).isEqualTo(KeyImportGates.HELD_IN_TOKEN.formatted("certKey_in_token"));
    }

    @Test
    void listsAKeyPairHeldByAKeyTheCallerMayNotSeeInNeutralWords() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID hidden = publicKeyInTheToken("certKey_hidden", pair);
        denyOn(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, hidden);
        connectorMock.stubKeyPairListing(page(listed("0a", "signer", pair)));

        // when
        TokenKeyDto entry = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10).getItems().get(0);

        // then
        assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY);
        assertThat(entry.getInventoryKeyName()).isNull();
        assertThat(entry.getReason()).isEqualTo(CryptographicKeyWriter.KEY_ALREADY_HELD);
    }

    /** A key without an identifier unique to it counts toward the page like a key pair, and follows the pairs. */
    @Test
    void listsAKeyWithoutAUniqueIdAfterTheKeyPairs() throws Exception {
        // given
        ListKeyPairsResponseV2Dto listing = new ListKeyPairsResponseV2Dto();
        listing.setItems(List.of(listed("0a", "signer", rsaKeyPair())));
        listing.setUnaddressableKeys(List.of(unaddressable("legacy")));
        listing.setTotalItems(5L);
        connectorMock.stubKeyPairListing(WIRE.writeValueAsString(listing));

        // when
        TokenKeyListResponseDto page = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 2);

        // then
        assertThat(page.getItems())
                .extracting(TokenKeyDto::getStatus)
                .containsExactly(TokenKeyStatus.ONBOARDABLE, TokenKeyStatus.NO_UNIQUE_ID);
        TokenKeyDto unaddressable = page.getItems().get(1);
        assertThat(unaddressable)
                .extracting(TokenKeyDto::getLabel, TokenKeyDto::getKeyAlgorithm, TokenKeyDto::getLength)
                .containsExactly("legacy", KeyAlgorithm.RSA, 2048);
        assertThat(unaddressable)
                .extracting(TokenKeyDto::getKeyPairHandle, TokenKeyDto::getFingerprint,
                        TokenKeyDto::getInventoryKeyUuid, TokenKeyDto::getInventoryKeyName,
                        TokenKeyDto::getSuggestedName)
                .containsOnlyNulls();
        assertThat(unaddressable.getReason()).contains("without an ID unique to it");
        assertThat(page)
                .extracting(TokenKeyListResponseDto::getTotalItems, TokenKeyListResponseDto::getItemsPerPage,
                        TokenKeyListResponseDto::getTotalPages)
                .containsExactly(5L, 2, 3);
    }

    /** An import the reconciliation still has to settle may yet register the key pair or destroy it. */
    @ParameterizedTest
    @EnumSource(value = KeyImportState.class, names = {"REQUESTED", "ACCEPTED", "COMPENSATING"})
    void listsAKeyPairAnUnsettledImportHoldsAsImportInProgress(KeyImportState state) throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        importOf(pair, state);
        connectorMock.stubKeyPairListing(page(listed("0a", "signer", pair)));

        // when
        TokenKeyDto entry = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10).getItems().get(0);

        // then
        assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IMPORT_IN_PROGRESS);
        assertThat(entry.getSuggestedName()).isNull();
    }

    @Test
    void listsAKeyPairWhoseImportFailedAsOnboardable() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        importOf(pair, KeyImportState.FAILED);
        connectorMock.stubKeyPairListing(page(listed("0a", "signer", pair)));

        // when
        TokenKeyDto entry = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10).getItems().get(0);

        // then
        assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.ONBOARDABLE);
    }

    /** The inventory is read once for a page, so a page of six key pairs costs as many queries as a page of two. */
    @Test
    void readsTheInventoryOnceForAPage() throws Exception {
        // given
        String smallPage = page(heldPair("0a"), listed("0b", "signer 0b", rsaKeyPair()));
        String largePage = page(heldPair("1a"), heldPair("1b"), heldPair("1c"), listed("1d", "signer 1d", rsaKeyPair()),
                listed("1e", "signer 1e", rsaKeyPair()), listed("1f", "signer 1f", rsaKeyPair()));
        connectorMock.stubKeyPairListing(smallPage);
        tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10);

        // when
        int smallPageQueries = queriesListingTheFirstPage();
        connectorMock.stubKeyPairListing(largePage);
        int largePageQueries = queriesListingTheFirstPage();

        // then
        assertThat(largePageQueries).isEqualTo(smallPageQueries);
    }

    /** The offset of a page this far exceeds an int, and would wrap to the offset of another page. */
    @Test
    void refusesAPageBeyondTheLargestOffset() throws Exception {
        // given
        connectorMock.stubKeyPairListing(page(listed("0a", "signer", rsaKeyPair())));
        int pageNumber = 4_294_969;
        int itemsPerPage = 1000;

        // when / then
        assertThatThrownBy(
                () -> tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, pageNumber, itemsPerPage))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("The page must start at most 2147483647 key pairs into the listing.");
        connectorMock.verifyKeyPairListingRequests(0);
    }

    @Test
    void onboardsTheSelectedKeyPairReadAgainFromTheToken() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID certificateUuid = persistedCertificateCarrying(pair);
        String listing = page(listed("0a", "signer", pair));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        String handle = handleOfTheFirstListedPair();

        // when
        TokenKeyOnboardingResultDto result = onboard(handle);

        // then
        assertThat(result.isOnboarded()).isTrue();
        assertThat(result.isIntoExistingKey()).isFalse();
        assertThat(result.getKeyName()).isEqualTo("signer");
        CryptographicKey onboarded = cryptographicKeyRepository
                .findByUuid(UUID.fromString(result.getKeyUuid()))
                .orElseThrow();
        assertThat(onboarded.getTokenProfileUuid()).isEqualTo(profileUuid);
        List<CryptographicKeyItem> items = cryptographicKeyItemRepository.findByKeyUuidIn(List.of(onboarded.getUuid()));
        assertThat(items).hasSize(2).noneMatch(CryptographicKeyItem::isExportable);
        assertThat(certificateRepository.findById(certificateUuid).orElseThrow().getKeyUuid())
                .isEqualTo(onboarded.getUuid());
        connectorMock.verifyKeyPairListingRequestContaining("""
                {"offset": 0, "limit": 1, "keyPairMetaFilter": [[{"name": "keyId"}]]}
                """);
    }

    @Test
    void listsAndOnboardsAKeyPairListedWithoutALength() throws Exception {
        // given
        String listing = page(listed("0a", "signer", PqcKeyFixtures.keyPair(), KeyAlgorithm.MLDSA, null));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);

        // when
        TokenKeyDto entry = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10).getItems().get(0);
        TokenKeyOnboardingResultDto result = onboard(entry.getKeyPairHandle());

        // then
        assertThat(entry)
                .extracting(TokenKeyDto::getStatus, TokenKeyDto::getKeyAlgorithm, TokenKeyDto::getLength)
                .containsExactly(TokenKeyStatus.ONBOARDABLE, KeyAlgorithm.MLDSA, null);
        assertThat(result.isOnboarded()).isTrue();
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(UUID.fromString(result.getKeyUuid()))))
                .hasSize(2)
                .extracting(CryptographicKeyItem::getLength)
                .containsOnlyNulls();
    }

    @Test
    void onboardsUnderTheNameTheSelectionGives() throws Exception {
        // given
        String listing = page(listed("0a", "signer", rsaKeyPair()));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        String handle = handleOfTheFirstListedPair();

        // when
        TokenKeyOnboardingResultDto result = onboard(new TokenKeySelectionDto(handle, "Payments signer"), null);

        // then
        assertThat(result.getKeyName()).isEqualTo("Payments signer");
    }

    @Test
    void writesTheCustomAttributesOfANewKey() throws Exception {
        // given
        CustomAttributeV3 department = departmentAttribute();
        String listing = page(listed("0a", "signer", rsaKeyPair()));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        String handle = handleOfTheFirstListedPair();

        // when
        TokenKeyOnboardingResultDto result = onboard(new TokenKeySelectionDto(handle, null),
                List.of(departmentValue(department, "payments")));

        // then
        assertThat(departmentOf(UUID.fromString(result.getKeyUuid()))).isEqualTo("payments");
    }

    @Test
    void refusesCustomAttributesItCannotWriteBeforeReadingTheTokenAgain() throws Exception {
        // given
        String listing = page(listed("0a", "signer", rsaKeyPair()));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        String handle = handleOfTheFirstListedPair();
        CustomAttributeV3 undefined = new CustomAttributeV3();
        undefined.setUuid(UUID.randomUUID().toString());
        undefined.setName("undefined");

        // when / then
        assertThatThrownBy(
                () -> onboard(new TokenKeySelectionDto(handle, null), List.of(departmentValue(undefined, "x"))))
                .isInstanceOf(ValidationException.class);
        connectorMock.verifyKeyPairListingRequests(1);
        assertThat(cryptographicKeyRepository.existsByName("signer")).isFalse();
    }

    @Test
    void onboardsAKeyPairIntoTheRecordHoldingItsPublicKeyAndKeepsTheRecordAsItIs() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID record = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_signer", pair.getPublic(), 2048, fingerprintOf(pair));
        UUID certificateUuid = persistedCertificateCarrying(pair);
        jdbcTemplate.update("UPDATE certificate SET key_uuid = ? WHERE uuid = ?", record, certificateUuid);
        CustomAttributeV3 department = departmentAttribute();
        UUID ownerUuid = UUID.randomUUID();
        Group group = group("signers");
        describedOwnedAndGrouped(record, ownerUuid, group, departmentValue(department, "the record's"));
        String listing = page(listed("0a", "signer", pair));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        String handle = handleOfTheFirstListedPair();

        // when
        TokenKeyOnboardingResultDto result = onboard(new TokenKeySelectionDto(handle, "ignored"),
                List.of(departmentValue(department, "the request's")));

        // then
        assertThat(result)
                .extracting(TokenKeyOnboardingResultDto::isOnboarded, TokenKeyOnboardingResultDto::isIntoExistingKey,
                        TokenKeyOnboardingResultDto::getKeyUuid, TokenKeyOnboardingResultDto::getKeyName)
                .containsExactly(true, true, record.toString(), "certKey_signer");
        KeyDetailDto key = cryptographicKeyService.getKey(SecuredUUID.fromUUID(record));
        assertThat(key.getTokenProfileUuid()).isEqualTo(profileUuid.toString());
        assertThat(key.getDescription()).isEqualTo("the certificate's key");
        assertThat(key.getOwnerUuid()).isEqualTo(ownerUuid.toString());
        assertThat(key.getGroups())
                .extracting(groupDto -> groupDto.getUuid())
                .containsExactly(group.getUuid().toString());
        assertThat(departmentOf(record)).isEqualTo("the record's");
        List<CryptographicKeyItem> items = cryptographicKeyItemRepository.findByKeyUuidIn(List.of(record));
        assertThat(items)
                .extracting(CryptographicKeyItem::getType, CryptographicKeyItem::isExportable)
                .containsExactlyInAnyOrder(tuple(KeyType.PUBLIC_KEY, false), tuple(KeyType.PRIVATE_KEY, false));
        assertThat(items).allSatisfy(item -> assertThat(item.getKeyMeta()).isNotEmpty());
        assertThat(certificateRepository.findById(certificateUuid).orElseThrow().getKeyUuid()).isEqualTo(record);
        assertThat(cryptographicKeyRepository.existsByName("ignored")).isFalse();
    }

    @Test
    void skipsAKeyPairWhoseRecordTheCallerMayNotUpdate() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID record = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_locked", pair.getPublic(), 2048, fingerprintOf(pair));
        denyOn(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE, record);
        String listing = page(listed("0a", "signer", pair));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);

        // when
        TokenKeyOnboardingResultDto result = onboard(handleOfTheFirstListedPair());

        // then
        assertThat(result.isOnboarded()).isFalse();
        assertThat(result.getReason()).isEqualTo(KeyImportGates.NOT_UPDATABLE.formatted("certKey_locked"));
        assertThat(cryptographicKeyRepository.findByUuid(record).orElseThrow().getTokenProfileUuid()).isNull();
    }

    @Test
    void onboardsIntoARecordTheCallerMayNotSeeWithoutNamingIt() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID hidden = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_hidden", pair.getPublic(), 2048, fingerprintOf(pair));
        denyOn(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, hidden);
        String listing = page(listed("0a", "signer", pair));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);

        // when
        TokenKeyOnboardingResultDto result = onboard(handleOfTheFirstListedPair());

        // then
        assertThat(result)
                .extracting(TokenKeyOnboardingResultDto::isOnboarded, TokenKeyOnboardingResultDto::isIntoExistingKey,
                        TokenKeyOnboardingResultDto::getKeyUuid, TokenKeyOnboardingResultDto::getKeyName)
                .containsExactly(true, true, null, null);
        assertThat(cryptographicKeyRepository.findByUuid(hidden).orElseThrow().getTokenProfileUuid())
                .isEqualTo(profileUuid);
    }

    /**
     * Two objects on the token may hold one key pair; the first onboarded joins the record, the second finds it held.
     */
    @Test
    void onboardsASecondKeyPairWithTheSamePublicKeyIntoNothing() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID record = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_shared", pair.getPublic(), 2048, fingerprintOf(pair));
        String listing = page(listed("0a", "first", pair), listed("0b", "second", pair));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        List<TokenKeyDto> entries = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10).getItems();
        OnboardTokenKeysRequestDto both = new OnboardTokenKeysRequestDto(List
                .of(new TokenKeySelectionDto(entries.get(0).getKeyPairHandle(), null),
                        new TokenKeySelectionDto(entries.get(1).getKeyPairHandle(), null)),
                null);

        // when
        OnboardTokenKeysResponseDto response = tokenKeyOnboardingService.onboardTokenKeys(tokenUuid, profileUuid, both);

        // then
        assertThat(response.getResults())
                .extracting(TokenKeyOnboardingResultDto::isOnboarded, TokenKeyOnboardingResultDto::getKeyUuid)
                .containsExactly(tuple(true, record.toString()), tuple(false, record.toString()));
        assertThat(response.getResults().get(1).getReason())
                .isEqualTo("Key certKey_shared already holds this key pair.");
    }

    /** A record that gained a token since the listing read it can no longer take the private key. */
    @Test
    void refusesToOnboardIntoARecordThatGainedATokenMeanwhile() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID record = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_taken", pair.getPublic(), 2048, fingerprintOf(pair));
        CryptographicKey taken = cryptographicKeyRepository.findByUuid(record).orElseThrow();
        taken.setTokenProfileUuid(profileUuid);
        taken.setTokenInstanceReferenceUuid(tokenUuid);
        cryptographicKeyRepository.saveAndFlush(taken);
        List<ProviderKeyItem> items = providerKeyPair(pair, "0a").itemsNamed("certKey_taken");

        // when / then
        assertThatThrownBy(() -> cryptographicKeyWriter
                .onboardIntoRecordUnlessImporting(record, profileModel(), fingerprintOf(pair), items))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(CryptographicKeyWriter.KEY_ALREADY_HELD);
        assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(record))).hasSize(1);
    }

    @Test
    void skipsAKeyPairTheInventoryAlreadyHolds() throws Exception {
        // given
        String listing = page(listed("0a", "signer", rsaKeyPair()));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        String handle = handleOfTheFirstListedPair();
        OnboardTokenKeysRequestDto twice = new OnboardTokenKeysRequestDto(
                List.of(new TokenKeySelectionDto(handle, null), new TokenKeySelectionDto(handle, "again")), null);

        // when
        OnboardTokenKeysResponseDto response = tokenKeyOnboardingService
                .onboardTokenKeys(tokenUuid, profileUuid, twice);

        // then
        assertThat(response.getResults())
                .extracting(TokenKeyOnboardingResultDto::isOnboarded)
                .containsExactly(true, false);
        TokenKeyOnboardingResultDto skipped = response.getResults().get(1);
        assertThat(skipped.getKeyName()).isEqualTo("signer");
        assertThat(skipped.getReason()).contains("signer");
        assertThat(cryptographicKeyRepository.existsByName("again")).isFalse();
    }

    @Test
    void skipsAKeyPairHeldAsAPublicKeyInAToken() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        publicKeyInTheToken("certKey_in_token", pair);
        String listing = page(listed("0a", "signer", pair));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        String handle = handleOfTheFirstListedPair();

        // when
        TokenKeyOnboardingResultDto result = onboard(handle);

        // then
        assertThat(result.isOnboarded()).isFalse();
        assertThat(result.getReason())
                .isEqualTo("Key certKey_in_token holds the same public key under a token instance, without its "
                        + "private key.");
    }

    @Test
    void skipsAKeyPairHeldByAKeyTheCallerMayNotSeeInWordsThatNameNoKey() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID hidden = certificateKeyWriter
                .uploadCertificatePublicKey("certKey_hidden", pair.getPublic(), 2048, fingerprintOf(pair));
        denyOn(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, hidden);
        denyOn(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE, hidden);
        String listing = page(listed("0a", "signer", pair));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        String handle = handleOfTheFirstListedPair();

        // when
        TokenKeyOnboardingResultDto result = onboard(handle);

        // then
        assertThat(result.isOnboarded()).isFalse();
        assertThat(result.getKeyUuid()).isNull();
        assertThat(result.getKeyName()).isNull();
        assertThat(result.getReason()).isEqualTo(CryptographicKeyWriter.KEY_ALREADY_HELD);
    }

    @Test
    void skipsAKeyPairAnUnsettledImportHolds() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        importOf(pair, KeyImportState.ACCEPTED);
        String listing = page(listed("0a", "signer", pair));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        String handle = handleOfTheFirstListedPair();

        // when
        TokenKeyOnboardingResultDto result = onboard(handle);

        // then
        assertThat(result.isOnboarded()).isFalse();
        assertThat(result.getReason()).isEqualTo("An import of this key pair is still in progress.");
        assertThat(cryptographicKeyRepository.existsByName("signer")).isFalse();
    }

    /**
     * An import holding the key pair may be registering it or undoing it under its attempt's lock, so the onboarding
     * waits for that lock and refuses the key pair while the import stays unsettled.
     */
    @Test
    void onboardingWaitsForAnUnsettledImportOfTheKeyPairAndRefusesIt() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        UUID attempt = importOf(pair, KeyImportState.ACCEPTED);
        TokenProfileFullModel profile = profileModel();
        List<ProviderKeyItem> items = providerKeyPair(pair, "0a").itemsNamed("signer");
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        try (ExecutorService onboarder = Executors.newSingleThreadExecutor()) {
            // when
            Future<Optional<CryptographicKeyBasicModel>> onboarding = transaction.execute(status -> {
                jdbcTemplate.queryForList("SELECT uuid FROM key_import WHERE uuid = ? FOR UPDATE", attempt);
                int lockHolderPid = jdbcTemplate.queryForObject("SELECT pg_backend_pid()", Integer.class);
                Future<Optional<CryptographicKeyBasicModel>> onboardingKey = onboarder
                        .submit(() -> cryptographicKeyWriter
                                .onboardUnlessImporting("signer", profile, fingerprintOf(pair), items, null));
                Awaitility
                        .await()
                        .atMost(Duration.ofSeconds(10))
                        .until(() -> jdbcTemplate
                                .queryForObject(
                                        "SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))",
                                        Long.class, lockHolderPid) > 0);
                return onboardingKey;
            });

            // then
            assertThat(onboarding.get(10, TimeUnit.SECONDS)).isEmpty();
            assertThat(cryptographicKeyRepository.existsByName("signer")).isFalse();
        }
    }

    @Test
    void skipsAKeyPairUnderATakenName() throws Exception {
        // given
        KeyPair other = rsaKeyPair();
        certificateKeyWriter
                .uploadCertificatePublicKey("Payments signer", other.getPublic(), 2048, fingerprintOf(other));
        String listing = page(listed("0a", "signer", rsaKeyPair()));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        String handle = handleOfTheFirstListedPair();

        // when
        TokenKeyOnboardingResultDto result = onboard(new TokenKeySelectionDto(handle, "Payments signer"), null);

        // then
        assertThat(result.isOnboarded()).isFalse();
        assertThat(result.getReason()).isEqualTo("A key named Payments signer already exists.");
    }

    @Test
    void reportsOnTheProfileWhetherItsConnectorListsKeys() throws Exception {
        // given
        SecuredParentUUID token = SecuredParentUUID.fromUUID(tokenUuid);
        SecuredUUID profile = SecuredUUID.fromUUID(profileUuid);

        // when
        boolean whileListing = tokenProfileService.getTokenProfile(token, profile).isKeyListAvailable();
        v2TokenFixture.declare(v2Token, FeatureFlag.STATELESS);
        boolean afterDropping = tokenProfileService.getTokenProfile(token, profile).isKeyListAvailable();

        // then
        assertThat(whileListing).isTrue();
        assertThat(afterDropping).isFalse();
    }

    @Test
    void listsOnlyTheProfilesWhoseConnectorListsKeysWhenAsked() {
        // when
        List<String> whileListing = keyListableProfiles();
        v2TokenFixture.declare(v2Token, FeatureFlag.STATELESS);
        List<String> afterDropping = keyListableProfiles();

        // then
        assertThat(whileListing).contains(profileUuid.toString());
        assertThat(afterDropping).doesNotContain(profileUuid.toString());
    }

    @Test
    void refusesToListOnAConnectorLackingKeyListing() {
        // given
        v2TokenFixture.declare(v2Token, FeatureFlag.STATELESS);

        // when / then
        assertThatThrownBy(() -> tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("cannot list the keys in its key storage");
    }

    @Test
    void removesAnOnboardedKeyFromTheInventoryAlone() throws Exception {
        // given
        String listing = page(listed("0a", "signer", rsaKeyPair()));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing).stubDestroyKey();
        UUID onboarded = onboardTheFirstListedPair();

        // when
        cryptographicKeyService.removeKeyFromInventory(SecuredUUID.fromUUID(onboarded));

        // then
        assertThat(cryptographicKeyRepository.findByUuid(onboarded)).isEmpty();
        connectorMock.verifyDestroyKeyRequests(0);
        assertThat(tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10).getItems().get(0).getStatus())
                .isEqualTo(TokenKeyStatus.ONBOARDABLE);
    }

    @Test
    void removesAKeyThePlatformCreatedOnATokenThatListsKeys() throws Exception {
        // given
        KeyPair pair = rsaKeyPair();
        connectorMock.stubKeyPairListing(page(listed("0c", "created", pair))).stubDestroyKey();
        UUID created = keyPairThePlatformCreated("created", pair, "0c");

        // when
        cryptographicKeyService.removeKeyFromInventory(SecuredUUID.fromUUID(created));

        // then
        assertThat(cryptographicKeyRepository.findByUuid(created)).isEmpty();
        connectorMock.verifyDestroyKeyRequests(0);
        assertThat(tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10).getItems().get(0).getStatus())
                .isEqualTo(TokenKeyStatus.ONBOARDABLE);
    }

    @Test
    void refusesToRemoveAKeyWithoutAPrivateKeyInAToken() throws Exception {
        // given
        UUID record = publicKeyOnlyRecord("certKey_record");

        // when / then
        assertThatThrownBy(() -> cryptographicKeyService.removeKeyFromInventory(SecuredUUID.fromUUID(record)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("It holds no private key in a token.");
        assertThat(cryptographicKeyRepository.findByUuid(record)).isPresent();
    }

    @Test
    void refusesToRemoveAKeyFromATokenWhoseConnectorListsNoKeys() throws Exception {
        // given
        UUID created = keyPairThePlatformCreated("created", rsaKeyPair(), "0c");
        v2TokenFixture.declare(v2Token, FeatureFlag.STATELESS);

        // when / then
        assertThatThrownBy(() -> cryptographicKeyService.removeKeyFromInventory(SecuredUUID.fromUUID(created)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("The connector of its token cannot list keys");
        assertThat(cryptographicKeyRepository.findByUuid(created)).isPresent();
    }

    @Test
    void refusesToRemoveACompromisedKey() throws Exception {
        // given
        UUID created = keyPairThePlatformCreated("created", rsaKeyPair(), "0c");
        withItemsIn(created, KeyState.COMPROMISED);

        // when / then
        assertThatThrownBy(() -> cryptographicKeyService.removeKeyFromInventory(SecuredUUID.fromUUID(created)))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("It is compromised");
        assertThat(cryptographicKeyRepository.findByUuid(created)).isPresent();
    }

    @Test
    void keepsAKeyCompromisedAfterItsRemovalReadIt() throws Exception {
        // given
        UUID created = keyPairThePlatformCreated("created", rsaKeyPair(), "0c");
        CryptographicKeyFullModel read = cryptographicKeyRepository.findFullModelByUuid(created).orElseThrow();
        Map<UUID, KeyState> statesRead = read
                .items()
                .stream()
                .collect(Collectors.toMap(CryptographicKeyItemBasicModel::uuid, CryptographicKeyItemBasicModel::state));
        withItemsIn(created, KeyState.COMPROMISED);

        // when / then
        assertThatThrownBy(() -> cryptographicKeyWriter.removeFromInventoryAsRead(read, statesRead))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("changed meanwhile");
        assertThat(cryptographicKeyRepository.findByUuid(created)).isPresent();
    }

    /** An operator compromises an item under the item's own lock, so the removal waits for it and sees the change. */
    @Test
    void removalWaitsForAnItemBeingCompromisedAndKeepsTheKey() throws Exception {
        // given
        UUID created = keyPairThePlatformCreated("created", rsaKeyPair(), "0c");
        CryptographicKeyFullModel read = cryptographicKeyRepository.findFullModelByUuid(created).orElseThrow();
        Map<UUID, KeyState> statesRead = read
                .items()
                .stream()
                .collect(Collectors.toMap(CryptographicKeyItemBasicModel::uuid, CryptographicKeyItemBasicModel::state));
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        try (ExecutorService remover = Executors.newSingleThreadExecutor()) {
            // when
            Future<?> removal = transaction.execute(status -> {
                jdbcTemplate
                        .update("UPDATE cryptographic_key_item SET state = ? WHERE key_uuid = ?",
                                KeyState.COMPROMISED.name(), created);
                int lockHolderPid = jdbcTemplate.queryForObject("SELECT pg_backend_pid()", Integer.class);
                Future<?> removingKey = remover
                        .submit(() -> cryptographicKeyWriter.removeFromInventoryAsRead(read, statesRead));
                Awaitility
                        .await()
                        .atMost(Duration.ofSeconds(10))
                        .until(() -> jdbcTemplate
                                .queryForObject(
                                        "SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))",
                                        Long.class, lockHolderPid) > 0);
                return removingKey;
            });

            // then
            assertThatThrownBy(() -> removal.get(10, TimeUnit.SECONDS))
                    .hasCauseInstanceOf(ValidationException.class)
                    .hasMessageContaining("changed meanwhile");
            assertThat(cryptographicKeyRepository.findByUuid(created)).isPresent();
        }
    }

    @Test
    void refusesToRemoveAnOnboardedKeyTheCallerMayNotDelete() throws Exception {
        // given
        String listing = page(listed("0a", "signer", rsaKeyPair()));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        UUID onboarded = onboardTheFirstListedPair();
        objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, onboarded, UUID.randomUUID(), "another");
        denyOn(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DELETE, onboarded);

        // when / then
        assertThatThrownBy(() -> cryptographicKeyService.removeKeyFromInventory(SecuredUUID.fromUUID(onboarded)))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(cryptographicKeyRepository.findByUuid(onboarded)).isPresent();
    }

    @Test
    void refusesToRemoveAnOnboardedKeyFromATokenWhoseKeysTheCallerMayNotManage() throws Exception {
        // given
        String listing = page(listed("0a", "signer", rsaKeyPair()));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        UUID onboarded = onboardTheFirstListedPair();
        denyOn(Resource.TOKEN, ResourceAction.MEMBERS, tokenUuid);

        // when / then
        assertThatThrownBy(() -> cryptographicKeyService.removeKeyFromInventory(SecuredUUID.fromUUID(onboarded)))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(cryptographicKeyRepository.findByUuid(onboarded)).isPresent();
    }

    @Test
    void removesTheRemovableKeysOfASelectionAndReportsTheOthers() throws Exception {
        // given
        String listing = page(listed("0a", "signer", rsaKeyPair()));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing).stubDestroyKey();
        UUID onboarded = onboardTheFirstListedPair();
        UUID created = keyPairThePlatformCreated("created", rsaKeyPair(), "0c");
        UUID compromised = keyPairThePlatformCreated("compromised", rsaKeyPair(), "0d");
        withItemsIn(compromised, KeyState.COMPROMISED);
        UUID record = publicKeyOnlyRecord("certKey_record");
        String unknown = UUID.randomUUID().toString();

        // when
        List<BulkActionMessageDto> report = cryptographicKeyService
                .removeKeysFromInventory(List
                        .of(onboarded.toString(), created.toString(), compromised.toString(), record.toString(),
                                unknown));

        // then
        assertThat(report)
                .extracting(BulkActionMessageDto::getUuid, BulkActionMessageDto::getName)
                .containsExactly(tuple(compromised.toString(), "compromised"),
                        tuple(record.toString(), "certKey_record"), tuple(unknown, unknown));
        assertThat(report.get(0).getMessage()).startsWith("It is compromised");
        assertThat(report.get(1).getMessage()).startsWith("It holds no private key in a token.");
        assertThat(cryptographicKeyRepository.findByUuid(onboarded)).isEmpty();
        assertThat(cryptographicKeyRepository.findByUuid(created)).isEmpty();
        assertThat(cryptographicKeyRepository.findByUuid(compromised)).isPresent();
        assertThat(cryptographicKeyRepository.findByUuid(record)).isPresent();
        connectorMock.verifyDestroyKeyRequests(0);
    }

    @Test
    void refusesASelectionHoldingAKeyTheCallerMayNotDeleteAndRemovesNone() throws Exception {
        // given
        String listing = page(listed("0a", "signer", rsaKeyPair()));
        connectorMock.stubKeyPairListing(listing).stubFilteredKeyPairListing(listing);
        UUID onboarded = onboardTheFirstListedPair();
        UUID created = keyPairThePlatformCreated("created", rsaKeyPair(), "0c");
        objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, created, UUID.randomUUID(), "another");
        denyOn(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DELETE, created);
        List<String> selection = List.of(onboarded.toString(), created.toString());

        // when / then
        assertThatThrownBy(() -> cryptographicKeyService.removeKeysFromInventory(selection))
                .isInstanceOf(AccessDeniedException.class);
        assertThat(cryptographicKeyRepository.findByUuid(onboarded)).isPresent();
    }

    private TokenKeyOnboardingResultDto onboard(String handle) throws Exception {
        return onboard(new TokenKeySelectionDto(handle, null), null);
    }

    private TokenKeyOnboardingResultDto onboard(TokenKeySelectionDto selection, List<RequestAttribute> customAttributes)
            throws Exception {
        return tokenKeyOnboardingService
                .onboardTokenKeys(tokenUuid, profileUuid,
                        new OnboardTokenKeysRequestDto(List.of(selection), customAttributes))
                .getResults()
                .get(0);
    }

    private List<String> keyListableProfiles() {
        return tokenProfileService
                .listTokenProfiles(Optional.empty(), List.of(), true, SecurityFilter.create())
                .stream()
                .map(TokenProfileDto::getUuid)
                .toList();
    }

    /** An attempt to import the key pair, in the given state. */
    private UUID importOf(KeyPair pair, KeyImportState state) throws Exception {
        KeyImportTerms terms = new KeyImportTerms(profileModel(), KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA,
                fingerprintOf(pair), false, List.of(), new NameAndUuidDto(UUID.randomUUID().toString(), "requester"));
        UUID attempt = keyImportWriter
                .open(terms, "import-" + UUID.randomUUID(), "imported key", List.of("sent-secret-digest"))
                .uuid();
        jdbcTemplate.update("UPDATE key_import SET state = ? WHERE uuid = ?", state.name(), attempt);
        return attempt;
    }

    private TokenProfileFullModel profileModel() {
        return tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(profileUuid, tokenUuid)
                .orElseThrow();
    }

    /** The key pair as a listing of the token would read it. */
    private static ProviderKeyPair providerKeyPair(KeyPair pair, String keyId) {
        RemoteKeyReference handle = new RemoteKeyReference.MetadataReference(handle(keyId));
        KeyMaterial spki = new KeyMaterial(KeyFormat.SPKI,
                Base64.getEncoder().encodeToString(pair.getPublic().getEncoded()));
        ProviderKeyItem privateKey = new ProviderKeyItem(null, KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, 2048, handle,
                null, List.of());
        ProviderKeyItem publicKey = new ProviderKeyItem(null, KeyType.PUBLIC_KEY, KeyAlgorithm.RSA, 2048, handle, spki,
                List.of());
        return new ProviderKeyPair(handle(keyId), "signer", privateKey, publicKey);
    }

    private UUID onboardTheFirstListedPair() throws Exception {
        return UUID.fromString(onboard(handleOfTheFirstListedPair()).getKeyUuid());
    }

    /** A key pair the platform created on the token, as key creation registers it. */
    private UUID keyPairThePlatformCreated(String name, KeyPair pair, String keyId) throws Exception {
        TokenProfileFullModel profile = profileModel();
        KeyRequestDto request = new KeyRequestDto();
        request.setName(name);
        return cryptographicKeyWriter
                .createKeyWithItems(request, profile, profile.tokenInstance(),
                        providerKeyPair(pair, keyId).itemsNamed(name), false, true)
                .uuid();
    }

    private UUID publicKeyOnlyRecord(String name) throws Exception {
        KeyPair pair = rsaKeyPair();
        return certificateKeyWriter.uploadCertificatePublicKey(name, pair.getPublic(), 2048, fingerprintOf(pair));
    }

    private UUID publicKeyInTheToken(String name, KeyPair pair) throws Exception {
        UUID record = certificateKeyWriter
                .uploadCertificatePublicKey(name, pair.getPublic(), 2048, fingerprintOf(pair));
        CryptographicKey inToken = cryptographicKeyRepository.findByUuid(record).orElseThrow();
        inToken.setTokenProfileUuid(profileUuid);
        inToken.setTokenInstanceReferenceUuid(tokenUuid);
        cryptographicKeyRepository.save(inToken);
        return record;
    }

    private void withItemsIn(UUID keyUuid, KeyState state) {
        List<CryptographicKeyItem> items = cryptographicKeyItemRepository.findByKeyUuidIn(List.of(keyUuid));
        items.forEach(item -> item.setState(state));
        cryptographicKeyItemRepository.saveAllAndFlush(items);
    }

    /** Gives the record a description, an owner, a group and a department, as another user would have. */
    private void describedOwnedAndGrouped(UUID recordUuid, UUID ownerUuid, Group group, RequestAttribute department)
            throws Exception {
        CryptographicKey described = cryptographicKeyRepository.findById(recordUuid).orElseThrow();
        described.setDescription("the certificate's key");
        cryptographicKeyRepository.saveAndFlush(described);
        objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, recordUuid, ownerUuid, "owner");
        objectAssociationService.addGroup(Resource.CRYPTOGRAPHIC_KEY, recordUuid, group.getUuid());
        attributeEngine
                .updateObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, recordUuid, List.of(department));
    }

    private Group group(String name) {
        Group group = new Group();
        group.setName(name);
        return groupRepository.save(group);
    }

    private CustomAttributeV3 departmentAttribute() throws Exception {
        CustomAttributeV3 department = new CustomAttributeV3();
        department.setUuid(UUID.randomUUID().toString());
        department.setName("department");
        department.setType(AttributeType.CUSTOM);
        department.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel("Department");
        department.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(department, List.of(Resource.CRYPTOGRAPHIC_KEY));
        return department;
    }

    private static RequestAttribute departmentValue(CustomAttributeV3 department, String value) {
        RequestAttributeV3 attribute = new RequestAttributeV3();
        attribute.setUuid(UUID.fromString(department.getUuid()));
        attribute.setName(department.getName());
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setContent(List.of(new StringAttributeContentV3(value)));
        return attribute;
    }

    private String departmentOf(UUID keyUuid) {
        List<ResponseAttribute> attributes = attributeEngine
                .getObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, keyUuid);
        assertThat(attributes).singleElement().extracting(ResponseAttribute::getName).isEqualTo("department");
        return ((ResponseAttributeV3) attributes.getFirst()).getContent().getFirst().getData().toString();
    }

    /** Denies the action on the one object, which the caller is then refused unless it owns the object. */
    private void denyOn(Resource resource, ResourceAction action, UUID objectUuid) {
        OpaResourceAccessResult denied = new OpaResourceAccessResult();
        denied.setAuthorized(false);
        when(opaClient
                .checkResourceAccess(any(),
                        argThat(requested -> requested != null && requested.getProperties() != null
                                && resource.getCode().equals(requested.getProperties().get("name"))
                                && action.getCode().equals(requested.getProperties().get("action"))
                                && requested.getObjectUUIDs() != null
                                && requested.getObjectUUIDs().contains(objectUuid.toString())),
                        any(), any()))
                .thenReturn(denied);
    }

    private int queriesListingTheFirstPage() throws Exception {
        return SqlCapture
                .during(() -> tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10))
                .statements()
                .size();
    }

    /** A key pair whose public key a certificate brought into the inventory. */
    private ListedKeyPairV2Dto heldPair(String keyId) throws Exception {
        KeyPair pair = rsaKeyPair();
        certificateKeyWriter
                .uploadCertificatePublicKey("certKey_" + keyId, pair.getPublic(), 2048, fingerprintOf(pair));
        return listed(keyId, "held " + keyId, pair);
    }

    private String handleOfTheFirstListedPair() throws Exception {
        return tokenKeyOnboardingService
                .listTokenKeys(tokenUuid, profileUuid, 1, 10)
                .getItems()
                .get(0)
                .getKeyPairHandle();
    }

    private UUID persistedCertificateCarrying(KeyPair pair) throws Exception {
        CertificateContent content = new CertificateContent();
        content.setContent("certificate-" + UUID.randomUUID());
        content = certificateContentRepository.saveAndFlush(content);
        Certificate certificate = new Certificate();
        certificate.setCommonName("signer");
        certificate.setSubjectDn("CN=signer");
        certificate.setIssuerDn("CN=issuer");
        certificate.setSerialNumber(UUID.randomUUID().toString());
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setCertificateContentId(content.getId());
        certificate.setPublicKeyFingerprint(fingerprintOf(pair));
        return certificateRepository.saveAndFlush(certificate).getUuid();
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static String fingerprintOf(KeyPair pair) throws Exception {
        String spki = Base64.getEncoder().encodeToString(pair.getPublic().getEncoded());
        return CertificateUtil.getThumbprint(spki.getBytes(StandardCharsets.UTF_8));
    }

    private static List<MetadataAttribute> handle(String keyId) {
        MetadataAttributeV3 attribute = new MetadataAttributeV3();
        attribute.setUuid("6b1c9c5e-2f8a-4a7e-9f2d-5b8e1c3a7d40");
        attribute.setName("keyId");
        attribute.setContentType(AttributeContentType.STRING);
        attribute.setProperties(new MetadataAttributeProperties());
        attribute.setContent(List.of(new StringAttributeContentV3(keyId)));
        return List.of(attribute);
    }

    private static ListedKeyPairV2Dto listed(String keyId, String label, KeyPair pair) {
        return listed(keyId, label, pair, KeyAlgorithm.RSA, 2048);
    }

    private static ListedKeyPairV2Dto listed(String keyId, String label, KeyPair pair, KeyAlgorithm algorithm,
            Integer length) {
        ListedKeyPairV2Dto listed = new ListedKeyPairV2Dto();
        listed.setKeyPairMeta(handle(keyId));
        listed.setLabel(label);
        PrivateKeyDataV2Dto privateData = new PrivateKeyDataV2Dto();
        privateData.setAlgorithm(algorithm);
        privateData.setLength(length);
        PrivateKeyDataResponseV2Dto privateKey = new PrivateKeyDataResponseV2Dto();
        privateKey.setKeyMeta(handle(keyId));
        privateKey.setKeyData(privateData);
        listed.setPrivateKeyData(privateKey);
        if (pair != null) {
            PublicKeyDataV2Dto publicData = new PublicKeyDataV2Dto();
            publicData.setAlgorithm(algorithm);
            publicData.setLength(length);
            publicData.setPublicKeySpki(pair.getPublic().getEncoded());
            PublicKeyDataResponseV2Dto publicKey = new PublicKeyDataResponseV2Dto();
            publicKey.setKeyMeta(handle(keyId));
            publicKey.setKeyData(publicData);
            listed.setPublicKeyData(publicKey);
        }
        return listed;
    }

    private static UnaddressableKeyV2Dto unaddressable(String label) {
        PrivateKeyDataV2Dto keyData = new PrivateKeyDataV2Dto();
        keyData.setAlgorithm(KeyAlgorithm.RSA);
        keyData.setLength(2048);
        UnaddressableKeyV2Dto key = new UnaddressableKeyV2Dto();
        key.setLabel(label);
        key.setKeyData(keyData);
        return key;
    }

    private static String page(ListedKeyPairV2Dto... pairs) throws Exception {
        ListKeyPairsResponseV2Dto page = new ListKeyPairsResponseV2Dto();
        page.setItems(Arrays.asList(pairs));
        page.setTotalItems((long) pairs.length);
        return WIRE.writeValueAsString(page);
    }
}
