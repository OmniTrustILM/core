package com.otilm.core.integration.service;

import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.web.CryptographicKeyController;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.attribute.ResponseAttributeV3;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.cryptography.key.OnboardTokenKeysRequestDto;
import com.otilm.api.model.client.cryptography.key.TokenKeySelectionDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.IntegerAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.v2.key.KeyEntryStatus;
import com.otilm.api.model.connector.cryptography.v2.key.ListKeysResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.ListedKeyEntryV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.OnboardTokenKeysResponseDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyListResponseDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyOnboardingOutcome;
import com.otilm.api.model.core.cryptography.key.TokenKeyOnboardingResultDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyStatus;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.otilm.api.model.core.logging.enums.AuditLogOutput;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.logging.enums.OperationResult;
import com.otilm.api.model.core.logging.records.LogRecord;
import com.otilm.api.model.core.logging.records.ResourceObjectIdentity;
import com.otilm.api.model.core.settings.logging.AuditLoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.LoggingSettingsDto;
import com.otilm.api.model.core.settings.logging.ResourceLoggingSettingsDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.KeyImportState;
import com.otilm.core.dao.entity.X509CertificateEntity;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.messaging.model.AuditLogMessage;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyBasicModel;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.KeyImportTerms;
import com.otilm.core.model.crypto.OnboardedKeys;
import com.otilm.core.model.crypto.OnboardedKeys.OnboardedKey;
import com.otilm.core.model.crypto.ProviderKeyPair;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.SettingExternalService;
import com.otilm.core.service.TokenKeyOnboardingExternalService;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.writer.CertificateKeyWriter;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.service.writer.KeyImportWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.LockContention;
import com.otilm.core.util.PqcKeyFixtures;
import com.otilm.core.util.RefusedDefinitionInserts;
import com.otilm.core.util.SqlCapture;
import com.otilm.core.util.TestPublicKeys;
import com.otilm.core.util.builders.CertificateBuilder;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.nio.charset.StandardCharsets;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.concurrent.DelegatingSecurityContextCallable;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static com.otilm.core.util.KeyMetaFixtures.keyIdMeta;
import static com.otilm.core.util.TestPublicKeys.rsaPublicKey;
import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateContentBuilder.aCertificateContent;
import static com.otilm.core.util.builders.KeyPairRequestDtoBuilder.aKeyPairRequest;
import static com.otilm.core.util.builders.ListKeysResponseV2DtoBuilder.aKeyListing;
import static com.otilm.core.util.builders.ListedKeyEntryV2DtoBuilder.aListedKeyPair;
import static com.otilm.core.util.builders.ListedKeyEntryV2DtoBuilder.anUnusableKey;
import static com.otilm.core.util.builders.ListedKeyEntryV2DtoBuilder.keyPairMetaOf;
import static com.otilm.core.util.builders.ProviderKeyPairBuilder.aProviderKeyPair;
import static com.otilm.core.util.builders.RequestAttributeV3Builder.aCustomAttribute;
import static com.otilm.core.util.builders.ResolveKeysResponseV2DtoBuilder.aKeyResolutionResponse;
import static com.otilm.core.util.builders.ResolveKeysResponseV2DtoBuilder.answered;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class TokenKeyOnboardingServiceITest extends BaseSpringBootTest {

    private static final String SLOT_ATTRIBUTE_UUID = "3f6d2a8e-9c41-4b7a-a5e2-7d1c8b0f4e93";
    private static final String REGISTERED_MEANWHILE = "registered meanwhile";

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
    private LockContention lockContention;
    @Autowired
    private CryptographicKeyController cryptographicKeyController;
    @Autowired
    private SettingExternalService settingExternalService;

    private V2TokenFixture.V2Token v2Token;
    private CryptographyProviderV2ConnectorMock connectorMock;
    private UUID tokenUuid;
    private UUID profileUuid;

    @BeforeEach
    void startTokenThatListsKeys() {
        v2Token = v2TokenFixture.start();
        v2TokenFixture.declare(v2Token, FeatureFlag.STATELESS, FeatureFlag.KEY_LIST);
        connectorMock = v2Token.connectorMock();
        tokenUuid = v2Token.token().getUuid();
        profileUuid = v2Token.profile().getUuid();
    }

    @AfterEach
    void stopConnectorAndStoreEveryDefinitionAgain() {
        connectorMock.stop();
        RefusedDefinitionInserts.remove(jdbcTemplate);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** The token lists the key pairs and resolves a selection of each of them, in listing order. */
    private void tokenLists(ListedKeyEntryV2Dto... entries) throws Exception {
        connectorMock.stubKeyListing(aKeyListing().withEntries(entries).build());
        tokenResolves(entries);
    }

    /** The token answers each selection with the answer at its position, whatever the selection names. */
    private void tokenResolves(ListedKeyEntryV2Dto... answers) throws Exception {
        connectorMock.stubKeyResolution(aKeyResolutionResponse().withAnswers(answers).build());
    }

    private void connectorDropsKeyListing() {
        v2TokenFixture.declare(v2Token, FeatureFlag.STATELESS);
    }

    private TokenKeyListResponseDto firstPage() throws Exception {
        return tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 10);
    }

    private TokenKeyDto firstListedEntry() throws Exception {
        return firstPage().getItems().getFirst();
    }

    private TokenKeySelectionDto theFirstListedPair() throws Exception {
        return selecting(firstListedEntry());
    }

    private TokenKeySelectionDto theFirstListedPairNamed(String name) throws Exception {
        return new TokenKeySelectionDto(firstListedEntry().getKeyPairMeta(), name);
    }

    private static TokenKeySelectionDto selecting(TokenKeyDto entry) {
        return new TokenKeySelectionDto(entry.getKeyPairMeta(), null);
    }

    private TokenKeyOnboardingResultDto onboard(TokenKeySelectionDto selection) throws Exception {
        return onboard(selection, null);
    }

    private TokenKeyOnboardingResultDto onboard(TokenKeySelectionDto selection, List<RequestAttribute> customAttributes)
            throws Exception {
        return tokenKeyOnboardingService
                .onboardTokenKeys(tokenUuid, profileUuid,
                        new OnboardTokenKeysRequestDto(List.of(selection), customAttributes))
                .getResults()
                .getFirst();
    }

    private List<TokenKeyOnboardingResultDto> onboardTogether(TokenKeySelectionDto... selections) throws Exception {
        return tokenKeyOnboardingService
                .onboardTokenKeys(tokenUuid, profileUuid, new OnboardTokenKeysRequestDto(List.of(selections), null))
                .getResults();
    }

    private TokenKeyOnboardingResultDto onboardTheFirstListedPair() throws Exception {
        return onboard(theFirstListedPair());
    }

    /** A key onboarded from a key pair the token lists. */
    private UUID anOnboardedKey() throws Exception {
        tokenLists(aListedKeyPair().build());
        return onboardTheFirstListedPair().getKeyUuid();
    }

    private UUID keyPairThePlatformCreated(String name) throws Exception {
        return keyPairThePlatformCreated(name, aProviderKeyPair().build());
    }

    /** A key pair the platform created on the token, as key creation registers it. */
    private UUID keyPairThePlatformCreated(String name, ProviderKeyPair pair) throws Exception {
        TokenProfileFullModel profile = profileModel();
        return cryptographicKeyWriter
                .createKeyWithItems(aKeyPairRequest().withName(name).build(), profile, profile.tokenInstance(),
                        pair.toOnboardedItems(name), false, true)
                .uuid();
    }

    /** Joins the key pair's private key to the record holding its public key, within the caller's transaction. */
    private void privateKeyJoinedMeanwhile(UUID recordUuid, PublicKey publicKey) {
        try {
            var items = aProviderKeyPair().withPublicKey(publicKey).build().toOnboardedItems("joined meanwhile");
            cryptographicKeyWriter
                    .onboardIntoRecordUnlessImporting(recordUuid, profileModel(), fingerprintOf(publicKey), items);
            cryptographicKeyItemRepository.flush();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    private void removeFromInventory(UUID keyUuid) throws Exception {
        cryptographicKeyService.removeKeyFromInventory(SecuredUUID.fromUUID(keyUuid));
    }

    private KeyDetailDto keyDetail(UUID keyUuid) throws Exception {
        return cryptographicKeyService.getKey(SecuredUUID.fromUUID(keyUuid));
    }

    private List<String> keyListableProfiles() {
        return tokenProfileService
                .listTokenProfiles(Optional.empty(), List.of(), true, SecurityFilter.create())
                .stream()
                .map(TokenProfileDto::getUuid)
                .toList();
    }

    private TokenProfileFullModel profileModel() {
        return tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(profileUuid, tokenUuid)
                .orElseThrow();
    }

    /** An attempt to import a key pair holding the public key, in the given state. */
    private UUID importOf(PublicKey publicKey, KeyImportState state) throws Exception {
        KeyImportTerms terms = new KeyImportTerms(profileModel(), KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA,
                fingerprintOf(publicKey), false, List.of(),
                new NameAndUuidDto(UUID.randomUUID().toString(), "requester"));
        UUID attempt = keyImportWriter
                .open(terms, "import-" + UUID.randomUUID(), "imported key", List.of("sent-secret-digest"))
                .uuid();
        jdbcTemplate.update("UPDATE key_import SET state = ? WHERE uuid = ?", state.name(), attempt);
        return attempt;
    }

    /** A public-key-only record, as an uploaded certificate brings it into the inventory. */
    private UUID recordHolding(String name, PublicKey publicKey) throws Exception {
        return certificateKeyWriter.uploadCertificatePublicKey(name, publicKey, 2048, fingerprintOf(publicKey));
    }

    private UUID publicKeyInTheToken(String name, PublicKey publicKey) throws Exception {
        return publicKeyIn(tokenUuid, profileUuid, name, publicKey);
    }

    /** A token other than the listing one, whose provider is never asked. */
    private V2TokenFixture.V2Token anotherToken() {
        V2TokenFixture.V2Token another = v2TokenFixture.start();
        another.connectorMock().stop();
        return another;
    }

    private UUID publicKeyIn(V2TokenFixture.V2Token token, String name, PublicKey publicKey) throws Exception {
        return publicKeyIn(token.token().getUuid(), token.profile().getUuid(), name, publicKey);
    }

    private UUID publicKeyIn(UUID tokenInstanceUuid, UUID tokenProfileUuid, String name, PublicKey publicKey)
            throws Exception {
        UUID publicKeyRecord = recordHolding(name, publicKey);
        CryptographicKey inToken = cryptographicKeyRepository.findByUuid(publicKeyRecord).orElseThrow();
        inToken.setTokenProfileUuid(tokenProfileUuid);
        inToken.setTokenInstanceReferenceUuid(tokenInstanceUuid);
        cryptographicKeyRepository.saveAndFlush(inToken);
        return publicKeyRecord;
    }

    /** A listed key pair whose public key a key in the listing token holds without its private key. */
    private ListedKeyEntryV2Dto pairHeldInTheToken(String recordName) throws Exception {
        PublicKey publicKey = rsaPublicKey();
        publicKeyInTheToken(recordName, publicKey);
        return aListedKeyPair().withPublicKey(publicKey).build();
    }

    /** A listed key pair whose public key an uploaded certificate brought into the inventory. */
    private ListedKeyEntryV2Dto heldPair(String recordName) throws Exception {
        PublicKey publicKey = rsaPublicKey();
        recordHolding(recordName, publicKey);
        return aListedKeyPair().withPublicKey(publicKey).build();
    }

    /** An ML-DSA key pair, which a token lists without a length. */
    private static ListedKeyEntryV2Dto postQuantumPair() throws Exception {
        return aListedKeyPair()
                .withAlgorithm(KeyAlgorithm.MLDSA)
                .withLength(null)
                .withPublicKey(PqcKeyFixtures.keyPair().getPublic())
                .build();
    }

    private void withItemsIn(UUID keyUuid, KeyState state) {
        List<CryptographicKeyItem> items = cryptographicKeyItemRepository.findByKeyUuidIn(List.of(keyUuid));
        items.forEach(item -> item.setState(state));
        cryptographicKeyItemRepository.saveAllAndFlush(items);
    }

    private static Map<UUID, KeyState> itemStatesOf(CryptographicKeyFullModel key) {
        return key
                .items()
                .stream()
                .collect(Collectors.toMap(CryptographicKeyItemBasicModel::uuid, CryptographicKeyItemBasicModel::state));
    }

    /** Hands the key to another owner, whom an action denied on the key leaves allowed. */
    private void ownedBySomeoneElse(UUID keyUuid) {
        objectAssociationService.setOwner(Resource.CRYPTOGRAPHIC_KEY, keyUuid, UUID.randomUUID(), "another");
    }

    /** Gives the record a description, an owner, a group and a department, as another user would have. */
    private void describedOwnedAndGrouped(UUID recordUuid, String description, UUID ownerUuid, Group group,
            RequestAttribute department) throws Exception {
        CryptographicKey described = cryptographicKeyRepository.findById(recordUuid).orElseThrow();
        described.setDescription(description);
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
        return aCustomAttribute()
                .withUuid(department.getUuid())
                .withName(department.getName())
                .withStringContent(value)
                .build();
    }

    private String departmentOf(UUID keyUuid) {
        List<ResponseAttribute> attributes = attributeEngine
                .getObjectCustomAttributesContent(Resource.CRYPTOGRAPHIC_KEY, keyUuid);
        assertThat(attributes).singleElement().extracting(ResponseAttribute::getName).isEqualTo("department");
        return ((ResponseAttributeV3) attributes.getFirst()).getContent().getFirst().getData().toString();
    }

    /** Lists the page once, so what only a first listing loads stays out of the query count. */
    private void warmUpListing(ListKeysResponseV2Dto page) throws Exception {
        queriesListing(page);
    }

    private int queriesListing(ListKeysResponseV2Dto page) throws Exception {
        connectorMock.stubKeyListing(page);
        return SqlCapture.during(this::firstPage).statements().size();
    }

    /** Onboards the pairs once, so what only a first onboarding loads stays out of the query count. */
    private void warmUpOnboarding(List<ListedKeyEntryV2Dto> pairs) throws Exception {
        queriesOnboarding(pairs);
    }

    private int queriesOnboarding(List<ListedKeyEntryV2Dto> pairs) throws Exception {
        tokenLists(pairs.toArray(ListedKeyEntryV2Dto[]::new));
        TokenKeySelectionDto[] selections = firstPage()
                .getItems()
                .stream()
                .map(TokenKeyOnboardingServiceITest::selecting)
                .toArray(TokenKeySelectionDto[]::new);
        return SqlCapture.during(() -> onboardTogether(selections)).statements().size();
    }

    private UUID certificateCarrying(PublicKey publicKey) throws Exception {
        return certificateRepository.saveAndFlush(issuedCertificateCarrying(publicKey).build()).getUuid();
    }

    private UUID certificateOf(UUID keyUuid, PublicKey publicKey) throws Exception {
        return certificateRepository
                .saveAndFlush(issuedCertificateCarrying(publicKey).withKeyUuid(keyUuid).build())
                .getUuid();
    }

    /** A hybrid certificate whose alternative key carries the public key. */
    private UUID hybridCertificateWithAlternativeKey(PublicKey altPublicKey) throws Exception {
        X509CertificateEntity certificate = X509CertificateEntity
                .from(issuedCertificateCarrying(rsaPublicKey()).build());
        certificate.setHybridCertificate(true);
        certificate.setAltKeyFingerprint(fingerprintOf(altPublicKey));
        return certificateRepository.saveAndFlush(certificate).getUuid();
    }

    private CertificateBuilder issuedCertificateCarrying(PublicKey publicKey) throws Exception {
        CertificateContent content = certificateContentRepository
                .saveAndFlush(aCertificateContent().withContent("certificate-" + UUID.randomUUID()).build());
        return aCertificate()
                .withCommonName("signer")
                .withSubjectDn("CN=signer")
                .withIssuerDn("CN=issuer")
                .withSerialNumber(UUID.randomUUID().toString())
                .withState(CertificateState.ISSUED)
                .withValidationStatus(CertificateValidationStatus.VALID)
                .withCertificateContentId(content.getId())
                .withPublicKeyFingerprint(fingerprintOf(publicKey));
    }

    private static String fingerprintOf(PublicKey publicKey) throws Exception {
        return CertificateUtil.getThumbprint(TestPublicKeys.spkiBase64(publicKey).getBytes(StandardCharsets.UTF_8));
    }

    /** A metadata attribute the connector reports on its keys, with no content yet. */
    private static MetadataAttributeV3 slotMetadata(AttributeContentType contentType) {
        MetadataAttributeV3 slot = new MetadataAttributeV3();
        slot.setUuid(SLOT_ATTRIBUTE_UUID);
        slot.setName("slot");
        slot.setContentType(contentType);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel("Slot");
        slot.setProperties(properties);
        return slot;
    }

    /** A metadata definition the connector registered on an earlier operation. */
    private void connectorRegistered(MetadataAttributeV3 definition) throws Exception {
        attributeEngine.updateMetadataAttributeDefinition(definition, profileModel().tokenInstance().connectorUuid());
    }

    private static ListedKeyEntryV2Dto pairWithPrivateKeyMetadata(String storageName, MetadataAttributeV3 metadata) {
        return aListedKeyPair().withStorageName(storageName).withMetadata(List.of(metadata)).build();
    }

    // ── Listing ───────────────────────────────────────────────────────────────

    @Nested
    class Listing {

        @Test
        void listsEachKeyPairWithItsStatus_inTheOrderTheTokenListsThem() throws Exception {
            // given
            tokenLists(aListedKeyPair().build(), heldPair("certKey_held"), aListedKeyPair().withoutPublicKey().build());

            // when
            TokenKeyListResponseDto listing = firstPage();

            // then
            assertThat(listing.getTotalItems()).isEqualTo(3);
            assertThat(listing.getItems())
                    .extracting(TokenKeyDto::getStatus)
                    .containsExactly(TokenKeyStatus.ONBOARDABLE, TokenKeyStatus.ONBOARDABLE_INTO_KEY,
                            TokenKeyStatus.PUBLIC_KEY_UNAVAILABLE);
        }

        @Test
        void describesTheKeyPairUnderItsStorageName_whenTheInventoryLacksIt() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var storageName = "signer";
            tokenLists(aListedKeyPair().withStorageName(storageName).withPublicKey(publicKey).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStorageName()).isEqualTo(storageName);
            assertThat(entry.getSuggestedName()).isEqualTo(storageName);
            assertThat(entry.getFingerprint()).isEqualTo(fingerprintOf(publicKey));
            assertThat(entry.getKeyAlgorithm()).isEqualTo(KeyAlgorithm.RSA);
            assertThat(entry.getReason()).isNull();
        }

        @Test
        void suggestsADistinctNameForEachKeyPair_whenTwoShareAStorageName() throws Exception {
            // given
            var storageName = "signer";
            var secondPublicKey = rsaPublicKey();
            tokenLists(aListedKeyPair().withStorageName(storageName).build(),
                    aListedKeyPair().withStorageName(storageName).withPublicKey(secondPublicKey).build());

            // when
            List<TokenKeyDto> entries = firstPage().getItems();

            // then
            String secondName = "%s (%s)".formatted(storageName, fingerprintOf(secondPublicKey).substring(0, 8));
            assertThat(entries).extracting(TokenKeyDto::getSuggestedName).containsExactly(storageName, secondName);
        }

        @Test
        void suggestsALongerFingerprintPrefix_whenKeysHaveTheStorageNameAndItsShortPrefix() throws Exception {
            // given
            var storageName = "signer";
            var publicKey = rsaPublicKey();
            String fingerprint = fingerprintOf(publicKey);
            recordHolding(storageName, rsaPublicKey());
            recordHolding("%s (%s)".formatted(storageName, fingerprint.substring(0, 8)), rsaPublicKey());
            tokenLists(aListedKeyPair().withStorageName(storageName).withPublicKey(publicKey).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getSuggestedName())
                    .isEqualTo("%s (%s)".formatted(storageName, fingerprint.substring(0, 9)));
        }

        @Test
        void namesTheRecordInsteadOfAName_whenACertificateBroughtThePublicKeyIn() throws Exception {
            // given
            var recordName = "certKey_held";
            tokenLists(heldPair(recordName));

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getInventoryKeyName()).isEqualTo(recordName);
            assertThat(entry.getSuggestedName()).isNull();
        }

        @Test
        void givesTheReason_whenTheTokenHoldsNoPublicKeyForThePair() throws Exception {
            // given
            tokenLists(aListedKeyPair().withoutPublicKey().build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getReason()).isEqualTo("The key storage holds no public key for this key pair.");
        }

        @Test
        void asksTheTokenForThePageFromItsStart_whenListingTheFirstPage() throws Exception {
            // given
            tokenLists(aListedKeyPair().build());

            // when
            firstPage();

            // then
            connectorMock.verifyKeyListingRequestContaining("""
                    {"offset": 0, "limit": 10}
                    """);
        }

        @Test
        void namesNoRecord_whenTheCallerMayNotSeeTheRecordHoldingThePublicKey() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var hidden = recordHolding("certKey_hidden", publicKey);
            denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, hidden);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.ONBOARDABLE_INTO_KEY);
            assertThat(entry.getInventoryKeyUuid()).isNull();
            assertThat(entry.getInventoryKeyName()).isNull();
        }

        @Test
        void listsItHeldWithoutAToken_whenTheCallerMayNotUpdateTheRecord() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var recordName = "certKey_locked";
            var publicKeyRecord = recordHolding(recordName, publicKey);
            denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE, publicKeyRecord);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY_WITHOUT_TOKEN);
            assertThat(entry.getInventoryKeyName()).isEqualTo(recordName);
            assertThat(entry.getReason()).isEqualTo(KeyImportGates.NOT_UPDATABLE.formatted(recordName));
        }

        @Test
        void listsItHeldWithoutAToken_whenTheRecordIsNotActive() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var holderName = "certKey_inactive";
            var publicKeyRecord = recordHolding(holderName, publicKey);
            withItemsIn(publicKeyRecord, KeyState.DEACTIVATED);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY_WITHOUT_TOKEN);
            assertThat(entry.getReason())
                    .startsWith("Key '%s' holds this public key without a token instance".formatted(holderName));
        }

        @Test
        void namesTheKeyHoldingThePair_whenTheInventoryHoldsIt() throws Exception {
            // given
            var storageName = "signer";
            tokenLists(aListedKeyPair().withStorageName(storageName).build());
            onboardTheFirstListedPair();

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY);
            assertThat(entry.getInventoryKeyName()).isEqualTo(storageName);
            assertThat(entry.getReason()).isEqualTo("Key '%s' already holds this key pair.".formatted(storageName));
        }

        @Test
        void listsItInTheInventory_whenAPublicKeyInATokenHoldsIt() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var recordName = "certKey_in_token";
            publicKeyInTheToken(recordName, publicKey);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY);
            assertThat(entry.getReason()).isEqualTo(KeyImportGates.HELD_IN_TOKEN.formatted(recordName));
        }

        @Test
        void givesANeutralReason_whenAKeyTheCallerMayNotSeeHoldsThePair() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var hidden = publicKeyInTheToken("certKey_hidden", publicKey);
            denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, hidden);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY);
            assertThat(entry.getInventoryKeyName()).isNull();
            assertThat(entry.getReason()).isEqualTo(CryptographicKeyWriter.KEY_ALREADY_HELD);
        }

        @Test
        void givesANeutralReason_whenTheCallerMayNotSeeTheMembersOfTheTokenHoldingThePair() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var another = anotherToken();
            publicKeyIn(another, "certKey_elsewhere", publicKey);
            denyResourceAccess(Resource.TOKEN, ResourceAction.MEMBERS, another.token().getUuid());
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY);
            assertThat(entry)
                    .extracting(TokenKeyDto::getInventoryKeyUuid, TokenKeyDto::getInventoryKeyName)
                    .containsOnlyNulls();
            assertThat(entry.getReason()).isEqualTo(CryptographicKeyWriter.KEY_ALREADY_HELD);
        }

        @Test
        void listsEachKeyInTheTokensOrder_whenAnUnusableKeySitsBetweenKeyPairs() throws Exception {
            // given
            var first = aListedKeyPair().withStorageName("first").build();
            var between = anUnusableKey().withStorageName("between").build();
            var last = aListedKeyPair().withStorageName("last").build();
            connectorMock.stubKeyListing(aKeyListing().withEntries(first, between, last).build());

            // when
            TokenKeyListResponseDto page = firstPage();

            // then
            assertThat(page.getItems())
                    .extracting(TokenKeyDto::getStorageName, TokenKeyDto::getStatus)
                    .containsExactly(tuple("first", TokenKeyStatus.ONBOARDABLE),
                            tuple("between", TokenKeyStatus.UNADDRESSABLE), tuple("last", TokenKeyStatus.ONBOARDABLE));
        }

        @Test
        void describesItsKeyDataAlone_whenAKeyIsUnusable() throws Exception {
            // given
            var storageName = "legacy";
            connectorMock
                    .stubKeyListing(
                            aKeyListing().withEntries(anUnusableKey().withStorageName(storageName).build()).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry)
                    .extracting(TokenKeyDto::getStorageName, TokenKeyDto::getKeyAlgorithm, TokenKeyDto::getLength)
                    .containsExactly(storageName, KeyAlgorithm.RSA, 2048);
            assertThat(entry)
                    .extracting(TokenKeyDto::getKeyPairMeta, TokenKeyDto::getFingerprint,
                            TokenKeyDto::getInventoryKeyUuid, TokenKeyDto::getInventoryKeyName,
                            TokenKeyDto::getSuggestedName)
                    .containsOnlyNulls();
            assertThat(entry.getReason()).isEqualTo("The connector cannot address this key alone.");
        }

        @Test
        void countsAnUnusableKeyTowardThePages_whenTheTokenListsOne() throws Exception {
            // given
            connectorMock
                    .stubKeyListing(aKeyListing()
                            .withEntries(aListedKeyPair().build(), anUnusableKey().build())
                            .withTotalItems(5)
                            .build());

            // when
            TokenKeyListResponseDto page = tokenKeyOnboardingService.listTokenKeys(tokenUuid, profileUuid, 1, 2);

            // then
            assertThat(page)
                    .extracting(TokenKeyListResponseDto::getTotalItems, TokenKeyListResponseDto::getItemsPerPage,
                            TokenKeyListResponseDto::getTotalPages)
                    .containsExactly(5L, 2, 3);
        }

        @ParameterizedTest
        @MethodSource("unusableKeyStatuses")
        void listsAnUnusableKeyWithTheStatusOfItsEntry(KeyEntryStatus connectorStatus, TokenKeyStatus status,
                String text) throws Exception {
            // given
            connectorMock
                    .stubKeyListing(
                            aKeyListing().withEntries(anUnusableKey().withStatus(connectorStatus).build()).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry).extracting(TokenKeyDto::getStatus, TokenKeyDto::getReason).containsExactly(status, text);
        }

        @Test
        void carriesTheConnectorsDiagnostic_whenAKeyIsUnusable() throws Exception {
            // given
            var noKeyId = "The private key has no CKA_ID, by which this connector addresses a key.";
            connectorMock
                    .stubKeyListing(aKeyListing().withEntries(anUnusableKey().withDiagnostic(noKeyId).build()).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getDiagnostic()).isEqualTo(noKeyId);
        }

        @Test
        void listsItAsRefused_whenTheConnectorRefusesAKeyPairTheInventoryLacks() throws Exception {
            // given
            tokenLists(aListedKeyPair().withStatus(KeyEntryStatus.REFUSED).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry)
                    .extracting(TokenKeyDto::getStatus, TokenKeyDto::getReason, TokenKeyDto::getSuggestedName)
                    .containsExactly(TokenKeyStatus.REFUSED,
                            "The connector refuses to let the platform onboard this key.", null);
        }

        @Test
        void listsItAsRefused_whenTheConnectorRefusesAKeyPairThatCouldJoinAnInventoryKey() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            recordHolding("certKey_held", publicKey);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).withStatus(KeyEntryStatus.REFUSED).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.REFUSED);
        }

        @Test
        void listsItAsRefused_whenTheConnectorRefusesAKeyPairARecordTheCallerMayNotUpdateHolds() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var recordName = "certKey_locked";
            var publicKeyRecord = recordHolding(recordName, publicKey);
            denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE, publicKeyRecord);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).withStatus(KeyEntryStatus.REFUSED).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry)
                    .extracting(TokenKeyDto::getStatus, TokenKeyDto::getReason, TokenKeyDto::getInventoryKeyName)
                    .containsExactly(TokenKeyStatus.REFUSED,
                            "The connector refuses to let the platform onboard this key.", recordName);
        }

        @Test
        void listsItAsRefused_whenTheConnectorRefusesAKeyPairAnInactiveRecordHolds() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var recordName = "certKey_inactive";
            var publicKeyRecord = recordHolding(recordName, publicKey);
            withItemsIn(publicKeyRecord, KeyState.DEACTIVATED);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).withStatus(KeyEntryStatus.REFUSED).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry)
                    .extracting(TokenKeyDto::getStatus, TokenKeyDto::getReason, TokenKeyDto::getInventoryKeyName)
                    .containsExactly(TokenKeyStatus.REFUSED,
                            "The connector refuses to let the platform onboard this key.", recordName);
        }

        @Test
        void listsItAsInInventory_whenTheConnectorRefusesAKeyPairTheInventoryHolds() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());
            onboardTheFirstListedPair();
            tokenLists(aListedKeyPair().withPublicKey(publicKey).withStatus(KeyEntryStatus.REFUSED).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY);
        }

        @Test
        void listsItAsRefused_whenTheConnectorRefusesAKeyPairListedWithoutAPublicKey() throws Exception {
            // given
            tokenLists(aListedKeyPair().withoutPublicKey().withStatus(KeyEntryStatus.REFUSED).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry)
                    .extracting(TokenKeyDto::getStatus, TokenKeyDto::getReason)
                    .containsExactly(TokenKeyStatus.REFUSED,
                            "The connector refuses to let the platform onboard this key.");
        }

        @Test
        void listsItAsRefused_whenTheConnectorRefusesAKeyPairAnUnsettledImportHolds() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            importOf(publicKey, KeyImportState.ACCEPTED);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).withStatus(KeyEntryStatus.REFUSED).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.REFUSED);
        }

        @Test
        void carriesTheConnectorsDiagnostic_whenTheConnectorRefusesAKeyPair() throws Exception {
            // given
            var refusalCause = "CKA_EXTRACTABLE is true on this private key.";
            tokenLists(aListedKeyPair().withStatus(KeyEntryStatus.REFUSED).withDiagnostic(refusalCause).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getDiagnostic()).isEqualTo(refusalCause);
        }

        @Test
        void listsNoAlgorithmOrLength_whenTheConnectorCannotReadTheKey() throws Exception {
            // given
            connectorMock
                    .stubKeyListing(aKeyListing()
                            .withEntries(anUnusableKey().withStatus(KeyEntryStatus.UNREADABLE).withoutKeyData().build())
                            .build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry)
                    .extracting(TokenKeyDto::getStatus, TokenKeyDto::getKeyAlgorithm, TokenKeyDto::getLength)
                    .containsExactly(TokenKeyStatus.UNREADABLE, null, null);
        }

        @Test
        void listsItsParameterSetAndPrivateSize_whenAnUnusableKeyCarriesItsIdentifier() throws Exception {
            // given
            connectorMock
                    .stubKeyListing(aKeyListing()
                            .withEntries(anUnusableKey()
                                    .withAlgorithm(KeyAlgorithm.MLDSA)
                                    .withLength(null)
                                    .withAlgorithmIdentifier(PqcKeyFixtures.algorithmIdentifier())
                                    .build())
                            .build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry)
                    .extracting(TokenKeyDto::getStatus, TokenKeyDto::getKeyAlgorithm, TokenKeyDto::getParameterSet,
                            TokenKeyDto::getLength)
                    .containsExactly(TokenKeyStatus.UNADDRESSABLE, KeyAlgorithm.MLDSA,
                            PqcKeyFixtures.ML_DSA_PARAMETER_SET, PqcKeyFixtures.ML_DSA_PRIVATE_KEY_BITS);
        }

        /** An import the reconciliation still has to settle may yet register the key pair or destroy it. */
        @ParameterizedTest
        @EnumSource(value = KeyImportState.class, names = {"REQUESTED", "ACCEPTED", "COMPENSATING"})
        void listsItAsImportInProgress_whenAnUnsettledImportHoldsIt(KeyImportState state) throws Exception {
            // given
            var publicKey = rsaPublicKey();
            importOf(publicKey, state);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.IMPORT_IN_PROGRESS);
            assertThat(entry.getSuggestedName()).isNull();
        }

        @Test
        void listsItOnboardable_whenItsImportFailed() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            importOf(publicKey, KeyImportState.FAILED);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry.getStatus()).isEqualTo(TokenKeyStatus.ONBOARDABLE);
        }

        @Test
        void listsItByItsParameterSetAndPublicSize_whenThePairIsPostQuantum() throws Exception {
            // given
            tokenLists(postQuantumPair());

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry)
                    .extracting(TokenKeyDto::getStatus, TokenKeyDto::getKeyAlgorithm, TokenKeyDto::getParameterSet,
                            TokenKeyDto::getLength)
                    .containsExactly(TokenKeyStatus.ONBOARDABLE, KeyAlgorithm.MLDSA,
                            PqcKeyFixtures.ML_DSA_PARAMETER_SET, PqcKeyFixtures.ML_DSA_PUBLIC_KEY_BITS);
        }

        @Test
        void listsItByItsParameterSetAndPrivateSize_whenTheTokenHoldsOnlyThePrivateKey() throws Exception {
            // given
            var privateKeyOnly = aListedKeyPair()
                    .withAlgorithm(KeyAlgorithm.MLDSA)
                    .withLength(null)
                    .withAlgorithmIdentifier(PqcKeyFixtures.algorithmIdentifier())
                    .withoutPublicKey()
                    .build();
            tokenLists(privateKeyOnly);

            // when
            TokenKeyDto entry = firstListedEntry();

            // then
            assertThat(entry)
                    .extracting(TokenKeyDto::getKeyAlgorithm, TokenKeyDto::getParameterSet, TokenKeyDto::getLength)
                    .containsExactly(KeyAlgorithm.MLDSA, PqcKeyFixtures.ML_DSA_PARAMETER_SET,
                            PqcKeyFixtures.ML_DSA_PRIVATE_KEY_BITS);
        }

        @Test
        void readsTheInventoryOnce_whenThePageHoldsMoreKeyPairs() throws Exception {
            // given
            var smallPage = aKeyListing()
                    .withEntries(heldPair("certKey_0a"), aListedKeyPair().withStorageName("signer 0b").build())
                    .build();
            var largePage = aKeyListing()
                    .withEntries(heldPair("certKey_1a"), heldPair("certKey_1b"), heldPair("certKey_1c"),
                            aListedKeyPair().withStorageName("signer 1d").build(),
                            aListedKeyPair().withStorageName("signer 1e").build(),
                            aListedKeyPair().withStorageName("signer 1f").build())
                    .build();
            warmUpListing(smallPage);

            // when
            int smallPageQueries = queriesListing(smallPage);
            int largePageQueries = queriesListing(largePage);

            // then
            assertThat(largePageQueries).isEqualTo(smallPageQueries);
        }

        /** The offset of a page this far exceeds an int, and would wrap to the offset of another page. */
        @Test
        void refusesThePageWithoutAskingTheToken_whenItStartsBeyondTheLargestOffset() throws Exception {
            // given
            tokenLists(aListedKeyPair().build());
            var pageNumber = 4_294_969;
            var itemsPerPage = 1000;

            // when
            ThrowingCallable listPage = () -> tokenKeyOnboardingService
                    .listTokenKeys(tokenUuid, profileUuid, pageNumber, itemsPerPage);

            // then
            assertThatThrownBy(listPage)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("The page must start at most 2147483647 entries into the listing.");
            connectorMock.verifyKeyListingRequests(0);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static Stream<Arguments> unusableKeyStatuses() {
            return Stream
                    .of(arguments(KeyEntryStatus.UNADDRESSABLE, TokenKeyStatus.UNADDRESSABLE,
                            "The connector cannot address this key alone."),
                            arguments(KeyEntryStatus.UNSUPPORTED_TYPE, TokenKeyStatus.UNSUPPORTED_KEY_TYPE,
                                    "The connector cannot operate a key of this type."),
                            arguments(KeyEntryStatus.UNREADABLE, TokenKeyStatus.UNREADABLE,
                                    "The connector cannot read this key."),
                            arguments(KeyEntryStatus.NOT_FOUND, TokenKeyStatus.GONE,
                                    "The key storage no longer holds this key pair."));
        }
    }

    // ── Onboarding ────────────────────────────────────────────────────────────

    @Nested
    class Onboarding {

        @Test
        void createsTheKeyOnTheProfile_whenTheInventoryLacksThePair() throws Exception {
            // given
            var storageName = "signer";
            tokenLists(aListedKeyPair().withStorageName(storageName).build());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result.getOutcome()).isEqualTo(TokenKeyOnboardingOutcome.ONBOARDED);
            assertThat(result.getKeyName()).isEqualTo(storageName);
            CryptographicKey onboarded = cryptographicKeyRepository.findByUuid(result.getKeyUuid()).orElseThrow();
            assertThat(onboarded.getTokenProfileUuid()).isEqualTo(profileUuid);
            assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(onboarded.getUuid())))
                    .hasSize(2)
                    .noneMatch(CryptographicKeyItem::isExportable)
                    .noneMatch(CryptographicKeyItem::isEnabled);
            assertThat(keyDetail(onboarded.getUuid()).getOwner()).isEqualTo("tst-user");
        }

        @Test
        void namesTheKeyWithALongerFingerprintPrefix_whenKeysHaveTheStorageNameAndItsShortPrefix() throws Exception {
            // given
            var storageName = "signer";
            var publicKey = rsaPublicKey();
            String fingerprint = fingerprintOf(publicKey);
            recordHolding(storageName, rsaPublicKey());
            recordHolding("%s (%s)".formatted(storageName, fingerprint.substring(0, 8)), rsaPublicKey());
            tokenLists(aListedKeyPair().withStorageName(storageName).withPublicKey(publicKey).build());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result.getOutcome()).isEqualTo(TokenKeyOnboardingOutcome.ONBOARDED);
            assertThat(result.getKeyName()).isEqualTo("%s (%s)".formatted(storageName, fingerprint.substring(0, 9)));
        }

        @Test
        void linksTheCertificateCarryingThePublicKey_whenItCreatesTheKey() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var certificateUuid = certificateCarrying(publicKey);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(certificateRepository.findById(certificateUuid).orElseThrow().getKeyUuid())
                    .isEqualTo(result.getKeyUuid());
        }

        @Test
        void linksTheCertificateCarryingThePublicKeyAsItsAlternativeKey_whenItOnboardsTheKeyAgain() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var certificateUuid = hybridCertificateWithAlternativeKey(publicKey);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());
            removeFromInventory(onboardTheFirstListedPair().getKeyUuid());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(certificateRepository.findById(certificateUuid).orElseThrow().getAltKeyUuid())
                    .isEqualTo(result.getKeyUuid());
        }

        @Test
        void resolvesEachSelectionUnderItsPosition_whenItOnboardsThem() throws Exception {
            // given
            tokenLists(aListedKeyPair().withKeyId("signer-id").build(),
                    aListedKeyPair().withKeyId("archive-id").build());
            var signer = new TokenKeySelectionDto(keyIdMeta("signer-id"), null);
            var archive = new TokenKeySelectionDto(keyIdMeta("archive-id"), null);

            // when
            onboardTogether(signer, archive);

            // then
            connectorMock.verifyKeyResolutionRequestContaining("""
                    {"keyRequestType": "keyPair", "keys": [
                        {"identifier": "0", "keyMeta": [{"name": "keyId", "content": [{"data": "signer-id"}]}]},
                        {"identifier": "1", "keyMeta": [{"name": "keyId", "content": [{"data": "archive-id"}]}]}]}
                    """);
            connectorMock.verifyKeyListingRequests(0);
        }

        @Test
        void namesTheKeyAsTheSelectionDoes_whenItGivesAName() throws Exception {
            // given
            tokenLists(aListedKeyPair().build());
            var name = "Payments signer";
            var selection = theFirstListedPairNamed(name);

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result.getKeyName()).isEqualTo(name);
        }

        @Test
        void writesTheCustomAttributes_whenItCreatesTheKey() throws Exception {
            // given
            var department = departmentAttribute();
            tokenLists(aListedKeyPair().build());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection, List.of(departmentValue(department, "payments")));

            // then
            assertThat(departmentOf(result.getKeyUuid())).isEqualTo("payments");
        }

        @Test
        void refusesWithoutReadingTheTokenAgain_whenItCannotWriteACustomAttribute() throws Exception {
            // given
            var storageName = "signer";
            tokenLists(aListedKeyPair().withStorageName(storageName).build());
            var selection = theFirstListedPair();
            List<RequestAttribute> undefined = List
                    .of(aCustomAttribute()
                            .withUuid(UUID.randomUUID())
                            .withName("undefined")
                            .withStringContent("x")
                            .build());

            // when
            ThrowingCallable onboard = () -> onboard(selection, undefined);

            // then
            assertThatThrownBy(onboard).isInstanceOf(ValidationException.class);
            connectorMock.verifyKeyResolutionRequests(0);
            assertThat(cryptographicKeyRepository.existsByName(storageName)).isFalse();
        }

        @Test
        void refusesWithoutReadingTheTokenAgain_whenItMayNotWriteACustomAttribute() throws Exception {
            // given
            var department = departmentAttribute();
            denyObjectAccess(Resource.ATTRIBUTE, ResourceAction.MEMBERS);
            var storageName = "signer";
            tokenLists(aListedKeyPair().withStorageName(storageName).build());
            var selection = theFirstListedPair();
            List<RequestAttribute> forbidden = List.of(departmentValue(department, "payments"));

            // when
            ThrowingCallable onboard = () -> onboard(selection, forbidden);

            // then
            assertThatThrownBy(onboard)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Not allowed to set custom attributes: department");
            connectorMock.verifyKeyResolutionRequests(0);
            assertThat(cryptographicKeyRepository.existsByName(storageName)).isFalse();
        }

        @Test
        void joinsTheRecordHoldingThePublicKey_whenACertificateBroughtItIn() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var recordName = "certKey_signer";
            var publicKeyRecord = recordHolding(recordName, publicKey);
            var certificateUuid = certificateOf(publicKeyRecord, publicKey);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());
            var ignoredName = "ignored";
            var selection = theFirstListedPairNamed(ignoredName);

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getKeyUuid,
                            TokenKeyOnboardingResultDto::getKeyName)
                    .containsExactly(TokenKeyOnboardingOutcome.JOINED_EXISTING_KEY, publicKeyRecord, recordName);
            assertThat(keyDetail(publicKeyRecord).getTokenProfileUuid()).isEqualTo(profileUuid.toString());
            List<CryptographicKeyItem> items = cryptographicKeyItemRepository.findByKeyUuidIn(List.of(publicKeyRecord));
            assertThat(items)
                    .extracting(CryptographicKeyItem::getType, CryptographicKeyItem::isExportable)
                    .containsExactlyInAnyOrder(tuple(KeyType.PUBLIC_KEY, false), tuple(KeyType.PRIVATE_KEY, false));
            assertThat(items).allSatisfy(item -> assertThat(item.getKeyMeta()).isNotEmpty());
            assertThat(items)
                    .filteredOn(item -> item.getType() == KeyType.PRIVATE_KEY)
                    .singleElement()
                    .extracting(CryptographicKeyItem::isEnabled)
                    .isEqualTo(false);
            assertThat(certificateRepository.findById(certificateUuid).orElseThrow().getKeyUuid())
                    .isEqualTo(publicKeyRecord);
            assertThat(cryptographicKeyRepository.existsByName(ignoredName)).isFalse();
        }

        @Test
        void keepsTheRecordsDescriptionOwnerGroupAndAttributes_whenItJoinsTheRecord() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var publicKeyRecord = recordHolding("certKey_signer", publicKey);
            var description = "the certificate's key";
            var ownerUuid = UUID.randomUUID();
            var group = group("signers");
            var department = departmentAttribute();
            var recordsDepartment = departmentValue(department, "the record's");
            describedOwnedAndGrouped(publicKeyRecord, description, ownerUuid, group, recordsDepartment);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());
            var selection = theFirstListedPair();

            // when
            onboard(selection, List.of(departmentValue(department, "the request's")));

            // then
            KeyDetailDto key = keyDetail(publicKeyRecord);
            assertThat(key.getDescription()).isEqualTo(description);
            assertThat(key.getOwnerUuid()).isEqualTo(ownerUuid.toString());
            assertThat(key.getGroups()).extracting(NameAndUuidDto::getUuid).containsExactly(group.getUuid().toString());
            assertThat(departmentOf(publicKeyRecord)).isEqualTo("the record's");
        }

        @Test
        void linksTheOtherCertificatesCarryingThePublicKey_whenItJoinsTheRecord() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var publicKeyRecord = recordHolding("certKey_signer", publicKey);
            var unlinkedCertificate = certificateCarrying(publicKey);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());
            var selection = theFirstListedPair();

            // when
            onboard(selection);

            // then
            assertThat(certificateRepository.findById(unlinkedCertificate).orElseThrow().getKeyUuid())
                    .isEqualTo(publicKeyRecord);
        }

        @Test
        void skipsTheKeyPair_whenTheCallerMayNotUpdateTheRecord() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var recordName = "certKey_locked";
            var publicKeyRecord = recordHolding(recordName, publicKey);
            denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE, publicKeyRecord);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result.getOutcome()).isEqualTo(TokenKeyOnboardingOutcome.BLOCKED);
            assertThat(result.getReason()).isEqualTo(KeyImportGates.NOT_UPDATABLE.formatted(recordName));
            assertThat(cryptographicKeyRepository.findByUuid(publicKeyRecord).orElseThrow().getTokenProfileUuid())
                    .isNull();
        }

        @Test
        void joinsTheRecordWithoutNamingIt_whenTheCallerMayNotSeeIt() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var hidden = recordHolding("certKey_hidden", publicKey);
            denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, hidden);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getKeyUuid,
                            TokenKeyOnboardingResultDto::getKeyName)
                    .containsExactly(TokenKeyOnboardingOutcome.JOINED_EXISTING_KEY, null, null);
            assertThat(cryptographicKeyRepository.findByUuid(hidden).orElseThrow().getTokenProfileUuid())
                    .isEqualTo(profileUuid);
        }

        @Test
        void findsTheKeyPairHeld_whenASecondObjectOnTheTokenHoldsIt() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var holderName = "certKey_shared";
            var publicKeyRecord = recordHolding(holderName, publicKey);
            tokenLists(aListedKeyPair().withStorageName("first").withPublicKey(publicKey).build(),
                    aListedKeyPair().withStorageName("second").withPublicKey(publicKey).build());
            List<TokenKeyDto> entries = firstPage().getItems();
            var first = selecting(entries.get(0));
            var second = selecting(entries.get(1));

            // when
            List<TokenKeyOnboardingResultDto> results = onboardTogether(first, second);

            // then
            assertThat(results)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getKeyUuid)
                    .containsExactly(tuple(TokenKeyOnboardingOutcome.JOINED_EXISTING_KEY, publicKeyRecord),
                            tuple(TokenKeyOnboardingOutcome.BLOCKED, publicKeyRecord));
            assertThat(results.get(1).getReason())
                    .isEqualTo("Key '%s' already holds this key pair.".formatted(holderName));
        }

        @Test
        void refusesToJoinTheRecord_whenItGainsItsPrivateKeyWhileTheOnboardingWaitsForIt() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var publicKeyRecord = recordHolding("certKey_taken", publicKey);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());
            var selection = theFirstListedPair();
            var securityContext = SecurityContextHolder.getContext();

            // when
            Future<TokenKeyOnboardingResultDto> onboarding = lockContention
                    .callBlockedBy(() -> privateKeyJoinedMeanwhile(publicKeyRecord, publicKey),
                            DelegatingSecurityContextCallable.create(() -> onboard(selection), securityContext));

            // then
            assertThat(onboarding.get(10, TimeUnit.SECONDS))
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getReason)
                    .containsExactly(TokenKeyOnboardingOutcome.FAILED,
                            "The key holding this public key changed while the private key was "
                                    + "joining it. List the key storage again.");
            assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(publicKeyRecord))).hasSize(2);
        }

        /** A key pair registered while the onboarding writes it takes the unique fingerprint first. */
        @Test
        void skipsTheKeyPairAndOnboardsTheNext_whenTheInventoryComesToHoldItWhileItIsWritten() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            tokenLists(aListedKeyPair().withStorageName("contested").withPublicKey(publicKey).build(),
                    aListedKeyPair().withStorageName("uncontested").build());
            List<TokenKeyDto> entries = firstPage().getItems();
            var contested = selecting(entries.get(0));
            var uncontested = selecting(entries.get(1));
            var securityContext = SecurityContextHolder.getContext();

            // when
            Future<List<TokenKeyOnboardingResultDto>> onboarding = lockContention
                    .callBlockedBy(() -> registeredMeanwhile(publicKey), DelegatingSecurityContextCallable
                            .create(() -> onboardTogether(contested, uncontested), securityContext));

            // then
            List<TokenKeyOnboardingResultDto> results = onboarding.get(10, TimeUnit.SECONDS);
            assertThat(results)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getStatus,
                            TokenKeyOnboardingResultDto::getReason)
                    .containsExactly(
                            tuple(TokenKeyOnboardingOutcome.BLOCKED, TokenKeyStatus.IN_INVENTORY,
                                    "The inventory came to hold this key pair while it was being onboarded."),
                            tuple(TokenKeyOnboardingOutcome.ONBOARDED, null, null));
            assertThat(results.getFirst().getKeyName()).isEqualTo(REGISTERED_MEANWHILE);
            assertThat(results.getFirst().getKeyUuid()).isNotNull();
            assertThat(cryptographicKeyRepository.existsByName("contested")).isFalse();
        }

        /** A public-key-only record that takes the unique fingerprint first can still take the private key. */
        @Test
        void reportsARetryableFailureAndOnboardsTheNext_whenACertificateBringsThePublicKeyInWhileItIsWritten()
                throws Exception {
            // given
            var publicKey = rsaPublicKey();
            tokenLists(aListedKeyPair().withStorageName("contested").withPublicKey(publicKey).build(),
                    aListedKeyPair().withStorageName("uncontested").build());
            List<TokenKeyDto> entries = firstPage().getItems();
            var contested = selecting(entries.get(0));
            var uncontested = selecting(entries.get(1));
            var securityContext = SecurityContextHolder.getContext();

            // when
            Future<List<TokenKeyOnboardingResultDto>> onboarding = lockContention
                    .callBlockedBy(() -> uploadedMeanwhile(publicKey), DelegatingSecurityContextCallable
                            .create(() -> onboardTogether(contested, uncontested), securityContext));

            // then
            assertThat(onboarding.get(10, TimeUnit.SECONDS))
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getStatus,
                            TokenKeyOnboardingResultDto::getReason)
                    .containsExactly(
                            tuple(TokenKeyOnboardingOutcome.FAILED, null,
                                    "Another key came to hold this public key while the key pair was being "
                                            + "onboarded. List the key storage again."),
                            tuple(TokenKeyOnboardingOutcome.ONBOARDED, null, null));
            assertThat(cryptographicKeyRepository.existsByName("contested")).isFalse();
        }

        @Test
        void reportsTheFailureAndOnboardsTheNext_whenOnboardingAKeyPairFails() throws Exception {
            // given
            connectorRegistered(slotMetadata(AttributeContentType.STRING));
            MetadataAttributeV3 integerSlot = slotMetadata(AttributeContentType.INTEGER);
            integerSlot.setContent(List.of(new IntegerAttributeContentV3(7)));
            tokenLists(pairWithPrivateKeyMetadata("clashing", integerSlot),
                    aListedKeyPair().withStorageName("next").build());
            List<TokenKeyDto> entries = firstPage().getItems();

            // when
            List<TokenKeyOnboardingResultDto> results = onboardTogether(selecting(entries.get(0)),
                    selecting(entries.get(1)));

            // then
            assertThat(results)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome)
                    .containsExactly(TokenKeyOnboardingOutcome.FAILED, TokenKeyOnboardingOutcome.ONBOARDED);
            assertThat(results.getFirst().getReason()).startsWith("Metadata attribute content type changed");
            assertThat(cryptographicKeyRepository.existsByName("clashing")).isFalse();
        }

        @Test
        void onboardsEachKeyPairUnderItsSuggestedName_whenTwoShareAStorageName() throws Exception {
            // given
            var storageName = "signer";
            tokenLists(aListedKeyPair().withStorageName(storageName).build(),
                    aListedKeyPair().withStorageName(storageName).build());
            List<TokenKeyDto> entries = firstPage().getItems();
            List<String> suggestedNames = entries.stream().map(TokenKeyDto::getSuggestedName).toList();
            var first = new TokenKeySelectionDto(entries.get(0).getKeyPairMeta(), suggestedNames.get(0));
            var second = new TokenKeySelectionDto(entries.get(1).getKeyPairMeta(), suggestedNames.get(1));

            // when
            List<TokenKeyOnboardingResultDto> results = onboardTogether(first, second);

            // then
            assertThat(results)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getKeyName)
                    .containsExactly(tuple(TokenKeyOnboardingOutcome.ONBOARDED, suggestedNames.get(0)),
                            tuple(TokenKeyOnboardingOutcome.ONBOARDED, suggestedNames.get(1)));
        }

        @Test
        void namesTheFirstKeyPairItOnboardsAfterTheStorageName_whenTwoShareOneAndNoSelectionNamesThem()
                throws Exception {
            // given
            var storageName = "signer";
            var listedFirstPublicKey = rsaPublicKey();
            var listedFirst = aListedKeyPair()
                    .withKeyId("listed-first-id")
                    .withStorageName(storageName)
                    .withPublicKey(listedFirstPublicKey)
                    .build();
            var listedSecond = aListedKeyPair().withKeyId("listed-second-id").withStorageName(storageName).build();
            tokenResolves(listedSecond, listedFirst);

            // when
            List<TokenKeyOnboardingResultDto> results = onboardTogether(
                    new TokenKeySelectionDto(keyPairMetaOf(listedSecond), null),
                    new TokenKeySelectionDto(keyPairMetaOf(listedFirst), null));

            // then
            String fingerprinted = "%s (%s)"
                    .formatted(storageName, fingerprintOf(listedFirstPublicKey).substring(0, 8));
            assertThat(results)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getKeyName)
                    .containsExactly(tuple(TokenKeyOnboardingOutcome.ONBOARDED, storageName),
                            tuple(TokenKeyOnboardingOutcome.ONBOARDED, fingerprinted));
        }

        @Test
        void skipsTheRepeatedKeyPair_whenTheSelectionRepeatsIt() throws Exception {
            // given
            var storageName = "signer";
            var pair = aListedKeyPair().withKeyId("signer-id").withStorageName(storageName).build();
            tokenLists(pair);
            var once = theFirstListedPair();
            var againName = "again";
            var again = theFirstListedPairNamed(againName);
            tokenResolves(pair, pair);

            // when
            List<TokenKeyOnboardingResultDto> results = onboardTogether(once, again);

            // then
            assertThat(results)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome)
                    .containsExactly(TokenKeyOnboardingOutcome.ONBOARDED, TokenKeyOnboardingOutcome.BLOCKED);
            TokenKeyOnboardingResultDto skipped = results.get(1);
            assertThat(skipped.getStatus()).isEqualTo(TokenKeyStatus.IN_INVENTORY);
            assertThat(skipped.getKeyName()).isEqualTo(storageName);
            assertThat(skipped.getReason()).contains(storageName);
            assertThat(cryptographicKeyRepository.existsByName(againName)).isFalse();
            connectorMock.verifyKeyResolutionRequestContaining("""
                    {"keys": [
                        {"identifier": "0", "keyMeta": [{"name": "keyId", "content": [{"data": "signer-id"}]}]},
                        {"identifier": "1", "keyMeta": [{"name": "keyId", "content": [{"data": "signer-id"}]}]}]}
                    """);
        }

        @ParameterizedTest
        @MethodSource("answersWithoutAKeyPair")
        void skipsTheSelectionAndOnboardsTheNext_whenTheTokenAnswersItWithoutAKeyPair(KeyEntryStatus status,
                TokenKeyStatus blockingStatus, String reason) throws Exception {
            // given
            var next = aListedKeyPair().withStorageName("next").build();
            tokenResolves(answered(status), next);
            var unanswered = new TokenKeySelectionDto(keyIdMeta("unanswered-id"), null);
            var nextSelection = new TokenKeySelectionDto(keyPairMetaOf(next), null);

            // when
            List<TokenKeyOnboardingResultDto> results = onboardTogether(unanswered, nextSelection);

            // then
            assertThat(results)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getStatus,
                            TokenKeyOnboardingResultDto::getReason)
                    .containsExactly(tuple(TokenKeyOnboardingOutcome.BLOCKED, blockingStatus, reason),
                            tuple(TokenKeyOnboardingOutcome.ONBOARDED, null, null));
            assertThat(results.getFirst())
                    .extracting(TokenKeyOnboardingResultDto::getKeyUuid, TokenKeyOnboardingResultDto::getKeyName)
                    .containsOnlyNulls();
        }

        @Test
        void carriesTheConnectorsDiagnostic_whenTheTokenAnswersASelectionWithoutAKeyPair() throws Exception {
            // given
            var gone = "The token holds no private key under this CKA_ID.";
            var answer = answered(KeyEntryStatus.NOT_FOUND);
            answer.setDiagnostic(gone);
            tokenResolves(answer);

            // when
            TokenKeyOnboardingResultDto result = onboard(new TokenKeySelectionDto(keyIdMeta("gone-id"), null));

            // then
            assertThat(result.getDiagnostic()).isEqualTo(gone);
        }

        @Test
        void carriesTheConnectorsDiagnostic_whenOnboardingAKeyPairFails() throws Exception {
            // given
            var tokenNote = "The token keeps this key pair under a vendor label.";
            connectorRegistered(slotMetadata(AttributeContentType.STRING));
            MetadataAttributeV3 integerSlot = slotMetadata(AttributeContentType.INTEGER);
            integerSlot.setContent(List.of(new IntegerAttributeContentV3(7)));
            var clashing = pairWithPrivateKeyMetadata("clashing", integerSlot);
            clashing.setDiagnostic(tokenNote);
            tokenLists(clashing);

            // when
            TokenKeyOnboardingResultDto result = onboardTheFirstListedPair();

            // then
            assertThat(result.getDiagnostic()).isEqualTo(tokenNote);
        }

        @Test
        void writesNoKey_whenTheConnectorRefusesTheSelectedKeyPair() throws Exception {
            // given
            tokenLists(aListedKeyPair().withStatus(KeyEntryStatus.REFUSED).build());
            long keysBefore = cryptographicKeyRepository.count();

            // when
            TokenKeyOnboardingResultDto result = onboardTheFirstListedPair();

            // then
            assertThat(result)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getStatus,
                            TokenKeyOnboardingResultDto::getReason)
                    .containsExactly(TokenKeyOnboardingOutcome.BLOCKED, TokenKeyStatus.REFUSED,
                            "The connector refuses to let the platform onboard this key.");
            assertThat(cryptographicKeyRepository.count()).isEqualTo(keysBefore);
        }

        @Test
        void skipsTheKeyPairAsRefused_whenTheConnectorRefusesAKeyPairWithoutAPublicKey() throws Exception {
            // given
            tokenLists(aListedKeyPair().withoutPublicKey().withStatus(KeyEntryStatus.REFUSED).build());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getStatus)
                    .containsExactly(TokenKeyOnboardingOutcome.BLOCKED, TokenKeyStatus.REFUSED);
        }

        @Test
        void carriesNoDiagnostic_whenItOnboardsTheKeyPair() throws Exception {
            // given
            tokenLists(aListedKeyPair().withDiagnostic("The token keeps this key pair under a vendor label.").build());

            // when
            TokenKeyOnboardingResultDto result = onboardTheFirstListedPair();

            // then
            assertThat(result)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getDiagnostic)
                    .containsExactly(TokenKeyOnboardingOutcome.ONBOARDED, null);
        }

        @Test
        void carriesNoDiagnostic_whenThePrivateKeyJoinsTheRecord() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            recordHolding("certKey_signer", publicKey);
            tokenLists(aListedKeyPair()
                    .withPublicKey(publicKey)
                    .withDiagnostic("The token keeps this key pair under a vendor label.")
                    .build());

            // when
            TokenKeyOnboardingResultDto result = onboardTheFirstListedPair();

            // then
            assertThat(result)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getDiagnostic)
                    .containsExactly(TokenKeyOnboardingOutcome.JOINED_EXISTING_KEY, null);
        }

        /** The resolution precedes every write, so a token that cannot answer it leaves the inventory as it was. */
        @Test
        void writesNoKey_whenTheResolutionFails() throws Exception {
            // given
            connectorMock.failKeyResolution();
            var first = new TokenKeySelectionDto(keyIdMeta("first-id"), null);
            var second = new TokenKeySelectionDto(keyIdMeta("second-id"), null);
            long keysBefore = cryptographicKeyRepository.count();

            // when / then
            assertThatThrownBy(() -> onboardTogether(first, second))
                    .isInstanceOf(ConnectorServerException.class)
                    .hasMessage("The connector failed to resolve the key pairs.");
            assertThat(cryptographicKeyRepository.count()).isEqualTo(keysBefore);
        }

        @Test
        void skipsTheKeyPair_whenAPublicKeyInATokenHoldsIt() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var holderName = "certKey_in_token";
            publicKeyInTheToken(holderName, publicKey);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result.getOutcome()).isEqualTo(TokenKeyOnboardingOutcome.BLOCKED);
            assertThat(result.getReason())
                    .isEqualTo("Key '%s' holds the same public key under a token instance, without its private key."
                            .formatted(holderName));
        }

        @Test
        void skipsTheKeyPair_whenTheTokenHoldsNoPublicKeyForIt() throws Exception {
            // given
            tokenLists(aListedKeyPair().withoutPublicKey().build());
            var selection = theFirstListedPair();
            long keysBefore = cryptographicKeyRepository.count();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getStatus,
                            TokenKeyOnboardingResultDto::getReason)
                    .containsExactly(TokenKeyOnboardingOutcome.BLOCKED, TokenKeyStatus.PUBLIC_KEY_UNAVAILABLE,
                            "The key storage holds no public key for this key pair.");
            assertThat(cryptographicKeyRepository.count()).isEqualTo(keysBefore);
        }

        @Test
        void skipsTheKeyPairInWordsNamingNoKey_whenAKeyTheCallerMayNotSeeHoldsIt() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var hidden = recordHolding("certKey_hidden", publicKey);
            denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, hidden);
            denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE, hidden);
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result.getOutcome()).isEqualTo(TokenKeyOnboardingOutcome.BLOCKED);
            assertThat(result.getKeyUuid()).isNull();
            assertThat(result.getKeyName()).isNull();
            assertThat(result.getReason()).isEqualTo(CryptographicKeyWriter.KEY_ALREADY_HELD);
        }

        @Test
        void skipsTheKeyPairInWordsNamingNoKey_whenTheCallerMayNotSeeTheMembersOfTheTokenHoldingIt() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var another = anotherToken();
            publicKeyIn(another, "certKey_elsewhere", publicKey);
            denyResourceAccess(Resource.TOKEN, ResourceAction.MEMBERS, another.token().getUuid());
            tokenLists(aListedKeyPair().withPublicKey(publicKey).build());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result.getOutcome()).isEqualTo(TokenKeyOnboardingOutcome.BLOCKED);
            assertThat(result)
                    .extracting(TokenKeyOnboardingResultDto::getKeyUuid, TokenKeyOnboardingResultDto::getKeyName)
                    .containsOnlyNulls();
            assertThat(result.getReason()).isEqualTo(CryptographicKeyWriter.KEY_ALREADY_HELD);
        }

        @Test
        void skipsTheKeyPair_whenAnUnsettledImportHoldsIt() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            importOf(publicKey, KeyImportState.ACCEPTED);
            var storageName = "signer";
            tokenLists(aListedKeyPair().withStorageName(storageName).withPublicKey(publicKey).build());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result.getOutcome()).isEqualTo(TokenKeyOnboardingOutcome.BLOCKED);
            assertThat(result.getReason()).isEqualTo("An import of this key pair is still in progress.");
            assertThat(cryptographicKeyRepository.existsByName(storageName)).isFalse();
        }

        /** The token may still find a key pair that the compensation destroys while it resolves the selection. */
        @Test
        void skipsTheKeyPair_whenItsImportIsCompensatedWhileTheTokenResolvesTheSelection() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var attempt = importOf(publicKey, KeyImportState.COMPENSATING);
            var storageName = "signer";
            tokenLists(aListedKeyPair().withStorageName(storageName).withPublicKey(publicKey).build());
            var selection = theFirstListedPair();
            connectorMock
                    .onKeyResolutionRequest(() -> jdbcTemplate
                            .update("UPDATE key_import SET state = ? WHERE uuid = ?", KeyImportState.COMPENSATED.name(),
                                    attempt));

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result.getOutcome()).isEqualTo(TokenKeyOnboardingOutcome.BLOCKED);
            assertThat(result.getReason()).isEqualTo("An import of this key pair is still in progress.");
            assertThat(cryptographicKeyRepository.existsByName(storageName)).isFalse();
        }

        @Test
        void readsTheInventoryOnce_whateverTheNumberOfSelections() throws Exception {
            // given
            var twoPairs = List.of(pairHeldInTheToken("certKey_0a"), pairHeldInTheToken("certKey_0b"));
            var sixPairs = List
                    .of(pairHeldInTheToken("certKey_1a"), pairHeldInTheToken("certKey_1b"),
                            pairHeldInTheToken("certKey_1c"), pairHeldInTheToken("certKey_1d"),
                            pairHeldInTheToken("certKey_1e"), pairHeldInTheToken("certKey_1f"));
            warmUpOnboarding(twoPairs);

            // when
            int twoSelectionsQueries = queriesOnboarding(twoPairs);
            int sixSelectionsQueries = queriesOnboarding(sixPairs);

            // then
            assertThat(sixSelectionsQueries).isEqualTo(twoSelectionsQueries);
        }

        /**
         * An import holding the key pair may be registering it or undoing it under its attempt's lock, so the
         * onboarding waits for that lock and refuses the key pair while the import stays unsettled.
         */
        @Test
        void waitsForTheImportAndRefusesTheKeyPair_whenAnUnsettledImportHoldsItsLock() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var attempt = importOf(publicKey, KeyImportState.ACCEPTED);
            var name = "signer";
            var profile = profileModel();
            var fingerprint = fingerprintOf(publicKey);
            var items = aProviderKeyPair().withPublicKey(publicKey).build().toOnboardedItems(name);

            // when
            Future<Optional<CryptographicKeyBasicModel>> onboarding = lockContention
                    .callBlockedBy(
                            () -> jdbcTemplate
                                    .queryForList("SELECT uuid FROM key_import WHERE uuid = ? FOR UPDATE", attempt),
                            () -> cryptographicKeyWriter
                                    .onboardUnlessImporting(name, profile, fingerprint, items, null, null));

            // then
            assertThat(onboarding.get(10, TimeUnit.SECONDS)).isEmpty();
            assertThat(cryptographicKeyRepository.existsByName(name)).isFalse();
        }

        @Test
        void skipsTheKeyPair_whenItsNameIsTaken() throws Exception {
            // given
            var takenName = "Payments signer";
            recordHolding(takenName, rsaPublicKey());
            tokenLists(aListedKeyPair().build());
            var selection = theFirstListedPairNamed(takenName);

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result.getOutcome()).isEqualTo(TokenKeyOnboardingOutcome.NAME_TAKEN);
            assertThat(result.getReason()).isEqualTo("A key '%s' already exists.".formatted(takenName));
        }

        @Test
        void sizesEachItemByItsParameterSet_whenThePairIsPostQuantum() throws Exception {
            // given
            tokenLists(postQuantumPair());
            var selection = theFirstListedPair();

            // when
            TokenKeyOnboardingResultDto result = onboard(selection);

            // then
            assertThat(result.getOutcome()).isEqualTo(TokenKeyOnboardingOutcome.ONBOARDED);
            assertThat(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(result.getKeyUuid())))
                    .extracting(CryptographicKeyItem::getType, CryptographicKeyItem::getParameterSet,
                            CryptographicKeyItem::getLength)
                    .containsExactlyInAnyOrder(
                            tuple(KeyType.PUBLIC_KEY, PqcKeyFixtures.ML_DSA_PARAMETER_SET,
                                    PqcKeyFixtures.ML_DSA_PUBLIC_KEY_BITS),
                            tuple(KeyType.PRIVATE_KEY, PqcKeyFixtures.ML_DSA_PARAMETER_SET,
                                    PqcKeyFixtures.ML_DSA_PRIVATE_KEY_BITS));
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static Stream<Arguments> answersWithoutAKeyPair() {
            return Stream
                    .of(arguments(KeyEntryStatus.NOT_FOUND, TokenKeyStatus.GONE,
                            "The key storage no longer holds this key pair."),
                            arguments(KeyEntryStatus.UNADDRESSABLE, TokenKeyStatus.UNADDRESSABLE,
                                    "The connector cannot address this key pair by its handle alone."),
                            arguments(KeyEntryStatus.UNSUPPORTED_TYPE, TokenKeyStatus.UNSUPPORTED_KEY_TYPE,
                                    "The connector cannot operate a key of this type."),
                            arguments(KeyEntryStatus.UNREADABLE, TokenKeyStatus.UNREADABLE,
                                    "The connector cannot read this key pair."),
                            arguments(
                                    named("a handle the token does not recognise has no key to describe",
                                            KeyEntryStatus.INVALID_HANDLE),
                                    null, "The connector does not recognise this handle."));
        }

        /** Registers a key pair holding the public key, as key creation does, within the caller's transaction. */
        private void registeredMeanwhile(PublicKey publicKey) {
            try {
                keyPairThePlatformCreated(REGISTERED_MEANWHILE, aProviderKeyPair().withPublicKey(publicKey).build());
                cryptographicKeyItemRepository.flush();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }

        /** Brings the public key in as an uploaded certificate does, within the caller's transaction. */
        private void uploadedMeanwhile(PublicKey publicKey) {
            try {
                recordHolding("uploaded meanwhile", publicKey);
                cryptographicKeyItemRepository.flush();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }
    }

    // ── KeyListAvailability ───────────────────────────────────────────────────

    @Nested
    class KeyListAvailability {

        @Test
        void refusesTheListing_whenTheProfileIsDisabled() throws Exception {
            // given
            tokenProfileService
                    .disableTokenProfile(SecuredParentUUID.fromUUID(tokenUuid), SecuredUUID.fromUUID(profileUuid));

            // when / then
            assertThatThrownBy(() -> firstPage())
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("is disabled");
        }

        @Test
        void listsOnlyKeyListableProfiles_whenTheConnectorDropsKeyListing() {
            // when
            List<String> whileListing = keyListableProfiles();
            connectorDropsKeyListing();
            List<String> afterDropping = keyListableProfiles();

            // then
            assertThat(whileListing).containsExactly(profileUuid.toString());
            assertThat(afterDropping).isEmpty();
        }

        @Test
        void refusesTheListing_whenTheConnectorLacksKeyListing() {
            // given
            connectorDropsKeyListing();

            // when / then
            assertThatThrownBy(() -> firstPage())
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("cannot list the keys in its key storage");
        }
    }

    // ── AuditRecord ───────────────────────────────────────────────────────────

    @Nested
    class AuditRecord {

        private final List<AuditLogMessage> auditMessages = new ArrayList<>();

        @BeforeEach
        void captureTheAuditRecordsOfARequest() {
            auditLogsOn();
            Mockito.doAnswer(invocation -> {
                auditMessages.add(invocation.getArgument(0));
                return null;
            }).when(auditLogsProducer).produceMessage(Mockito.any());
            RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));
        }

        @AfterEach
        void leaveTheRequest() {
            RequestContextHolder.resetRequestAttributes();
        }

        private void auditLogsOn() {
            AuditLoggingSettingsDto auditLogs = new AuditLoggingSettingsDto();
            auditLogs.setOutput(AuditLogOutput.ALL);
            auditLogs.setLogAllModules(true);
            auditLogs.setLogAllResources(true);
            LoggingSettingsDto settings = new LoggingSettingsDto();
            settings.setAuditLogs(auditLogs);
            settings.setEventLogs(new ResourceLoggingSettingsDto());
            settingExternalService.updateLoggingSettings(settings);
        }

        private OnboardTokenKeysResponseDto onboardThroughTheApi(TokenKeySelectionDto... selections) throws Exception {
            return cryptographicKeyController
                    .onboardTokenKeys(tokenUuid.toString(), profileUuid.toString(),
                            new OnboardTokenKeysRequestDto(List.of(selections), null));
        }

        private LogRecord theOnboardingRecord() {
            List<LogRecord> records = auditMessages
                    .stream()
                    .map(AuditLogMessage::getLogRecord)
                    .filter(auditRecord -> auditRecord.operation() == Operation.ONBOARD)
                    .toList();
            assertThat(records).hasSize(1);
            return records.getFirst();
        }

        @Test
        void namesTheKeyAsTheRecordsResource_whenTheRequestOnboardsOne() throws Exception {
            // given
            var storageName = "signer";
            tokenLists(aListedKeyPair().withStorageName(storageName).build());
            var selection = theFirstListedPair();

            // when
            UUID keyUuid = onboardThroughTheApi(selection).getResults().getFirst().getKeyUuid();

            // then
            LogRecord auditRecord = theOnboardingRecord();
            assertThat(auditRecord.resource().objects())
                    .containsExactly(new ResourceObjectIdentity(storageName, keyUuid));
            assertThat(auditRecord.operationData())
                    .isEqualTo(new OnboardedKeys(List.of(new OnboardedKey(keyUuid.toString(), storageName, false))));
        }

        /** The record names a joined record the caller may not see, which the result leaves unnamed. */
        @Test
        void namesEveryKeyInTheOperationData_whenTheRequestOnboardsSeveral() throws Exception {
            // given
            var publicKey = rsaPublicKey();
            var hiddenName = "certKey_hidden";
            var hidden = recordHolding(hiddenName, publicKey);
            denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DETAIL, hidden);
            var storageName = "signer";
            tokenLists(aListedKeyPair().withStorageName(storageName).build(),
                    aListedKeyPair().withPublicKey(publicKey).build());
            List<TokenKeyDto> entries = firstPage().getItems();

            // when
            List<TokenKeyOnboardingResultDto> results = onboardThroughTheApi(selecting(entries.get(0)),
                    selecting(entries.get(1))).getResults();

            // then
            UUID created = results.getFirst().getKeyUuid();
            LogRecord auditRecord = theOnboardingRecord();
            assertThat(auditRecord.resource().objects()).isNullOrEmpty();
            assertThat(auditRecord.operationData())
                    .isEqualTo(new OnboardedKeys(List
                            .of(new OnboardedKey(created.toString(), storageName, false),
                                    new OnboardedKey(hidden.toString(), hiddenName, true))));
        }

        @Test
        void onboardsNothingAndNamesNoResource_whenNoSelectionResolvesToAKeyPair() throws Exception {
            // given
            tokenResolves(answered(KeyEntryStatus.NOT_FOUND), answered(KeyEntryStatus.NOT_FOUND));
            var first = new TokenKeySelectionDto(keyIdMeta("first-id"), null);
            var second = new TokenKeySelectionDto(keyIdMeta("second-id"), null);

            // when
            List<TokenKeyOnboardingResultDto> results = onboardThroughTheApi(first, second).getResults();

            // then
            var gone = "The key storage no longer holds this key pair.";
            assertThat(results)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getReason)
                    .containsExactly(tuple(TokenKeyOnboardingOutcome.BLOCKED, gone),
                            tuple(TokenKeyOnboardingOutcome.BLOCKED, gone));
            LogRecord auditRecord = theOnboardingRecord();
            assertThat(auditRecord.operationResult()).isEqualTo(OperationResult.SUCCESS);
            assertThat(auditRecord.resource().objects()).isNullOrEmpty();
            assertThat(auditRecord.operationData()).isEqualTo(new OnboardedKeys(List.of()));
        }

        /** Each key commits on its own, so the keys onboarded before the failure stay in the inventory. */
        @Test
        void listsTheKeyItOnboardedWithoutNamingItTheResource_whenALaterKeyPairFailsTheRequest() throws Exception {
            // given
            RefusedDefinitionInserts.install(jdbcTemplate);
            MetadataAttributeV3 refused = slotMetadata(AttributeContentType.INTEGER);
            refused.setName(RefusedDefinitionInserts.REFUSED_NAME);
            refused.setContent(List.of(new IntegerAttributeContentV3(7)));
            var storageName = "signer";
            tokenLists(aListedKeyPair().withStorageName(storageName).build(),
                    pairWithPrivateKeyMetadata("refused", refused));
            List<TokenKeyDto> entries = firstPage().getItems();

            // when
            ThrowingCallable onboardThroughTheApi = () -> onboardThroughTheApi(selecting(entries.get(0)),
                    selecting(entries.get(1)));

            // then
            assertThatThrownBy(onboardThroughTheApi).hasMessageContaining("attribute definition refused by the test");
            UUID onboarded = jdbcTemplate
                    .queryForObject("SELECT uuid FROM cryptographic_key WHERE name = ?", UUID.class, storageName);
            LogRecord auditRecord = theOnboardingRecord();
            assertThat(auditRecord.operationResult()).isEqualTo(OperationResult.FAILURE);
            assertThat(auditRecord.resource().objects()).isNullOrEmpty();
            assertThat(auditRecord.operationData())
                    .isEqualTo(new OnboardedKeys(List.of(new OnboardedKey(onboarded.toString(), storageName, false))));
        }
    }

    // ── RemovalFromInventory ──────────────────────────────────────────────────

    @Nested
    class RemovalFromInventory {

        @Test
        void removesAnOnboardedKeyFromTheInventoryAlone_whenItsTokenListsKeys() throws Exception {
            // given
            var onboarded = anOnboardedKey();
            connectorMock.stubDestroyKey();

            // when
            removeFromInventory(onboarded);

            // then
            assertThat(cryptographicKeyRepository.findByUuid(onboarded)).isEmpty();
            connectorMock.verifyDestroyKeyRequests(0);
            assertThat(firstListedEntry().getStatus()).isEqualTo(TokenKeyStatus.ONBOARDABLE);
        }

        @Test
        void removesACreatedKeyFromTheInventoryAlone_whenItsTokenListsKeys() throws Exception {
            // given
            var keyId = "created-key";
            var publicKey = rsaPublicKey();
            tokenLists(aListedKeyPair().withKeyId(keyId).withStorageName("created").withPublicKey(publicKey).build());
            connectorMock.stubDestroyKey();
            var created = keyPairThePlatformCreated("created",
                    aProviderKeyPair().withKeyId(keyId).withPublicKey(publicKey).build());

            // when
            removeFromInventory(created);

            // then
            assertThat(cryptographicKeyRepository.findByUuid(created)).isEmpty();
            connectorMock.verifyDestroyKeyRequests(0);
            assertThat(firstListedEntry().getStatus()).isEqualTo(TokenKeyStatus.ONBOARDABLE);
        }

        @Test
        void refusesTheRemoval_whenTheKeyHoldsNoPrivateKeyInAToken() throws Exception {
            // given
            var publicKeyRecord = recordHolding("certKey_record", rsaPublicKey());

            // when / then
            assertThatThrownBy(() -> removeFromInventory(publicKeyRecord))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("It holds no private key in a token.");
            assertThat(cryptographicKeyRepository.findByUuid(publicKeyRecord)).isPresent();
        }

        @Test
        void refusesTheRemoval_whenItsConnectorListsNoKeys() throws Exception {
            // given
            var created = keyPairThePlatformCreated("created");
            connectorDropsKeyListing();

            // when / then
            assertThatThrownBy(() -> removeFromInventory(created))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("The connector backing this token cannot list keys");
            assertThat(cryptographicKeyRepository.findByUuid(created)).isPresent();
        }

        @Test
        void refusesTheRemoval_whenTheKeyIsCompromised() throws Exception {
            // given
            var created = keyPairThePlatformCreated("created");
            withItemsIn(created, KeyState.COMPROMISED);

            // when / then
            assertThatThrownBy(() -> removeFromInventory(created))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("It is compromised");
            assertThat(cryptographicKeyRepository.findByUuid(created)).isPresent();
        }

        @Test
        void refusesTheRemoval_whenTheKeyWasCompromisedAfterTheRemovalReadIt() throws Exception {
            // given
            var created = keyPairThePlatformCreated("created");
            var read = cryptographicKeyRepository.findFullModelByUuid(created).orElseThrow();
            var statesRead = itemStatesOf(read);
            withItemsIn(created, KeyState.COMPROMISED);

            // when / then
            assertThatThrownBy(() -> cryptographicKeyWriter.removeFromInventoryAsRead(read, statesRead))
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("changed meanwhile");
            assertThat(cryptographicKeyRepository.findByUuid(created)).isPresent();
        }

        /**
         * An operator compromises an item under the item's own lock, so the removal waits for it and sees the change.
         */
        @Test
        void waitsForTheItemAndKeepsTheKey_whenAnOperatorCompromisesItMeanwhile() throws Exception {
            // given
            var created = keyPairThePlatformCreated("created");
            var read = cryptographicKeyRepository.findFullModelByUuid(created).orElseThrow();
            var statesRead = itemStatesOf(read);

            // when
            Future<?> removal = lockContention
                    .runBlockedBy(
                            () -> jdbcTemplate
                                    .update("UPDATE cryptographic_key_item SET state = ? WHERE key_uuid = ?",
                                            KeyState.COMPROMISED.name(), created),
                            () -> cryptographicKeyWriter.removeFromInventoryAsRead(read, statesRead));

            // then
            assertThatThrownBy(() -> removal.get(10, TimeUnit.SECONDS))
                    .hasCauseInstanceOf(ValidationException.class)
                    .hasMessageContaining("changed meanwhile");
            assertThat(cryptographicKeyRepository.findByUuid(created)).isPresent();
        }

        @Test
        void refusesTheRemoval_whenTheCallerMayNotDeleteTheKey() throws Exception {
            // given
            var onboarded = anOnboardedKey();
            ownedBySomeoneElse(onboarded);
            denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DELETE, onboarded);

            // when / then
            assertThatThrownBy(() -> removeFromInventory(onboarded)).isInstanceOf(AccessDeniedException.class);
            assertThat(cryptographicKeyRepository.findByUuid(onboarded)).isPresent();
        }

        @Test
        void refusesTheRemoval_whenTheCallerMayNotManageTheTokensKeys() throws Exception {
            // given
            var onboarded = anOnboardedKey();
            denyResourceAccess(Resource.TOKEN, ResourceAction.MEMBERS, tokenUuid);

            // when / then
            assertThatThrownBy(() -> removeFromInventory(onboarded)).isInstanceOf(AccessDeniedException.class);
            assertThat(cryptographicKeyRepository.findByUuid(onboarded)).isPresent();
        }

        @Test
        void removesTheRemovableKeysAndReportsTheOthers_whenASelectionMixesThem() throws Exception {
            // given
            var onboarded = anOnboardedKey();
            connectorMock.stubDestroyKey();
            var created = keyPairThePlatformCreated("created");
            var compromised = keyPairThePlatformCreated("compromised");
            withItemsIn(compromised, KeyState.COMPROMISED);
            var publicKeyRecord = recordHolding("certKey_record", rsaPublicKey());
            var unknown = UUID.randomUUID().toString();

            // when
            List<BulkActionMessageDto> report = cryptographicKeyService
                    .removeKeysFromInventory(List
                            .of(onboarded.toString(), created.toString(), compromised.toString(),
                                    publicKeyRecord.toString(), unknown));

            // then
            assertThat(report)
                    .extracting(BulkActionMessageDto::getUuid, BulkActionMessageDto::getName)
                    .containsExactly(tuple(compromised.toString(), "compromised"),
                            tuple(publicKeyRecord.toString(), "certKey_record"), tuple(unknown, unknown));
            assertThat(report.get(0).getMessage()).startsWith("It is compromised");
            assertThat(report.get(1).getMessage()).startsWith("It holds no private key in a token.");
            assertThat(cryptographicKeyRepository.findByUuid(onboarded)).isEmpty();
            assertThat(cryptographicKeyRepository.findByUuid(created)).isEmpty();
            assertThat(cryptographicKeyRepository.findByUuid(compromised)).isPresent();
            assertThat(cryptographicKeyRepository.findByUuid(publicKeyRecord)).isPresent();
            connectorMock.verifyDestroyKeyRequests(0);
        }

        @Test
        void refusesTheSelectionAndRemovesNone_whenTheCallerMayNotDeleteOneKey() throws Exception {
            // given
            var onboarded = anOnboardedKey();
            var created = keyPairThePlatformCreated("created");
            ownedBySomeoneElse(created);
            denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DELETE, created);
            var selection = List.of(onboarded.toString(), created.toString());

            // when / then
            assertThatThrownBy(() -> cryptographicKeyService.removeKeysFromInventory(selection))
                    .isInstanceOf(AccessDeniedException.class);
            assertThat(cryptographicKeyRepository.findByUuid(onboarded)).isPresent();
        }
    }
}
