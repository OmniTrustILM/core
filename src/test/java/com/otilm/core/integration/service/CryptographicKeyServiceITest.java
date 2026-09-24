package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.core.WireMockConfiguration;
import com.github.tomakehurst.wiremock.extension.Parameters;
import com.github.tomakehurst.wiremock.extension.ServeEventListener;
import com.github.tomakehurst.wiremock.stubbing.ServeEvent;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.certificate.SearchFilterRequestDto;
import com.otilm.api.model.client.certificate.SearchRequestDto;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.CryptographicKeyResponseDto;
import com.otilm.api.model.client.cryptography.key.BulkCompromiseKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.CompromiseKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.EditKeyItemDto;
import com.otilm.api.model.client.cryptography.key.EditKeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyCompromiseReason;
import com.otilm.api.model.client.cryptography.key.KeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.client.cryptography.key.UpdateKeyUsageRequestDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.connector.cryptography.v2.key.KeyExportableAttribute;
import com.otilm.api.model.connector.cryptography.v2.key.KeyPairDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PrivateKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.PublicKeyDataV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyDataResponseV2Dto;
import com.otilm.api.model.connector.cryptography.v2.key.SecretKeyDataV2Dto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyDto;
import com.otilm.api.model.core.cryptography.key.KeyEvent;
import com.otilm.api.model.core.cryptography.key.KeyEventStatus;
import com.otilm.api.model.core.cryptography.key.KeyItemDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.Comment;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyEventHistory;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.entity.OwnerAssociation;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.CommentRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.CryptographicKeyEventHistoryRepository;
import com.otilm.core.dao.repository.CryptographicKeyItemRepository;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.GroupAssociationRepository;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.dao.repository.OwnerAssociationRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.messaging.jms.producers.NotificationProducer;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.CryptographicKeyBasicModel;
import com.otilm.core.model.crypto.CryptographicKeyFullModel;
import com.otilm.core.model.crypto.ImmutableTokenInstanceBasicModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileBasicModel;
import com.otilm.core.model.crypto.ProviderKeyItem;
import com.otilm.core.model.crypto.RemoteKeyReference;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.model.group.GroupModel;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.CryptographicKeyEventHistoryService;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.service.ResourceObjectAssociationService;
import com.otilm.core.service.writer.CommentWriter;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.KeySizeUtil;
import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.time.Duration;
import java.time.LocalDateTime;
import java.time.Month;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.ProviderKeyItemBuilder.aProviderKeyItem;
import static org.mockito.Mockito.any;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.argThat;
import static org.mockito.Mockito.contains;
import static org.mockito.Mockito.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CryptographicKeyServiceITest extends BaseSpringBootTest {

    /** A v3 attribute names its version, and each of its content items names its content type. */
    private static final String EXPORTABLE_INTENT_ON_THE_WIRE = "$.createKeyAttributes[?(@.name == '%s' && @.uuid == '%s'"
            + " && @.version == 'v3' && @.content[0].contentType == 'boolean' && @.content[0].data == %s)]";

    private static final String KEY_NAME = "testKey1";

    @Autowired
    private CryptographicKeyExternalService cryptographicKeyService;
    @Autowired
    private CryptographicKeyWriter cryptographicKeyWriter;
    @Autowired
    private JdbcTemplate jdbcTemplate;
    @Autowired
    private PlatformTransactionManager transactionManager;
    @Autowired
    private AttributeEngine attributeEngine;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CommentRepository commentRepository;
    @Autowired
    private CommentWriter commentWriter;
    @Autowired
    private CryptographicKeyEventHistoryService keyEventHistoryService;
    @Autowired
    private ResourceObjectAssociationService objectAssociationService;
    @Autowired
    private GroupAssociationRepository groupAssociationRepository;
    @Autowired
    private CryptographicKeyInternalService cryptographicKeyInternalService;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private GroupRepository groupRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;
    @Autowired
    private CryptographicKeyEventHistoryRepository cryptographicKeyEventHistoryRepository;
    @Autowired
    private OwnerAssociationRepository ownerAssociationRepository;
    @MockitoBean
    private NotificationProducer notificationProducer;

    private Group group;
    private Connector connector;
    private TokenInstanceReference tokenInstanceReference;
    private TokenProfile tokenProfile;
    private TokenProfile tokenProfile2;
    private CryptographicKey key;
    private CryptographicKey keyWithoutToken;
    private CryptographicKeyItem publicKeyItem;
    private CryptographicKeyItem privateKeyItem;
    private WireMockServer mockServer;

    @BeforeEach
    void setUp() {
        alignHistoryDeletionConstraintWithMigration();
        // Start Mock Server
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        // Create and Save Connector
        connector = new Connector();
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.saveAndFlush(connector); // Ensure immediate persistence

        // create and save group
        group = new Group();
        group.setName("TestGroup");
        group.setDescription("Desc");
        groupRepository.save(group);

        // Create and Save TokenInstanceReferences
        tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setName("Token");
        tokenInstanceReference.setTokenInstanceUuid("1l");
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReference.setStatus(TokenInstanceStatus.CONNECTED);
        tokenInstanceReferenceRepository.saveAndFlush(tokenInstanceReference);

        // Create and Save TokenProfiles
        tokenProfile = new TokenProfile();
        tokenProfile.setName("profile1");
        tokenProfile.setTokenInstanceReference(tokenInstanceReference);
        tokenProfile.setDescription("sample description");
        tokenProfile.setEnabled(true);
        tokenProfile.setTokenInstanceName("testInstance");
        tokenProfileRepository.saveAndFlush(tokenProfile);

        tokenProfile2 = new TokenProfile();
        tokenProfile2.setName("profile2");
        tokenProfile2.setTokenInstanceReference(tokenInstanceReference);
        tokenProfile2.setDescription("sample description2");
        tokenProfile2.setEnabled(true);
        tokenProfile2.setTokenInstanceName("testInstance");
        tokenProfileRepository.saveAndFlush(tokenProfile2);

        // Create and Save CryptographicKey
        key = createKey(KEY_NAME, tokenProfile, tokenInstanceReference);
        key.setDescription("initial description");
        key = cryptographicKeyRepository.saveAndFlush(key);

        // Create and Save CryptographicKeyItem - Private Key
        privateKeyItem = createKeyItem(key, KeyType.PRIVATE_KEY, KeyState.ACTIVE, true);
        privateKeyItem.setLength(1024);
        privateKeyItem.setKeyData("some/encrypted/data");
        privateKeyItem.setFormat(KeyFormat.PRKI);
        privateKeyItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        privateKeyItem = cryptographicKeyItemRepository.saveAndFlush(privateKeyItem);

        // Create and Save CryptographicKeyItem - Public Key
        publicKeyItem = createKeyItem(key, KeyType.PUBLIC_KEY, KeyState.ACTIVE, true);
        publicKeyItem.setLength(1024);
        publicKeyItem.setKeyData("some/encrypted/data");
        publicKeyItem.setFormat(KeyFormat.SPKI);
        publicKeyItem.setKeyAlgorithm(KeyAlgorithm.RSA);
        publicKeyItem = cryptographicKeyItemRepository.saveAndFlush(publicKeyItem);

        // Update KeyReferenceUUIDs and Resave Items
        privateKeyItem.setKeyReferenceUuid(privateKeyItem.getUuid());
        publicKeyItem.setKeyReferenceUuid(publicKeyItem.getUuid());
        cryptographicKeyItemRepository.saveAndFlush(privateKeyItem);
        cryptographicKeyItemRepository.saveAndFlush(publicKeyItem);

        // Associate Items with Key and Resave Key
        Set<CryptographicKeyItem> items = new HashSet<>();
        items.add(publicKeyItem);
        items.add(privateKeyItem);
        key.setItems(items);
        cryptographicKeyRepository.saveAndFlush(key);

        // Create and Save CryptographicKey without token
        keyWithoutToken = new CryptographicKey();
        keyWithoutToken.setName("testKeyWithoutToken");
        keyWithoutToken.setDescription("testKeyWithoutToken");
        keyWithoutToken = cryptographicKeyRepository.saveAndFlush(keyWithoutToken);

        // Create and Save CryptographicKeyItem - Public Key
        CryptographicKeyItem pk = createKeyItem(keyWithoutToken, KeyType.PUBLIC_KEY, KeyState.ACTIVE, true);
        pk.setLength(1024);
        pk.setKeyData("some/encrypted/data");
        pk.setFormat(KeyFormat.SPKI);
        pk.setKeyAlgorithm(KeyAlgorithm.ECDSA);
        cryptographicKeyItemRepository.saveAndFlush(pk);

        // Ensure OwnerAssociation is created and associated
        OwnerAssociation ownerAssociation = new OwnerAssociation();
        ownerAssociation.setOwnerUuid(UUID.randomUUID()); // Set a proper UUID
        ownerAssociation.setOwnerUsername("ownerName");
        ownerAssociation.setResource(Resource.CRYPTOGRAPHIC_KEY);
        ownerAssociation.setObjectUuid(key.getUuid());
        ownerAssociation.setKey(key);
        ownerAssociationRepository.saveAndFlush(ownerAssociation);

        key.setOwner(ownerAssociation);
        cryptographicKeyRepository.saveAndFlush(key);
    }

    private void alignHistoryDeletionConstraintWithMigration() {
        String historyTable = dbSchema + ".key_event_history";
        String itemTable = dbSchema + ".cryptographic_key_item";
        List<String> generatedConstraints = jdbcTemplate.queryForList("""
                SELECT conname FROM pg_constraint
                WHERE conrelid = ?::regclass AND confrelid = ?::regclass
                  AND contype = 'f' AND confdeltype <> 'c'
                """, String.class, historyTable, itemTable);
        for (String constraint : generatedConstraints) {
            jdbcTemplate.execute("ALTER TABLE %s DROP CONSTRAINT %s".formatted(historyTable, constraint));
        }
        if (!generatedConstraints.isEmpty()) {
            // Hibernate create-drop omits the cascade shipped in V202228121130__cryptoraphic_provider.sql.
            jdbcTemplate.execute("""
                    ALTER TABLE %s ADD CONSTRAINT key_history_to_cryptographic_key_item
                    FOREIGN KEY (key_uuid) REFERENCES %s ON UPDATE NO ACTION ON DELETE CASCADE
                    """.formatted(historyTable, itemTable));
        }
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void findKeyReferenceUuidsByTokenInstanceUuid_returnsDistinctNonNullReferencesForRequestedToken() {
        // given
        UUID remoteReference = UUID.randomUUID();
        privateKeyItem.setKeyReferenceUuid(remoteReference);
        privateKeyItem.setState(KeyState.DESTROYED);
        cryptographicKeyItemRepository.saveAndFlush(privateKeyItem);
        createKeyItemWithReference(key, remoteReference);
        createKeyItemWithReference(key, null);
        TokenInstanceReference otherToken = new TokenInstanceReference();
        otherToken.setName("other token");
        otherToken.setTokenInstanceUuid(UUID.randomUUID().toString());
        otherToken.setStatus(TokenInstanceStatus.CONNECTED);
        otherToken.setKind("test token");
        tokenInstanceReferenceRepository.saveAndFlush(otherToken);
        CryptographicKey otherTokenKey = createKey("other token key", null, otherToken);
        createKeyItemWithReference(otherTokenKey, UUID.randomUUID());
        Set<UUID> expectedReferences = Set.of(remoteReference, publicKeyItem.getKeyReferenceUuid());

        // when
        Set<UUID> references = cryptographicKeyItemRepository
                .findKeyReferenceUuidsByTokenInstanceUuid(tokenInstanceReference.getUuid());

        // then
        Assertions.assertEquals(expectedReferences, references);
    }

    @Test
    void findKeyReferenceUuidsByTokenInstanceUuid_returnsEmpty_whenNoKeysMatch() {
        // given
        UUID unknownTokenUuid = UUID.randomUUID();

        // when
        Set<UUID> references = cryptographicKeyItemRepository
                .findKeyReferenceUuidsByTokenInstanceUuid(unknownTokenUuid);

        // then
        Assertions.assertTrue(references.isEmpty());
    }

    @Test
    void testGetKeyByUuid() throws NotFoundException {
        KeyDetailDto dto = cryptographicKeyService.getKey(SecuredUUID.fromUUID(key.getUuid()));
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(key.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(2, dto.getItems().size());
    }

    @Test
    void fullModel_loadsAssociationsOutsideTransaction() throws NotFoundException {
        // given
        objectAssociationService.setGroups(Resource.CRYPTOGRAPHIC_KEY, key.getUuid(), Set.of(group.getUuid()));
        Certificate certificate = certificateRepository.saveAndFlush(aCertificate().withKey(key).build());
        UUID expectedOwnerUuid = key.getOwner().getOwnerUuid();

        // when
        CryptographicKeyFullModel model = cryptographicKeyRepository.findFullModelByUuid(key.getUuid()).orElseThrow();

        // then
        Assertions.assertEquals(tokenProfile.getUuid(), model.tokenProfile().uuid());
        Assertions.assertEquals(tokenInstanceReference.getUuid(), model.tokenInstance().uuid());
        Assertions
                .assertEquals(Set.of(tokenProfile.getUuid(), tokenProfile2.getUuid()),
                        model
                                .tokenInstance()
                                .tokenProfiles()
                                .stream()
                                .map(profile -> profile.uuid())
                                .collect(Collectors.toSet()));
        Assertions
                .assertEquals(Set.of(group.getUuid()),
                        model.groups().stream().map(GroupModel::uuid).collect(Collectors.toSet()));
        Assertions.assertEquals(expectedOwnerUuid, model.ownerUuid());
        Assertions
                .assertEquals(Set.of(privateKeyItem.getUuid(), publicKeyItem.getUuid()),
                        model.items().stream().map(item -> item.uuid()).collect(Collectors.toSet()));
        Assertions
                .assertEquals(List.of(certificate.getUuid()),
                        model.certificateAssociations().stream().map(association -> association.uuid()).toList());
    }

    @Test
    void testGetKeyByUuid_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> cryptographicKeyService
                        .getKey(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testAddKey() throws ConnectorException, AlreadyExistException, AttributeException, NotFoundException {
        // given
        var expectedOwner = AuthHelper.getUserProfile().getUser();
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/pair/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/secret/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+"))
                        .willReturn(WireMock.okJson("{}")));
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/status"))
                        .willReturn(WireMock.okJson("{}")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock
                                .urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/pair/attributes/validate"))
                        .willReturn(WireMock.ok()));
        mockServer
                .stubFor(WireMock
                        .post(WireMock
                                .urlPathMatching(
                                        "/v1/cryptographyProvider/tokens/[^/]+/keys/secret/attributes/validate"))
                        .willReturn(WireMock.ok()));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/pair"))
                        .willReturn(WireMock
                                .okJson("{\"privateKeyData\":{\"name\":\"privateKey\", \"uuid\":\"149db148-8c51-11ed-a1eb-0242ac120002\", \"keyData\":{\"type\":\"Private\", \"algorithm\":\"RSA\", \"format\":\"Custom\", \"value\":{\"securityCategory\":\"5\"}}}, \"publicKeyData\":{\"name\":\"publicKey\", \"uuid\":\"149db148-8c51-11ed-a1eb-0242ac120003\",  \"keyData\":{\"type\":\"Public\", \"algorithm\":\"RSA\", \"format\":\"Raw\", \"value\":\"something priv\"}}}")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/secret"))
                        .willReturn(WireMock
                                .okJson("{\"name\":\"secretkeyitem\", \"uuid\":\"149db149-8c51-11ed-a1eb-0242ac120003\", \"keyData\":{\"type\":\"Secret\", \"algorithm\":\"RSA\", \"format\":\"Raw\", \"value\":\"something secret\"}}")));

        KeyRequestDto request = new KeyRequestDto();
        request.setName("testKeyPairKey");
        request.setDescription("sampleDescription");
        request.setAttributes(List.of());
        request.setGroupUuids(List.of(group.getUuid().toString()));

        UUID tokenInstanceReferenceUuid = tokenInstanceReference.getUuid();
        SecuredParentUUID tokenProfileUuid = tokenProfile.getSecuredParentUuid();
        // when
        KeyDetailDto dto = cryptographicKeyService
                .createKey(tokenInstanceReferenceUuid, tokenProfileUuid, KeyRequestType.KEY_PAIR, request);
        // then
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(expectedOwner.getUuid(), dto.getOwnerUuid());
        Assertions.assertEquals(expectedOwner.getUsername(), dto.getOwner());
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertEquals(2, dto.getItems().size());
        Assertions.assertEquals(1, dto.getGroups().size());
        Assertions.assertEquals(group.getUuid().toString(), dto.getGroups().getFirst().getUuid());

        request.setName("newName");
        // create key with same fingerprint
        Assertions
                .assertThrows(ValidationException.class, () -> cryptographicKeyService
                        .createKey(tokenInstanceReferenceUuid, tokenProfileUuid, KeyRequestType.KEY_PAIR, request));

        // create secret key type
        request.setName("testSecretKey");
        request.setGroupUuids(null);
        // when
        dto = cryptographicKeyService
                .createKey(tokenInstanceReferenceUuid, tokenProfileUuid, KeyRequestType.SECRET, request);

        // then
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(expectedOwner.getUuid(), dto.getOwnerUuid());
        Assertions.assertEquals(expectedOwner.getUsername(), dto.getOwner());
        Assertions.assertEquals(request.getName(), dto.getName());
        Assertions.assertEquals(1, dto.getItems().size());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void createKeyWithItems_persistsParentAndAllItems(boolean discovered) throws AttributeException {
        // given
        String keyName = "atomic-key";
        List<ProviderKeyItem> items = List.of(providerItem("first-item"), providerItem("second-item"));
        UUID expectedProfileUuid = discovered ? null : tokenProfile.getUuid();

        // when
        CryptographicKeyBasicModel created = createKeyWithItems(keyName, items, discovered);

        // then
        CryptographicKey storedKey = cryptographicKeyRepository.findByUuid(created.uuid()).orElseThrow();
        List<CryptographicKeyItem> storedItems = cryptographicKeyItemRepository
                .findByKeyUuidIn(List.of(created.uuid()));
        Assertions.assertEquals(keyName, storedKey.getName());
        Assertions.assertEquals(expectedProfileUuid, storedKey.getTokenProfileUuid());
        Assertions.assertEquals(tokenInstanceReference.getUuid(), storedKey.getTokenInstanceReferenceUuid());
        Assertions.assertEquals(items.size(), storedItems.size());
        for (CryptographicKeyItem storedItem : storedItems) {
            Assertions.assertEquals(!discovered, storedItem.isEnabled());
            Assertions
                    .assertEquals(1,
                            cryptographicKeyEventHistoryRepository.findByKeyOrderByCreatedDesc(storedItem).size());
        }
    }

    @Test
    void metadataReference_roundTripsThroughJsonb() throws AttributeException {
        // given
        String providerHandleName = "stateless-provider-handle";
        MetadataAttributeV3 handle = new MetadataAttributeV3();
        handle.setName(providerHandleName);
        handle.setUuid(UUID.randomUUID().toString());
        handle.setType(AttributeType.META);
        handle.setContentType(AttributeContentType.STRING);
        handle.setProperties(new MetadataAttributeProperties());
        handle.setContent(List.of(new StringAttributeContentV3("opaque-provider-handle")));
        RemoteKeyReference.MetadataReference reference = new RemoteKeyReference.MetadataReference(List.of(handle));
        ProviderKeyItem item = aProviderKeyItem().withReference(reference).build();

        // when
        CryptographicKeyBasicModel created = createKeyWithItems("metadata-reference-key", List.of(item), false);

        // then
        CryptographicKeyItem stored = cryptographicKeyItemRepository
                .findByKeyUuidIn(List.of(created.uuid()))
                .getFirst();
        Assertions.assertNull(stored.getKeyReferenceUuid());
        Assertions.assertEquals(providerHandleName, stored.getKeyMeta().getFirst().getName());
        Assertions
                .assertEquals(providerHandleName,
                        jdbcTemplate
                                .queryForObject(
                                        "SELECT key_meta->0->>'name' FROM " + dbSchema
                                                + ".cryptographic_key_item WHERE uuid = ?",
                                        String.class, stored.getUuid()));
        CryptographicKeyFullModel model = cryptographicKeyRepository.findFullModelByUuid(created.uuid()).orElseThrow();
        Assertions.assertInstanceOf(RemoteKeyReference.MetadataReference.class, model.items().getFirst().reference());
    }

    @Test
    void keyMetaMigration_preservesExistingRowsAndAddsNullableJsonb() throws Exception {
        // given
        UUID existingItemUuid = UUID.randomUUID();
        String migrationSql = new ClassPathResource("db/migration/V202609101200__cryptographic_key_item_meta.sql")
                .getContentAsString(StandardCharsets.UTF_8);
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        transaction.executeWithoutResult(status -> {
            jdbcTemplate.execute("CREATE TEMP TABLE cryptographic_key_item (uuid UUID PRIMARY KEY) ON COMMIT DROP");
            jdbcTemplate.update("INSERT INTO pg_temp.cryptographic_key_item (uuid) VALUES (?)", existingItemUuid);

            // when
            jdbcTemplate.execute(migrationSql);

            // then
            Assertions
                    .assertEquals(existingItemUuid,
                            jdbcTemplate.queryForObject("SELECT uuid FROM pg_temp.cryptographic_key_item", UUID.class));
            Assertions
                    .assertNull(jdbcTemplate
                            .queryForObject("SELECT key_meta::text FROM pg_temp.cryptographic_key_item", String.class));
            Assertions
                    .assertEquals("jsonb", jdbcTemplate
                            .queryForObject("SELECT pg_typeof(key_meta)::text FROM pg_temp.cryptographic_key_item",
                                    String.class));
        });
    }

    @Test
    void createAndDestroyV2Key_reusesPersistedOpaqueHandle() throws Exception {
        // given
        configureV2Token();
        String opaqueHandle = "durable-provider-key";
        stubV2SecretCreation(opaqueHandle);
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/cryptographyProvider/keys/destroy"))
                        .willReturn(WireMock.okJson("{}")));
        KeyRequestDto request = keyCreationRequest("v2-key-lifecycle");

        // when
        KeyDetailDto created = cryptographicKeyService
                .createKey(tokenInstanceReference.getUuid(), tokenProfile.getSecuredParentUuid(), KeyRequestType.SECRET,
                        request);
        UUID createdItemUuid = UUID.fromString(created.getItems().getFirst().getUuid());
        cryptographicKeyWriter.setKeyItemCompromised(createdItemUuid, KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE);
        cryptographicKeyService.destroyKey(UUID.fromString(created.getUuid()), List.of(createdItemUuid.toString()));

        // then
        CryptographicKeyItem stored = cryptographicKeyItemRepository.findByUuid(createdItemUuid).orElseThrow();
        Assertions.assertEquals(KeyState.DESTROYED_COMPROMISED, stored.getState());
        Assertions.assertNull(stored.getKeyReferenceUuid());
        Assertions.assertNull(stored.getKeyData());
        Assertions
                .assertEquals(opaqueHandle,
                        jdbcTemplate
                                .queryForObject(
                                        "SELECT key_meta->0->'content'->0->>'data' FROM " + dbSchema
                                                + ".cryptographic_key_item WHERE uuid = ?",
                                        String.class, createdItemUuid));
        mockServer
                .verify(WireMock
                        .postRequestedFor(WireMock.urlPathEqualTo("/v2/cryptographyProvider/keys/destroy"))
                        .withRequestBody(WireMock
                                .matchingJsonPath("$.keyMeta[0].content[0].data", WireMock.equalTo(opaqueHandle))));
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void createKey_statesTheExportableIntentToAV2ConnectorThatRequiresIt(boolean exportable) throws Exception {
        // given
        configureV2Token(List.of(FeatureFlag.STATELESS, FeatureFlag.KEY_EXPORT));
        tokenProfile
                .setExportableKeyTypes(
                        List.of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA))));
        tokenProfileRepository.saveAndFlush(tokenProfile);
        stubV2KeyPairCreation(List.of(KeyExportableAttribute.definition()));
        KeyRequestDto request = keyCreationRequest("v2-exportable-" + exportable);
        request.setExportable(exportable);

        // when
        KeyDetailDto created = cryptographicKeyService
                .createKey(tokenInstanceReference.getUuid(), tokenProfile.getSecuredParentUuid(),
                        KeyRequestType.KEY_PAIR, request);

        // then
        Map<KeyType, KeyItemDetailDto> items = created
                .getItems()
                .stream()
                .collect(Collectors.toMap(KeyItemDetailDto::getType, item -> item));
        Assertions.assertEquals(exportable, items.get(KeyType.PRIVATE_KEY).isExportable());
        Assertions.assertFalse(items.get(KeyType.PUBLIC_KEY).isExportable());
        Assertions.assertEquals(exportable, storedExportable(items.get(KeyType.PRIVATE_KEY)));
        Assertions.assertFalse(storedExportable(items.get(KeyType.PUBLIC_KEY)));
        mockServer
                .verify(WireMock
                        .postRequestedFor(WireMock.urlPathEqualTo("/v2/cryptographyProvider/keys"))
                        .withRequestBody(WireMock
                                .matchingJsonPath(EXPORTABLE_INTENT_ON_THE_WIRE
                                        .formatted(KeyExportableAttribute.NAME, KeyExportableAttribute.ATTRIBUTE_UUID,
                                                exportable))));
    }

    @Test
    void createKey_statesNoExportableIntentToAV2ConnectorWithoutKeyExport() throws Exception {
        // given
        configureV2Token();
        stubV2SecretCreation("unexported-provider-key");
        KeyRequestDto request = keyCreationRequest("v2-without-key-export");

        // when
        cryptographicKeyService
                .createKey(tokenInstanceReference.getUuid(), tokenProfile.getSecuredParentUuid(), KeyRequestType.SECRET,
                        request);

        // then
        mockServer.verify(1, WireMock.postRequestedFor(WireMock.urlPathEqualTo("/v2/cryptographyProvider/keys")));
        mockServer
                .verify(0,
                        WireMock
                                .postRequestedFor(WireMock.urlPathEqualTo("/v2/cryptographyProvider/keys"))
                                .withRequestBody(WireMock
                                        .matchingJsonPath("$.createKeyAttributes[?(@.name == '%s')]"
                                                .formatted(KeyExportableAttribute.NAME))));
    }

    @Test
    void createKey_suspendsAndRestoresCallerTransaction() {
        // given
        stubV1SecretCreation();
        KeyRequestDto request = keyCreationRequest("independently-committed-key");
        Group callerOnlyGroup = new Group();
        callerOnlyGroup.setName("rolled-back-caller-group");
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);

        // when
        KeyDetailDto created = transaction.execute(status -> {
            groupRepository.saveAndFlush(callerOnlyGroup);
            KeyDetailDto result;
            try {
                result = cryptographicKeyService
                        .createKey(tokenInstanceReference.getUuid(), tokenProfile.getSecuredParentUuid(),
                                KeyRequestType.SECRET, request);
            } catch (Exception e) {
                throw new AssertionError("Key creation failed before caller transaction could be restored", e);
            }
            Assertions.assertTrue(TransactionSynchronizationManager.isActualTransactionActive());
            status.setRollbackOnly();
            return result;
        });

        // then
        Assertions.assertTrue(groupRepository.findByUuid(callerOnlyGroup.getUuid()).isEmpty());
        UUID createdKeyUuid = UUID.fromString(created.getUuid());
        Assertions.assertTrue(cryptographicKeyRepository.existsById(createdKeyUuid));
        Assertions.assertEquals(1, cryptographicKeyItemRepository.findByKeyUuidIn(List.of(createdKeyUuid)).size());
    }

    private void configureV2Token() {
        configureV2Token(List.of(FeatureFlag.STATELESS));
    }

    private void configureV2Token(List<FeatureFlag> features) {
        connector.setVersion(ConnectorVersion.V2);
        connectorRepository.saveAndFlush(connector);
        ConnectorInterfaceEntity providerInterface = new ConnectorInterfaceEntity();
        providerInterface.setConnectorUuid(connector.getUuid());
        providerInterface.setConnector(connector);
        providerInterface.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        providerInterface.setVersion("v2");
        providerInterface.setFeatures(features);
        connectorInterfaceRepository.saveAndFlush(providerInterface);
        tokenInstanceReference.setConnectorInterface(providerInterface);
        tokenInstanceReferenceRepository.saveAndFlush(tokenInstanceReference);
    }

    private void stubV2SecretCreation(String opaqueHandle) throws Exception {
        stubV2SecretCreation(opaqueHandle, List.of());
    }

    private void stubV2SecretCreation(String opaqueHandle, List<BaseAttribute> createKeyAttributes) throws Exception {
        SecretKeyDataV2Dto keyData = new SecretKeyDataV2Dto();
        keyData.setAlgorithm(KeyAlgorithm.UNKNOWN);
        keyData.setLength(256);
        SecretKeyDataResponseV2Dto response = new SecretKeyDataResponseV2Dto();
        response.setKeyData(keyData);
        response.setKeyMeta(List.of(providerHandle(opaqueHandle)));
        stubV2Creation(createKeyAttributes, response);
    }

    private void stubV2KeyPairCreation(List<BaseAttribute> createKeyAttributes) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        PublicKeyDataV2Dto publicData = new PublicKeyDataV2Dto();
        publicData.setAlgorithm(KeyAlgorithm.RSA);
        publicData.setLength(2048);
        publicData.setPublicKeySpki(generator.generateKeyPair().getPublic().getEncoded());
        PublicKeyDataResponseV2Dto publicKey = new PublicKeyDataResponseV2Dto();
        publicKey.setKeyData(publicData);
        publicKey.setKeyMeta(List.of(providerHandle("public-handle")));
        PrivateKeyDataV2Dto privateData = new PrivateKeyDataV2Dto();
        privateData.setAlgorithm(KeyAlgorithm.RSA);
        privateData.setLength(2048);
        PrivateKeyDataResponseV2Dto privateKey = new PrivateKeyDataResponseV2Dto();
        privateKey.setKeyData(privateData);
        privateKey.setKeyMeta(List.of(providerHandle("private-handle")));
        KeyPairDataResponseV2Dto response = new KeyPairDataResponseV2Dto();
        response.setPublicKeyData(publicKey);
        response.setPrivateKeyData(privateKey);
        response.setKeyPairMeta(List.of(providerHandle("pair-handle")));
        stubV2Creation(createKeyAttributes, response);
    }

    private void stubV2Creation(List<BaseAttribute> createKeyAttributes, Object response) throws Exception {
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/cryptographyProvider/keys/create/attributes"))
                        .willReturn(
                                WireMock.okJson(ObjectMapperFactory.wire().writeValueAsString(createKeyAttributes))));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathEqualTo("/v2/cryptographyProvider/keys"))
                        .willReturn(WireMock.okJson(ObjectMapperFactory.wire().writeValueAsString(response))));
    }

    private static MetadataAttributeV3 providerHandle(String opaqueHandle) {
        MetadataAttributeV3 handle = new MetadataAttributeV3();
        handle.setUuid(UUID.randomUUID().toString());
        handle.setName("provider-handle");
        handle.setType(AttributeType.META);
        handle.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel("Provider handle");
        handle.setProperties(properties);
        handle.setContent(List.of(new StringAttributeContentV3(opaqueHandle)));
        return handle;
    }

    private void stubV1SecretCreation() {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/secret/attributes"))
                        .willReturn(WireMock.okJson("[]")));
        mockServer
                .stubFor(WireMock
                        .post(WireMock
                                .urlPathMatching(
                                        "/v1/cryptographyProvider/tokens/[^/]+/keys/secret/attributes/validate"))
                        .willReturn(WireMock.ok()));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/secret"))
                        .willReturn(WireMock.okJson("""
                                {"name":"secret-item","uuid":"149db149-8c51-11ed-a1eb-0242ac120003",
                                 "keyData":{"type":"Secret","algorithm":"Unknown","format":"Raw",
                                            "length":256,"value":{"value":"secret-material"}}}
                                """)));
    }

    private static KeyRequestDto keyCreationRequest(String name) {
        KeyRequestDto request = new KeyRequestDto();
        request.setName(name);
        request.setDescription("Created through the provider boundary");
        request.setAttributes(List.of());
        request.setCustomAttributes(List.of());
        request.setEnabled(true);
        return request;
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void createKeyWithItems_rollsBackParentAndEarlierItems_whenLaterItemFails(boolean discovered) {
        // given
        String keyName = "rolled-back-key";
        String rejectedItemName = "rejected-atomic-item";
        List<ProviderKeyItem> items = List.of(providerItem("accepted-item"), providerItem(rejectedItemName));
        long initialItemCount = cryptographicKeyItemRepository.count();
        long initialHistoryCount = cryptographicKeyEventHistoryRepository.count();
        String constraintName = "reject_atomic_key_item";
        String itemTable = dbSchema + ".cryptographic_key_item";
        jdbcTemplate
                .execute("ALTER TABLE %s ADD CONSTRAINT %s CHECK (name <> '%s')"
                        .formatted(itemTable, constraintName, rejectedItemName));
        try {
            // when
            Executable create = () -> createKeyWithItems(keyName, items, discovered);

            // then
            DataIntegrityViolationException failure = Assertions
                    .assertThrows(DataIntegrityViolationException.class, create);
            Assertions.assertTrue(failure.getMostSpecificCause().getMessage().contains(constraintName));
            Assertions.assertTrue(cryptographicKeyRepository.findByName(keyName).isEmpty());
            Assertions.assertEquals(initialItemCount, cryptographicKeyItemRepository.count());
            Assertions.assertEquals(initialHistoryCount, cryptographicKeyEventHistoryRepository.count());
        } finally {
            jdbcTemplate.execute("ALTER TABLE %s DROP CONSTRAINT %s".formatted(itemTable, constraintName));
        }
    }

    private CryptographicKeyBasicModel createKeyWithItems(String name, List<ProviderKeyItem> items, boolean discovered)
            throws AttributeException {
        KeyRequestDto request = new KeyRequestDto();
        request.setName(name);
        var profile = discovered ? null : ImmutableTokenProfileBasicModel.from(tokenProfile);
        var token = ImmutableTokenInstanceBasicModel.from(tokenInstanceReference);
        return cryptographicKeyWriter.createKeyWithItems(request, profile, token, items, discovered, !discovered);
    }

    private ProviderKeyItem providerItem(String name) {
        return new ProviderKeyItem(name, KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, 2048,
                new RemoteKeyReference.UuidReference(UUID.randomUUID()), null, List.of());
    }

    @Test
    void testAddKey_disabledTokenProfile() {
        tokenProfile.setEnabled(false);
        tokenProfileRepository.saveAndFlush(tokenProfile);

        KeyRequestDto request = new KeyRequestDto();
        request.setName("keyOnDisabledTokenProfile");
        request.setAttributes(List.of());
        UUID tokenInstanceUuid = tokenInstanceReference.getUuid();
        SecuredParentUUID tokenProfileUuid = tokenProfile.getSecuredParentUuid();

        ValidationException exception = Assertions
                .assertThrows(ValidationException.class, () -> cryptographicKeyService
                        .createKey(tokenInstanceUuid, tokenProfileUuid, KeyRequestType.SECRET, request));
        Assertions.assertTrue(exception.getMessage().contains("Token Profile"));
        Assertions.assertTrue(exception.getMessage().contains("disabled"));
        mockServer.verify(0, WireMock.anyRequestedFor(WireMock.anyUrl()));
    }

    @Test
    void testAddKey_tokenProfileNotFound() {
        // given
        KeyRequestDto request = new KeyRequestDto();
        request.setName("keyOnMissingTokenProfile");
        UUID tokenInstanceUuid = tokenInstanceReference.getUuid();
        SecuredParentUUID missingTokenProfileUuid = SecuredParentUUID.fromUUID(UUID.randomUUID());

        // when
        Executable create = () -> cryptographicKeyService
                .createKey(tokenInstanceUuid, missingTokenProfileUuid, KeyRequestType.SECRET, request);

        // then
        NotFoundException exception = Assertions.assertThrows(NotFoundException.class, create);
        Assertions.assertTrue(exception.getMessage().contains(missingTokenProfileUuid.getValue().toString()));
        Assertions.assertTrue(exception.getMessage().contains(tokenInstanceUuid.toString()));
        mockServer.verify(0, WireMock.anyRequestedFor(WireMock.anyUrl()));
    }

    @Test
    void testAddKey_alreadyExist() {
        KeyRequestDto request = new KeyRequestDto();
        request.setName(KEY_NAME); // raProfile with same username exist

        Assertions
                .assertThrows(AlreadyExistException.class,
                        () -> cryptographicKeyService
                                .createKey(tokenInstanceReference.getUuid(), tokenProfile.getSecuredParentUuid(),
                                        KeyRequestType.KEY_PAIR, request));
    }

    @Test
    void testDestroyKey() throws ConnectorException, NotFoundException {
        mockServer
                .stubFor(WireMock
                        .delete(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+"))
                        .willReturn(WireMock.ok()));

        privateKeyItem.setState(KeyState.DEACTIVATED);
        publicKeyItem.setState(KeyState.DEACTIVATED);
        cryptographicKeyItemRepository.save(privateKeyItem);
        cryptographicKeyItemRepository.save(publicKeyItem);

        cryptographicKeyService
                .destroyKey(key.getUuid(),
                        List.of(privateKeyItem.getUuid().toString(), publicKeyItem.getUuid().toString()));
        Assertions
                .assertEquals(KeyState.DESTROYED,
                        cryptographicKeyService
                                .getKeyItem(key.getSecuredUuid(), privateKeyItem.getUuid().toString())
                                .getState());
    }

    @Test
    void destroyKey_preservesCompromiseCommittedDuringConnectorCall() throws Exception {
        // given
        UUID itemUuid = privateKeyItem.getUuid();
        KeyCompromiseReason reason = KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE;
        privateKeyItem.setState(KeyState.DEACTIVATED);
        cryptographicKeyItemRepository.saveAndFlush(privateKeyItem);
        CompletableFuture<Optional<String>> compromise = compromiseBeforeDestructionResponse(itemUuid, reason);

        // when
        cryptographicKeyService.destroyKey(key.getUuid(), List.of(itemUuid.toString()));

        // then
        Assertions.assertTrue(compromise.get(10, TimeUnit.SECONDS).isEmpty());
        CryptographicKeyItem stored = cryptographicKeyItemRepository.findByUuid(itemUuid).orElseThrow();
        Assertions.assertEquals(KeyState.DESTROYED_COMPROMISED, stored.getState());
        Assertions.assertEquals(reason, stored.getReason());
        Assertions.assertNull(stored.getKeyData());
        var history = cryptographicKeyEventHistoryRepository.findByKeyOrderByCreatedDesc(stored);
        Assertions
                .assertTrue(history
                        .stream()
                        .anyMatch(event -> event.getEvent() == KeyEvent.COMPROMISED
                                && event.getStatus() == KeyEventStatus.SUCCESS));
        Assertions
                .assertTrue(history
                        .stream()
                        .anyMatch(event -> event.getEvent() == KeyEvent.DESTROY
                                && event.getStatus() == KeyEventStatus.SUCCESS));
    }

    private CompletableFuture<Optional<String>> compromiseBeforeDestructionResponse(UUID itemUuid,
            KeyCompromiseReason reason) {
        CompletableFuture<Optional<String>> compromise = new CompletableFuture<>();
        String destructionPath = "/v1/cryptographyProvider/tokens/" + tokenInstanceReference.getTokenInstanceUuid()
                + "/keys/" + privateKeyItem.getKeyReferenceUuid();
        ServeEventListener listener = new ServeEventListener() {
            @Override
            public void beforeResponseSent(ServeEvent serveEvent, Parameters parameters) {
                if (!serveEvent.getRequest().getUrl().equals(destructionPath)) {
                    return;
                }
                try {
                    TransactionTemplate transaction = new TransactionTemplate(transactionManager);
                    Optional<String> rejection = transaction.execute(status -> {
                        jdbcTemplate.execute("SET LOCAL lock_timeout = '5s'");
                        try {
                            return cryptographicKeyWriter.setKeyItemCompromised(itemUuid, reason);
                        } catch (NotFoundException e) {
                            throw new IllegalStateException("Key item disappeared during concurrent compromise", e);
                        }
                    });
                    compromise.complete(rejection);
                } catch (Exception e) {
                    compromise.completeExceptionally(e);
                }
            }

            @Override
            public String getName() {
                return "compromise-before-destruction-response";
            }
        };
        mockServer.stop();
        mockServer = new WireMockServer(WireMockConfiguration.wireMockConfig().dynamicPort().extensions(listener));
        mockServer.start();
        connector.setUrl("http://localhost:" + mockServer.port());
        connectorRepository.saveAndFlush(connector);
        mockServer.stubFor(WireMock.delete(WireMock.urlPathEqualTo(destructionPath)).willReturn(WireMock.ok()));
        return compromise;
    }

    @Test
    void testDestroyKey_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> cryptographicKeyService
                        .getKey(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testDestroyKey_validationError() {
        mockServer
                .stubFor(WireMock.delete(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+")));

        UUID keyUuid = key.getUuid();
        List<String> keyItemsUuids = List.of(privateKeyItem.getUuid().toString(), publicKeyItem.getUuid().toString());
        Assertions
                .assertThrows(ValidationException.class,
                        () -> cryptographicKeyService.destroyKey(keyUuid, keyItemsUuids));
    }

    @Test
    void testDestroyKey_parentKeyObject() throws ConnectorException, NotFoundException {
        mockServer
                .stubFor(WireMock
                        .delete(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+"))
                        .willReturn(WireMock.ok()));

        privateKeyItem.setState(KeyState.DEACTIVATED);
        publicKeyItem.setState(KeyState.DEACTIVATED);
        cryptographicKeyItemRepository.save(privateKeyItem);
        cryptographicKeyItemRepository.save(publicKeyItem);

        cryptographicKeyService.destroyKey(List.of(key.getUuid().toString()));

        KeyItemDetailDto keyItemDetailDto = cryptographicKeyService
                .getKeyItem(key.getSecuredUuid(), privateKeyItem.getUuid().toString());
        Assertions.assertEquals(KeyState.DESTROYED, keyItemDetailDto.getState());
        Assertions.assertNull(keyItemDetailDto.getKeyData());
    }

    @Test
    void testCompromiseKey() throws NotFoundException {
        cryptographicKeyService
                .compromiseKey(key.getUuid(), new CompromiseKeyRequestDto(KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE,
                        List.of(privateKeyItem.getUuid(), publicKeyItem.getUuid())));
        Assertions
                .assertEquals(KeyState.COMPROMISED,
                        cryptographicKeyService
                                .getKeyItem(key.getSecuredUuid(), privateKeyItem.getUuid().toString())
                                .getState());
        Assertions
                .assertEquals(KeyState.COMPROMISED,
                        cryptographicKeyService
                                .getKeyItem(key.getSecuredUuid(), publicKeyItem.getUuid().toString())
                                .getState());
    }

    @Test
    void setKeyItemCompromised_persistsStateReasonAndSuccessHistory() throws NotFoundException {
        // given
        UUID itemUuid = privateKeyItem.getUuid();
        KeyCompromiseReason reason = KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE;

        // when
        Optional<String> rejection = cryptographicKeyWriter.setKeyItemCompromised(itemUuid, reason);

        // then
        CryptographicKeyItem storedItem = cryptographicKeyItemRepository.findByUuid(itemUuid).orElseThrow();
        var history = cryptographicKeyEventHistoryRepository.findByKeyOrderByCreatedDesc(storedItem);
        Assertions.assertTrue(rejection.isEmpty());
        Assertions.assertEquals(KeyState.COMPROMISED, storedItem.getState());
        Assertions.assertEquals(reason, storedItem.getReason());
        Assertions.assertEquals(1, history.size());
        Assertions.assertEquals(KeyEvent.COMPROMISED, history.getFirst().getEvent());
        Assertions.assertEquals(KeyEventStatus.SUCCESS, history.getFirst().getStatus());
    }

    @Test
    void compromise_waitsForConcurrentWriterAndRechecksState() throws Exception {
        // given
        UUID itemUuid = privateKeyItem.getUuid();
        KeyState concurrentlyCommittedState = KeyState.DESTROYED;
        KeyCompromiseReason requestedReason = KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE;
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        try (ExecutorService contender = Executors.newSingleThreadExecutor()) {
            // when
            Future<Optional<String>> outcome = transaction.execute(status -> {
                CryptographicKeyItem locked = cryptographicKeyItemRepository
                        .findForUpdateByUuid(itemUuid)
                        .orElseThrow();
                locked.setState(concurrentlyCommittedState);
                cryptographicKeyItemRepository.saveAndFlush(locked);
                int lockHolderPid = jdbcTemplate.queryForObject("SELECT pg_backend_pid()", Integer.class);
                Future<Optional<String>> waitingWriter = contender
                        .submit(() -> cryptographicKeyWriter.setKeyItemCompromised(itemUuid, requestedReason));
                Awaitility
                        .await()
                        .atMost(Duration.ofSeconds(10))
                        .until(() -> jdbcTemplate
                                .queryForObject(
                                        "SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))",
                                        Long.class, lockHolderPid) > 0);
                return waitingWriter;
            });

            // then
            Optional<String> rejection = outcome.get(10, TimeUnit.SECONDS);
            Assertions.assertTrue(rejection.orElseThrow().contains(concurrentlyCommittedState.getLabel()));
            CryptographicKeyItem stored = cryptographicKeyItemRepository.findByUuid(itemUuid).orElseThrow();
            Assertions.assertEquals(concurrentlyCommittedState, stored.getState());
            Assertions.assertNull(stored.getReason());
            Assertions
                    .assertEquals(KeyEventStatus.FAILED,
                            cryptographicKeyEventHistoryRepository
                                    .findByKeyOrderByCreatedDesc(stored)
                                    .getFirst()
                                    .getStatus());
        }
    }

    @Test
    void writer_joinsAmbientTransaction() {
        // given
        UUID itemUuid = privateKeyItem.getUuid();
        KeyState initialState = privateKeyItem.getState();
        long initialHistoryCount = cryptographicKeyEventHistoryRepository.count();
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);

        // when
        transaction.executeWithoutResult(status -> {
            try {
                cryptographicKeyWriter.setKeyItemCompromised(itemUuid, KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE);
                status.setRollbackOnly();
            } catch (NotFoundException e) {
                throw new AssertionError("Existing item disappeared during writer transaction", e);
            }
        });

        // then
        Assertions
                .assertEquals(initialState,
                        cryptographicKeyItemRepository.findByUuid(itemUuid).orElseThrow().getState());
        Assertions.assertEquals(initialHistoryCount, cryptographicKeyEventHistoryRepository.count());
    }

    @Test
    void setKeyItemCompromised_preservesItemAndRecordsFailure_whenStateIsInvalid() throws NotFoundException {
        // given
        KeyState entryState = KeyState.COMPROMISED;
        KeyCompromiseReason entryReason = KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE;
        KeyCompromiseReason requestedReason = KeyCompromiseReason.UNAUTHORIZED_MODIFICATION;
        privateKeyItem.setState(entryState);
        privateKeyItem.setReason(entryReason);
        cryptographicKeyItemRepository.saveAndFlush(privateKeyItem);
        UUID itemUuid = privateKeyItem.getUuid();

        // when
        Optional<String> rejection = cryptographicKeyWriter.setKeyItemCompromised(itemUuid, requestedReason);

        // then
        CryptographicKeyItem storedItem = cryptographicKeyItemRepository.findByUuid(itemUuid).orElseThrow();
        var history = cryptographicKeyEventHistoryRepository.findByKeyOrderByCreatedDesc(storedItem);
        Assertions.assertEquals(Optional.of(history.getFirst().getMessage()), rejection);
        Assertions.assertEquals(entryState, storedItem.getState());
        Assertions.assertEquals(entryReason, storedItem.getReason());
        Assertions.assertEquals(1, history.size());
        Assertions.assertEquals(KeyEvent.COMPROMISED, history.getFirst().getEvent());
        Assertions.assertEquals(KeyEventStatus.FAILED, history.getFirst().getStatus());
    }

    @ParameterizedTest
    @EnumSource(value = KeyEvent.class, names = {"COMPROMISED", "UPDATE_USAGE"})
    void writerUpdate_rollsBackItem_whenHistoryInsertFails(KeyEvent event) {
        // given
        UUID itemUuid = privateKeyItem.getUuid();
        KeyState entryState = privateKeyItem.getState();
        KeyCompromiseReason entryReason = privateKeyItem.getReason();
        List<KeyUsage> entryUsages = privateKeyItem.getUsage();
        List<KeyUsage> requestedUsages = entryUsages.isEmpty() ? List.of(KeyUsage.SIGN) : List.of();
        KeyCompromiseReason requestedReason = KeyCompromiseReason.UNAUTHORIZED_DISCLOSURE;
        String constraintName = "reject_history_for_test_item";
        String historyTable = dbSchema + ".key_event_history";
        jdbcTemplate
                .execute("ALTER TABLE %s ADD CONSTRAINT %s CHECK (key_uuid <> '%s'::uuid)"
                        .formatted(historyTable, constraintName, itemUuid));
        try {
            // when
            org.junit.jupiter.api.function.Executable update = () -> {
                if (event == KeyEvent.COMPROMISED) {
                    cryptographicKeyWriter.setKeyItemCompromised(itemUuid, requestedReason);
                } else {
                    cryptographicKeyWriter.updateUsage(itemUuid, requestedUsages);
                }
            };

            // then
            DataIntegrityViolationException failure = Assertions
                    .assertThrows(DataIntegrityViolationException.class, update);
            Assertions.assertTrue(failure.getMostSpecificCause().getMessage().contains(constraintName));
            CryptographicKeyItem storedItem = cryptographicKeyItemRepository.findByUuid(itemUuid).orElseThrow();
            Assertions.assertEquals(entryState, storedItem.getState());
            Assertions.assertEquals(entryReason, storedItem.getReason());
            Assertions.assertEquals(entryUsages, storedItem.getUsage());
            Assertions
                    .assertTrue(
                            cryptographicKeyEventHistoryRepository.findByKeyOrderByCreatedDesc(storedItem).isEmpty());
        } finally {
            jdbcTemplate.execute("ALTER TABLE %s DROP CONSTRAINT %s".formatted(historyTable, constraintName));
        }
    }

    @Test
    void testCompromisedKey_notFound() {
        Assertions
                .assertThrows(NotFoundException.class, () -> cryptographicKeyService
                        .getKey(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void testCompromiseKey_validationError() throws NotFoundException {
        cryptographicKeyService
                .compromiseKey(key.getUuid(), new CompromiseKeyRequestDto(KeyCompromiseReason.UNAUTHORIZED_MODIFICATION,
                        List.of(privateKeyItem.getUuid(), publicKeyItem.getUuid())));

        UUID keyUuid = key.getUuid();
        List<UUID> keyItemsUuids = List.of(privateKeyItem.getUuid(), publicKeyItem.getUuid());
        CompromiseKeyRequestDto keyRequestDto = new CompromiseKeyRequestDto(
                KeyCompromiseReason.UNAUTHORIZED_MODIFICATION, keyItemsUuids);
        Assertions
                .assertThrows(ValidationException.class,
                        () -> cryptographicKeyService.compromiseKey(keyUuid, keyRequestDto));
    }

    @Test
    void testCompromisedKey_parentKeyObject() throws NotFoundException {
        cryptographicKeyService
                .compromiseKey(new BulkCompromiseKeyRequestDto(KeyCompromiseReason.UNAUTHORIZED_SUBSTITUTION,
                        List.of(key.getUuid())));
        Assertions
                .assertEquals(KeyState.COMPROMISED,
                        cryptographicKeyService
                                .getKeyItem(key.getSecuredUuid(), privateKeyItem.getUuid().toString())
                                .getState());
        Assertions.assertNotEquals(null, privateKeyItem.getKeyData());
        Assertions
                .assertEquals(KeyState.COMPROMISED,
                        cryptographicKeyService
                                .getKeyItem(key.getSecuredUuid(), publicKeyItem.getUuid().toString())
                                .getState());
        Assertions.assertNotEquals(null, publicKeyItem.getKeyData());
    }

    @Test
    void updateUsage_persistsUsagesAndSuccessHistory() throws NotFoundException {
        // given
        UUID itemUuid = privateKeyItem.getUuid();
        List<KeyUsage> requestedUsages = List.of(KeyUsage.SIGN);
        String oldUsages = privateKeyItem.getUsage().stream().map(KeyUsage::getCode).collect(Collectors.joining(", "));
        String expectedMessage = "Key usages updated from " + oldUsages + " to " + KeyUsage.SIGN.getCode() + ".";

        // when
        Optional<String> rejection = cryptographicKeyWriter.updateUsage(itemUuid, requestedUsages);

        // then
        CryptographicKeyItem storedItem = cryptographicKeyItemRepository.findByUuid(itemUuid).orElseThrow();
        var history = cryptographicKeyEventHistoryRepository.findByKeyOrderByCreatedDesc(storedItem);
        Assertions.assertTrue(rejection.isEmpty());
        Assertions.assertEquals(requestedUsages, storedItem.getUsage());
        Assertions.assertEquals(1, history.size());
        Assertions.assertEquals(KeyEvent.UPDATE_USAGE, history.getFirst().getEvent());
        Assertions.assertEquals(KeyEventStatus.SUCCESS, history.getFirst().getStatus());
        Assertions.assertEquals(expectedMessage, history.getFirst().getMessage());
    }

    @Test
    void updateUsage_preservesUsagesAndRecordsFailure_whenUsageIsUnsupported() throws NotFoundException {
        // given
        UUID itemUuid = privateKeyItem.getUuid();
        List<KeyUsage> entryUsages = privateKeyItem.getUsage();
        List<KeyUsage> unsupportedUsages = List.of(KeyUsage.VERIFY);

        // when
        Optional<String> rejection = cryptographicKeyWriter.updateUsage(itemUuid, unsupportedUsages);

        // then
        CryptographicKeyItem storedItem = cryptographicKeyItemRepository.findByUuid(itemUuid).orElseThrow();
        var history = cryptographicKeyEventHistoryRepository.findByKeyOrderByCreatedDesc(storedItem);
        Assertions.assertEquals(Optional.of(history.getFirst().getMessage()), rejection);
        Assertions.assertEquals(entryUsages, storedItem.getUsage());
        Assertions.assertEquals(1, history.size());
        Assertions.assertEquals(KeyEvent.UPDATE_USAGE, history.getFirst().getEvent());
        Assertions.assertEquals(KeyEventStatus.FAILED, history.getFirst().getStatus());
    }

    @Test
    void testUpdateKeyUsage() throws NotFoundException {
        UpdateKeyUsageRequestDto request = new UpdateKeyUsageRequestDto();
        request.setUuids(List.of(privateKeyItem.getUuid()));
        request.setUsage(List.of(KeyUsage.DECRYPT));
        cryptographicKeyService.updateKeyUsages(key.getUuid(), request);
        Assertions
                .assertEquals(1,
                        cryptographicKeyService
                                .getKeyItem(key.getSecuredUuid(), privateKeyItem.getUuid().toString())
                                .getUsage()
                                .size());
    }

    @Test
    void editKey_withMissingGroup_rollsBackKeyAndGroups() throws Exception {
        // given
        EditKeyRequestDto initialRequest = new EditKeyRequestDto();
        initialRequest.setGroupUuids(List.of(group.getUuid().toString()));
        cryptographicKeyService.editKey(key.getSecuredUuid(), initialRequest);
        UUID missingGroupUuid = UUID.randomUUID();
        String changedName = "must-not-be-persisted";
        EditKeyRequestDto request = new EditKeyRequestDto();
        request.setName(changedName);
        request.setGroupUuids(List.of(missingGroupUuid.toString()));

        // when
        org.junit.jupiter.api.function.Executable update = () -> cryptographicKeyService
                .editKey(key.getSecuredUuid(), request);

        // then
        NotFoundException failure = Assertions.assertThrows(NotFoundException.class, update);
        Assertions.assertTrue(failure.getMessage().contains(missingGroupUuid.toString()));
        CryptographicKey persistedKey = cryptographicKeyRepository.findWithGroupsByUuid(key.getUuid()).orElseThrow();
        Assertions.assertEquals(KEY_NAME, persistedKey.getName());
        Assertions
                .assertEquals(Set.of(group.getUuid()),
                        persistedKey
                                .getGroups()
                                .stream()
                                .map(Group::getUuid)
                                .collect(java.util.stream.Collectors.toSet()));
    }

    @Test
    void update_withInvalidAttributes_rollsBackKeyAndAssociations() {
        // given
        String changedName = "rolled-back-key";
        String unknownAttributeName = "unassociated-custom-attribute";
        NameAndUuidDto replacementOwner = new NameAndUuidDto(UUID.randomUUID().toString(), "replacement-owner");
        UUID originalOwnerUuid = key.getOwner().getOwnerUuid();
        RequestAttributeV3 invalidAttribute = new RequestAttributeV3();
        invalidAttribute.setName(unknownAttributeName);
        EditKeyRequestDto request = new EditKeyRequestDto();
        request.setName(changedName);
        request.setGroupUuids(List.of(group.getUuid().toString()));
        request.setCustomAttributes(List.of(invalidAttribute));

        // when
        org.junit.jupiter.api.function.Executable update = () -> cryptographicKeyWriter
                .update(key.getUuid(), request, replacementOwner, null);

        // then
        Assertions.assertThrows(ValidationException.class, update);
        CryptographicKey persistedKey = cryptographicKeyRepository
                .findWithAssociationsByUuid(key.getUuid())
                .orElseThrow();
        Assertions.assertEquals(KEY_NAME, persistedKey.getName());
        Assertions.assertTrue(persistedKey.getGroups().isEmpty());
        Assertions.assertEquals(originalOwnerUuid, persistedKey.getOwner().getOwnerUuid());
    }

    @Test
    void testUpdateKey() throws NotFoundException, AttributeException {
        EditKeyRequestDto request = new EditKeyRequestDto();
        request.setName("updatedName");
        request.setDescription("updatedDescription");
        request.setTokenProfileUuid(tokenProfile2.getUuid().toString());
        request.setGroupUuids(List.of(group.getUuid().toString()));

        cryptographicKeyService.editKey(key.getSecuredUuid(), request);

        KeyDetailDto keyDetailDto = cryptographicKeyService.getKey(key.getSecuredUuid());
        Assertions.assertEquals(request.getName(), keyDetailDto.getName());
        Assertions.assertEquals(request.getDescription(), keyDetailDto.getDescription());
        Assertions.assertEquals(request.getTokenProfileUuid(), keyDetailDto.getTokenProfileUuid());
        Assertions.assertEquals(1, keyDetailDto.getGroups().size());
        Assertions.assertEquals(group.getUuid().toString(), keyDetailDto.getGroups().getFirst().getUuid());

        TokenInstanceReference tokenInstanceReference2 = new TokenInstanceReference();
        tokenInstanceReference2.setStatus(TokenInstanceStatus.CONNECTED);
        tokenInstanceReference2.setName("Token2");
        tokenInstanceReference2.setTokenInstanceUuid("2l");
        tokenInstanceReference2.setConnector(connector);
        tokenInstanceReferenceRepository.saveAndFlush(tokenInstanceReference2);

        tokenProfile2.setTokenInstanceReference(tokenInstanceReference2);
        tokenProfileRepository.saveAndFlush(tokenProfile2);

        request.setName("");
        SecuredUUID securedUuid = key.getSecuredUuid();
        Assertions.assertThrows(ValidationException.class, () -> cryptographicKeyService.editKey(securedUuid, request));

        EditKeyRequestDto requestEmpty = new EditKeyRequestDto();
        keyDetailDto = cryptographicKeyService.editKey(key.getSecuredUuid(), requestEmpty);
        Assertions.assertEquals("updatedName", keyDetailDto.getName());
    }

    @Test
    void testUpdateKey_tokenProfileNotFound() {
        EditKeyRequestDto request = new EditKeyRequestDto();
        request.setTokenProfileUuid(UUID.randomUUID().toString());
        SecuredUUID keyUuid = key.getSecuredUuid();

        NotFoundException exception = Assertions
                .assertThrows(NotFoundException.class, () -> cryptographicKeyService.editKey(keyUuid, request));

        Assertions.assertTrue(exception.getMessage().contains(TokenProfile.class.getSimpleName()));
    }

    @Test
    void testUpdateKey_disabledTokenProfile() {
        tokenProfile2.setEnabled(false);
        tokenProfileRepository.saveAndFlush(tokenProfile2);
        UUID originalTokenProfileUuid = key.getTokenProfileUuid();
        String originalName = key.getName();
        String originalDescription = key.getDescription();
        EditKeyRequestDto request = new EditKeyRequestDto();
        request.setName("rejectedName");
        request.setDescription("rejectedDescription");
        request.setTokenProfileUuid(tokenProfile2.getUuid().toString());
        SecuredUUID keyUuid = key.getSecuredUuid();

        Assertions.assertThrows(ValidationException.class, () -> cryptographicKeyService.editKey(keyUuid, request));

        CryptographicKey persistedKey = cryptographicKeyRepository.findByUuid(key.getUuid()).orElseThrow();
        Assertions.assertEquals(originalTokenProfileUuid, persistedKey.getTokenProfileUuid());
        Assertions.assertEquals(originalName, persistedKey.getName());
        Assertions.assertEquals(originalDescription, persistedKey.getDescription());
    }

    @Test
    void testListCreateKeyAttributes_disabledTokenProfile() {
        tokenProfile.setEnabled(false);
        tokenProfileRepository.saveAndFlush(tokenProfile);
        UUID tokenInstanceUuid = tokenInstanceReference.getUuid();
        SecuredParentUUID tokenProfileUuid = tokenProfile.getSecuredParentUuid();

        Assertions
                .assertThrows(ValidationException.class, () -> cryptographicKeyService
                        .listCreateKeyAttributes(tokenInstanceUuid, tokenProfileUuid, KeyRequestType.SECRET));

        mockServer.verify(0, WireMock.anyRequestedFor(WireMock.anyUrl()));
    }

    @Test
    void testSync_allNewObject() throws ConnectorException, AttributeException, NotFoundException {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys"))
                        .willReturn(WireMock.okJson("""
                                [
                                    {
                                        "name":"key1",
                                        "uuid":"e7426f1e-8ccc-11ed-a1eb-0242ac120002",
                                        "association":"",
                                        "keyData":{
                                            "type":"Secret",
                                            "algorithm":"RSA",
                                            "format":"Raw",
                                            "value":{"value":"sampleKeyValue1"},
                                            "length":1024
                                        }
                                    },
                                \t{
                                        "name":"key2",
                                        "uuid":"e7426f1e-8ccc-11ed-a1eb-0242ac120003",
                                        "association":"",
                                        "keyData":{
                                            "type":"Private",
                                            "algorithm":"RSA",
                                            "format":"Raw",
                                            "value":{"value":"sampleKeyValue2"},
                                            "length":1024
                                        }
                                    },
                                \t{
                                        "name":"key3",
                                        "uuid":"e7426f1e-8ccc-11ed-a1eb-0242ac120004",
                                        "association":"",
                                        "keyData":{
                                            "type":"Public",
                                            "algorithm":"RSA",
                                            "format":"Raw",
                                            "value":{"value":"sampleKeyValue3"},
                                            "length":1024
                                        }
                                    },
                                \t{
                                        "name":"key4",
                                        "uuid":"e7426f1e-8ccc-11ed-a1eb-0242ac120005",
                                        "association":"sampleKeyPair",
                                        "keyData":{
                                            "type":"Private",
                                            "algorithm":"RSA",
                                            "format":"Raw",
                                            "value":{"value":"sampleKeyValue4"},
                                            "length":1024
                                        }
                                    },
                                \t{
                                        "name":"keySPrivate4",
                                        "uuid":"e7426f1e-8ccc-11ed-a1eb-0242ac120006",
                                        "association":"sampleKeyPair",
                                        "keyData":{
                                            "type":"Public",
                                            "algorithm":"RSA",
                                            "format":"Raw",
                                            "value":{"value":"sampleKeyValue5"},
                                            "length":1024
                                        }
                                    }
                                ]""")));
        cryptographicKeyService.syncKeys(tokenInstanceReference.getSecuredParentUuid());

        Assertions.assertEquals(8, cryptographicKeyItemRepository.count());
    }

    @Test
    void testSync_existingObject() throws ConnectorException, AttributeException, NotFoundException {
        mockServer
                .stubFor(WireMock
                        .get(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys"))
                        .willReturn(WireMock
                                .okJson("[\n" + "    {\n" + "        \"name\":\"key1\",\n" + "        \"uuid\":\""
                                        + privateKeyItem.getUuid().toString() + "\",\n"
                                        + "        \"association\":\"\",\n" + "        \"keyData\":{\n"
                                        + "            \"type\":\"Secret\",\n" + "            \"algorithm\":\"RSA\",\n"
                                        + "            \"format\":\"Raw\",\n"
                                        + "            \"value\":{\"value\":\"sampleKeyValue1\"},\n"
                                        + "            \"length\":1024\n" + "        }\n" + "    },\n" + "\t{\n"
                                        + "        \"name\":\"key2\",\n" + "        \"uuid\":\""
                                        + publicKeyItem.getUuid().toString() + "\",\n"
                                        + "        \"association\":\"\",\n" + "        \"keyData\":{\n"
                                        + "            \"type\":\"Private\",\n" + "            \"algorithm\":\"RSA\",\n"
                                        + "            \"format\":\"Raw\",\n"
                                        + "            \"value\":{\"value\":\"sampleKeyValue2\"},\n"
                                        + "            \"length\":1024\n" + "        }\n" + "    },\n" + "\t{\n"
                                        + "        \"name\":\"key3\",\n"
                                        + "        \"uuid\":\"e7426f1e-8ccc-11ed-a1eb-0242ac120004\",\n"
                                        + "        \"association\":\"\",\n" + "        \"keyData\":{\n"
                                        + "            \"type\":\"Public\",\n" + "            \"algorithm\":\"RSA\",\n"
                                        + "            \"format\":\"Raw\",\n"
                                        + "            \"value\":{\"value\":\"sampleKeyValue3\"},\n"
                                        + "            \"length\":1024\n" + "        }\n" + "    },\n" + "\t{\n"
                                        + "        \"name\":\"key4\",\n"
                                        + "        \"uuid\":\"e7426f1e-8ccc-11ed-a1eb-0242ac120005\",\n"
                                        + "        \"association\":\"sampleKeyPair\",\n" + "        \"keyData\":{\n"
                                        + "            \"type\":\"Private\",\n" + "            \"algorithm\":\"RSA\",\n"
                                        + "            \"format\":\"Raw\",\n"
                                        + "            \"value\":{\"value\":\"sampleKeyValue4\"},\n"
                                        + "            \"length\":1024\n" + "        }\n" + "    },\n" + "\t{\n"
                                        + "        \"name\":\"keySPrivate4\",\n"
                                        + "        \"uuid\":\"e7426f1e-8ccc-11ed-a1eb-0242ac120006\",\n"
                                        + "        \"association\":\"sampleKeyPair\",\n" + "        \"keyData\":{\n"
                                        + "            \"type\":\"Public\",\n" + "            \"algorithm\":\"RSA\",\n"
                                        + "            \"format\":\"Raw\",\n"
                                        + "            \"value\":{\"value\":\"sampleKeyValue5\"},\n"
                                        + "            \"length\":1024\n" + "        }\n" + "    }\n" + "]")));
        cryptographicKeyService.syncKeys(tokenInstanceReference.getSecuredParentUuid());

        Assertions.assertEquals(6, cryptographicKeyItemRepository.count());
    }

    @Test
    void testEditKeyItem() throws NotFoundException {
        final String NEW_NAME = "new name";
        EditKeyItemDto request = new EditKeyItemDto();
        request.setName(NEW_NAME);
        cryptographicKeyService.editKeyItem(SecuredUUID.fromUUID(key.getUuid()), privateKeyItem.getUuid(), request);
        privateKeyItem = cryptographicKeyItemRepository.findByUuid(privateKeyItem.getUuid()).orElse(null);
        Assertions.assertNotNull(privateKeyItem);
        Assertions.assertEquals(NEW_NAME, privateKeyItem.getName());
    }

    @Test
    void editKeyItem_rejectsForeignParentWithoutRenamingItem() {
        // given
        UUID foreignParentUuid = keyWithoutToken.getUuid();
        String originalName = privateKeyItem.getName();
        EditKeyItemDto request = new EditKeyItemDto();
        request.setName("forbidden-rename");

        // when
        Executable edit = () -> cryptographicKeyWriter
                .editKeyItem(foreignParentUuid, privateKeyItem.getUuid(), request);

        // then
        Assertions.assertThrows(NotFoundException.class, edit);
        Assertions
                .assertEquals(originalName,
                        cryptographicKeyItemRepository.findByUuid(privateKeyItem.getUuid()).orElseThrow().getName());
    }

    @Test
    void editKeyItemRequiresUpdatePermission() {
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.UPDATE);

        EditKeyItemDto request = new EditKeyItemDto();
        request.setName("renamed");
        SecuredUUID keyUuid = SecuredUUID.fromUUID(key.getUuid());
        UUID keyItemUuid = privateKeyItem.getUuid();

        Assertions
                .assertThrows(AccessDeniedException.class,
                        () -> cryptographicKeyService.editKeyItem(keyUuid, keyItemUuid, request));
    }

    @Test
    void testListingKeys() {
        SearchRequestDto searchRequestDto = new SearchRequestDto();
        searchRequestDto.setItemsPerPage(10);
        searchRequestDto.setPageNumber(1);
        searchRequestDto
                .setFilters(List
                        .of(new SearchFilterRequestDto(FilterFieldSource.PROPERTY,
                                FilterField.CKI_CRYPTOGRAPHIC_ALGORITHM.toString(), FilterConditionOperator.EQUALS,
                                "RSA")));
        CryptographicKeyResponseDto response = cryptographicKeyService
                .listCryptographicKeys(SecurityFilter.create(), searchRequestDto);
        Assertions.assertEquals(2, response.getTotalItems());

        searchRequestDto
                .setFilters(List
                        .of(new SearchFilterRequestDto(FilterFieldSource.PROPERTY, FilterField.CKI_TYPE.toString(),
                                FilterConditionOperator.EQUALS, KeyType.PUBLIC_KEY.getCode())));
        response = cryptographicKeyService.listCryptographicKeys(SecurityFilter.create(), searchRequestDto);
        Assertions.assertEquals(2, response.getTotalItems());

        List<KeyDto> keyPairs = cryptographicKeyService
                .listKeyPairs(Optional.ofNullable(tokenProfile.getUuid().toString()), SecurityFilter.create());
        Assertions.assertEquals(1, keyPairs.size());

        publicKeyItem.setState(KeyState.DEACTIVATED);
        cryptographicKeyItemRepository.saveAndFlush(publicKeyItem);
        keyPairs = cryptographicKeyService.listKeyPairs(Optional.empty(), SecurityFilter.create());
        Assertions.assertEquals(0, keyPairs.size());
    }

    @Test
    void listKeyPairs_countsPrimaryAndAlternativeCertificateLinks() {
        // given
        certificateRepository
                .saveAllAndFlush(List
                        .of(aCertificate().withKey(key).build(), aCertificate().withAltKeyUuid(key.getUuid()).build(),
                                aCertificate().withKey(key).withAltKeyUuid(key.getUuid()).build(),
                                aCertificate().withKey(keyWithoutToken).build()));
        int certificateLinks = 4;
        int siblingItem = 1;

        // when
        List<KeyDto> pairs = cryptographicKeyService.listKeyPairs(Optional.empty(), SecurityFilter.create());

        // then
        Assertions.assertEquals(1, pairs.size());
        Assertions.assertEquals(key.getUuid().toString(), pairs.getFirst().getUuid());
        Assertions.assertEquals(certificateLinks + siblingItem, pairs.getFirst().getAssociations());
    }

    @Test
    void getCertificateAssociationCounts_returnsZeroForUnassociatedKey() {
        // given
        List<UUID> keyUuids = List.of(key.getUuid());

        // when
        var counts = cryptographicKeyRepository.getCertificateAssociationCounts(keyUuids);

        // then
        Assertions.assertEquals(1, counts.size());
        Assertions.assertEquals(key.getUuid(), counts.getFirst().getUuid());
        Assertions.assertEquals(0L, counts.getFirst().getAssociations());
    }

    @Test
    void testDeleteKey() throws ConnectorException, NotFoundException {
        cryptographicKeyService.deleteKey(key.getUuid(), List.of(publicKeyItem.getUuid().toString()));

        KeyDetailDto keyDetailDto = cryptographicKeyService.getKey(SecuredUUID.fromUUID(key.getUuid()));
        Assertions.assertEquals(1, keyDetailDto.getItems().size());
        Assertions.assertEquals(privateKeyItem.getUuid().toString(), keyDetailDto.getItems().getFirst().getUuid());

        cryptographicKeyService.deleteKey(key.getUuid(), List.of());
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> cryptographicKeyService.getKey(SecuredUUID.fromUUID(key.getUuid())));
    }

    @Test
    void deleteKey_selectedSubsetPreservesParentAndSibling() throws ConnectorException, NotFoundException {
        // given
        CryptographicKeyItem selectedItem = createKeyItem(keyWithoutToken, KeyType.PRIVATE_KEY, KeyState.ACTIVE, true);
        List<UUID> originalItems = cryptographicKeyItemRepository
                .findByKeyUuidIn(List.of(keyWithoutToken.getUuid()))
                .stream()
                .map(CryptographicKeyItem::getUuid)
                .toList();
        UUID siblingUuid = originalItems
                .stream()
                .filter(uuid -> !uuid.equals(selectedItem.getUuid()))
                .findFirst()
                .orElseThrow();

        // when
        cryptographicKeyService.deleteKey(keyWithoutToken.getUuid(), List.of(selectedItem.getUuid().toString()));

        // then
        Assertions.assertFalse(cryptographicKeyItemRepository.existsById(selectedItem.getUuid()));
        Assertions.assertTrue(cryptographicKeyItemRepository.existsById(siblingUuid));
        Assertions.assertTrue(cryptographicKeyRepository.existsById(keyWithoutToken.getUuid()));
    }

    @Test
    void deleteKey_selectedLastItemsRemoveParentAndCertificateReferences() throws Exception {
        // given
        UUID certificateUuid = prepareBatchDeletionAssociations();
        UUID parentUuid = key.getUuid();
        List<String> selectedItems = List.of(privateKeyItem.getUuid().toString(), publicKeyItem.getUuid().toString());

        // when
        cryptographicKeyService.deleteKey(parentUuid, selectedItems);

        // then
        Assertions.assertFalse(cryptographicKeyRepository.existsById(parentUuid));
        Assertions.assertTrue(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(parentUuid)).isEmpty());
        Certificate certificate = certificateRepository.findById(certificateUuid).orElseThrow();
        Assertions.assertNull(certificate.getKeyUuid());
        Assertions.assertNull(certificate.getAltKeyUuid());
        Assertions
                .assertNull(
                        ownerAssociationRepository.findByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, parentUuid));
        Assertions.assertFalse(commentRepository.existsByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, parentUuid));
        Assertions
                .assertTrue(groupAssociationRepository
                        .findByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, parentUuid)
                        .isEmpty());
    }

    @Test
    void deleteKeyItem_deletesHistoryButPreservesParentAndSibling() throws NotFoundException {
        // given
        UUID deletedItemUuid = privateKeyItem.getUuid();
        UUID siblingUuid = publicKeyItem.getUuid();
        UUID parentUuid = key.getUuid();
        keyEventHistoryService
                .addEventHistory(KeyEvent.ENABLE, KeyEventStatus.SUCCESS, "Key enabled", null, deletedItemUuid);
        keyEventHistoryService
                .addEventHistory(KeyEvent.ENABLE, KeyEventStatus.SUCCESS, "Key enabled", null, siblingUuid);

        // when
        boolean deleted = cryptographicKeyWriter.deleteKeyItem(deletedItemUuid);

        // then
        Assertions.assertTrue(deleted);
        Assertions.assertFalse(cryptographicKeyItemRepository.existsById(deletedItemUuid));
        Assertions.assertTrue(cryptographicKeyRepository.existsById(parentUuid));
        Assertions.assertTrue(cryptographicKeyItemRepository.existsById(siblingUuid));
        var remainingHistory = cryptographicKeyEventHistoryRepository.findAll();
        Assertions.assertEquals(1, remainingHistory.size());
        Assertions.assertEquals(siblingUuid, remainingHistory.getFirst().getKeyUuid());
        Assertions
                .assertNotNull(
                        ownerAssociationRepository.findByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, parentUuid));
    }

    @Test
    void deleteKeyItem_returnsFalseWhenMissingAndPreservesExistingItems() {
        // given
        UUID missingItemUuid = UUID.randomUUID();
        long existingItemCount = cryptographicKeyItemRepository.count();

        // when
        boolean deleted = cryptographicKeyWriter.deleteKeyItem(missingItemUuid);

        // then
        Assertions.assertFalse(deleted);
        Assertions.assertEquals(existingItemCount, cryptographicKeyItemRepository.count());
    }

    @Test
    void deleteKeyWithAssociations_deletesItemsAndHistoryAndPreservesUnrelatedKey() {
        // given
        var keyModel = cryptographicKeyRepository.findBasicModelByUuid(key.getUuid()).orElseThrow();
        UUID unrelatedKeyUuid = keyWithoutToken.getUuid();
        List<UUID> deletedItemUuids = List.of(privateKeyItem.getUuid(), publicKeyItem.getUuid());
        keyEventHistoryService
                .addEventHistory(KeyEvent.ENABLE, KeyEventStatus.SUCCESS, "Key enabled", null,
                        privateKeyItem.getUuid());

        // when
        cryptographicKeyWriter.deleteKeyWithAssociations(keyModel);

        // then
        Assertions.assertFalse(cryptographicKeyRepository.existsById(keyModel.uuid()));
        Assertions.assertTrue(cryptographicKeyItemRepository.findByUuidIn(deletedItemUuids).isEmpty());
        Assertions.assertEquals(0, cryptographicKeyEventHistoryRepository.count());
        Assertions.assertTrue(cryptographicKeyRepository.existsById(unrelatedKeyUuid));
        Assertions.assertFalse(cryptographicKeyItemRepository.findByKeyUuidIn(List.of(unrelatedKeyUuid)).isEmpty());
    }

    @Test
    void deleteKeyWithAssociations_removesOwnerAndGroupLinksButPreservesGroup() throws NotFoundException {
        // given
        var keyModel = cryptographicKeyRepository.findBasicModelByUuid(key.getUuid()).orElseThrow();
        UUID groupUuid = group.getUuid();
        objectAssociationService.setGroups(Resource.CRYPTOGRAPHIC_KEY, keyModel.uuid(), Set.of(groupUuid));
        Assertions
                .assertNotNull(ownerAssociationRepository
                        .findByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, keyModel.uuid()));

        // when
        cryptographicKeyWriter.deleteKeyWithAssociations(keyModel);

        // then
        Assertions
                .assertNull(ownerAssociationRepository
                        .findByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, keyModel.uuid()));
        Assertions
                .assertTrue(groupAssociationRepository
                        .findByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, keyModel.uuid())
                        .isEmpty());
        Assertions.assertTrue(groupRepository.findByUuid(groupUuid).isPresent());
    }

    @Test
    void deleteKeyItemsWithAssociations_preservesParentWithUnselectedSibling() throws Exception {
        // given
        UUID certificateUuid = prepareBatchDeletionAssociations();
        UUID selectedItemUuid = privateKeyItem.getUuid();
        UUID remainingItemUuid = publicKeyItem.getUuid();

        // when
        int deletedCount = cryptographicKeyWriter
                .deleteKeyItemsWithAssociations(List.of(selectedItemUuid), List.of(key.getUuid()));

        // then
        Assertions.assertEquals(1, deletedCount);
        Assertions.assertFalse(cryptographicKeyItemRepository.existsById(selectedItemUuid));
        Assertions.assertTrue(cryptographicKeyItemRepository.existsById(remainingItemUuid));
        assertBatchParentAssociationsPresent(certificateUuid);
        Assertions.assertEquals(0, attributeLinkCount(selectedItemUuid));
        Assertions.assertEquals(1, attributeLinkCount(remainingItemUuid));
        var remainingHistory = cryptographicKeyEventHistoryRepository.findAll();
        Assertions.assertEquals(1, remainingHistory.size());
        Assertions.assertEquals(remainingItemUuid, remainingHistory.getFirst().getKeyUuid());
    }

    @Test
    void deleteKeyItemsWithAssociations_removesEmptyParentAndAssociations() throws Exception {
        // given
        UUID certificateUuid = prepareBatchDeletionAssociations();
        List<UUID> selectedItemUuids = List.of(privateKeyItem.getUuid(), publicKeyItem.getUuid());
        UUID deletedKeyUuid = key.getUuid();

        // when
        int deletedCount = cryptographicKeyWriter
                .deleteKeyItemsWithAssociations(selectedItemUuids, List.of(deletedKeyUuid));

        // then
        Assertions.assertEquals(selectedItemUuids.size(), deletedCount);
        Assertions.assertTrue(cryptographicKeyItemRepository.findByUuidIn(selectedItemUuids).isEmpty());
        Assertions.assertFalse(cryptographicKeyRepository.existsById(deletedKeyUuid));
        Certificate certificate = certificateRepository.findById(certificateUuid).orElseThrow();
        Assertions.assertNull(certificate.getKeyUuid());
        Assertions.assertNull(certificate.getAltKeyUuid());
        Assertions.assertEquals(0, cryptographicKeyEventHistoryRepository.count());
        for (UUID objectUuid : List.of(deletedKeyUuid, privateKeyItem.getUuid(), publicKeyItem.getUuid())) {
            Assertions.assertEquals(0, attributeLinkCount(objectUuid));
        }
        Assertions
                .assertNull(ownerAssociationRepository
                        .findByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, deletedKeyUuid));
        Assertions
                .assertTrue(groupAssociationRepository
                        .findByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, deletedKeyUuid)
                        .isEmpty());
        Assertions
                .assertFalse(
                        commentRepository.existsByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, deletedKeyUuid));
        Assertions.assertTrue(groupRepository.findByUuid(group.getUuid()).isPresent());
        Assertions.assertTrue(cryptographicKeyRepository.existsById(keyWithoutToken.getUuid()));
        Assertions
                .assertFalse(
                        cryptographicKeyItemRepository.findByKeyUuidIn(List.of(keyWithoutToken.getUuid())).isEmpty());
    }

    @Test
    void deleteKeyItemsWithAssociations_waitsForSiblingDeletionAndRemovesEmptyParent() throws Exception {
        // given
        UUID certificateUuid = prepareBatchDeletionAssociations();
        UUID parentUuid = key.getUuid();
        UUID firstItemUuid = privateKeyItem.getUuid();
        UUID finalItemUuid = publicKeyItem.getUuid();
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);
        try (ExecutorService contender = Executors.newSingleThreadExecutor()) {
            // when
            Future<Integer> outcome = transaction.execute(status -> {
                Assertions
                        .assertEquals(1, cryptographicKeyWriter
                                .deleteKeyItemsWithAssociations(List.of(firstItemUuid), List.of(parentUuid)));
                int lockHolderPid = jdbcTemplate.queryForObject("SELECT pg_backend_pid()", Integer.class);
                Future<Integer> waitingWriter = contender
                        .submit(() -> cryptographicKeyWriter
                                .deleteKeyItemsWithAssociations(List.of(finalItemUuid), List.of(parentUuid)));
                Awaitility
                        .await()
                        .atMost(Duration.ofSeconds(10))
                        .until(() -> jdbcTemplate
                                .queryForObject(
                                        "SELECT count(*) FROM pg_stat_activity WHERE ? = ANY(pg_blocking_pids(pid))",
                                        Long.class, lockHolderPid) > 0);
                return waitingWriter;
            });

            // then
            Assertions.assertEquals(1, outcome.get(10, TimeUnit.SECONDS));
            Assertions.assertFalse(cryptographicKeyRepository.existsById(parentUuid));
            Assertions
                    .assertTrue(cryptographicKeyItemRepository
                            .findByUuidIn(List.of(firstItemUuid, finalItemUuid))
                            .isEmpty());
            Certificate certificate = certificateRepository.findById(certificateUuid).orElseThrow();
            Assertions.assertNull(certificate.getKeyUuid());
            Assertions.assertNull(certificate.getAltKeyUuid());
            Assertions
                    .assertNull(ownerAssociationRepository
                            .findByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, parentUuid));
            Assertions
                    .assertTrue(groupAssociationRepository
                            .findByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, parentUuid)
                            .isEmpty());
            Assertions
                    .assertFalse(
                            commentRepository.existsByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, parentUuid));
            Assertions.assertEquals(0, attributeLinkCount(parentUuid));
        }
    }

    @Test
    void deleteKeyItemsWithAssociations_rollsBackAllCleanupWhenParentDeletionFails() throws Exception {
        // given
        UUID certificateUuid = prepareBatchDeletionAssociations();
        List<UUID> selectedItemUuids = List.of(privateKeyItem.getUuid(), publicKeyItem.getUuid());
        String guardTable = dbSchema + ".batch_key_delete_guard";
        String constraintName = "retain_batch_key";
        jdbcTemplate
                .execute("CREATE TABLE %s (key_uuid UUID CONSTRAINT %s REFERENCES %s.cryptographic_key(uuid))"
                        .formatted(guardTable, constraintName, dbSchema));
        try {
            jdbcTemplate.update("INSERT INTO " + guardTable + " (key_uuid) VALUES (?)", key.getUuid());

            // when
            Executable delete = () -> cryptographicKeyWriter
                    .deleteKeyItemsWithAssociations(selectedItemUuids, List.of(key.getUuid()));

            // then
            DataIntegrityViolationException failure = Assertions
                    .assertThrows(DataIntegrityViolationException.class, delete);
            Assertions.assertTrue(failure.getMostSpecificCause().getMessage().contains(constraintName));
            Assertions
                    .assertEquals(selectedItemUuids.size(),
                            cryptographicKeyItemRepository.findByUuidIn(selectedItemUuids).size());
            Assertions.assertEquals(selectedItemUuids.size(), cryptographicKeyEventHistoryRepository.count());
            for (UUID itemUuid : selectedItemUuids) {
                Assertions.assertEquals(1, attributeLinkCount(itemUuid));
            }
            assertBatchParentAssociationsPresent(certificateUuid);
        } finally {
            jdbcTemplate.execute("DROP TABLE " + guardTable);
        }
    }

    private UUID prepareBatchDeletionAssociations() throws Exception {
        UUID keyUuid = key.getUuid();
        objectAssociationService.setGroups(Resource.CRYPTOGRAPHIC_KEY, keyUuid, Set.of(group.getUuid()));
        Certificate certificate = aCertificate().withKeyUuid(keyUuid).withAltKeyUuid(keyUuid).build();
        certificate = certificateRepository.saveAndFlush(certificate);
        Comment comment = new Comment();
        comment.setResource(Resource.CRYPTOGRAPHIC_KEY);
        comment.setObjectUuid(keyUuid);
        comment.setAuthorUuid(UUID.randomUUID());
        comment.setAuthorUsername("key-operator");
        comment.setBody("Keep the key association history");
        commentWriter.create(comment);
        for (UUID itemUuid : List.of(privateKeyItem.getUuid(), publicKeyItem.getUuid())) {
            keyEventHistoryService
                    .addEventHistory(KeyEvent.ENABLE, KeyEventStatus.SUCCESS, "Key enabled", null, itemUuid);
            addDeletionMetadata(itemUuid);
        }
        addDeletionMetadata(keyUuid);
        return certificate.getUuid();
    }

    private void addDeletionMetadata(UUID objectUuid) throws AttributeException {
        MetadataAttributeV3 metadata = new MetadataAttributeV3();
        metadata.setUuid(UUID.randomUUID().toString());
        metadata.setName("deletion-metadata-" + objectUuid);
        metadata.setType(AttributeType.META);
        metadata.setContentType(AttributeContentType.STRING);
        MetadataAttributeProperties properties = new MetadataAttributeProperties();
        properties.setLabel("Deletion metadata");
        properties.setVisible(true);
        metadata.setProperties(properties);
        metadata.setContent(List.of(new StringAttributeContentV3("retained until deletion commits")));
        ObjectAttributeContentInfo contentInfo = ObjectAttributeContentInfo
                .builder(Resource.CRYPTOGRAPHIC_KEY, objectUuid)
                .connector(connector.getUuid())
                .build();
        attributeEngine.updateMetadataAttribute(metadata, contentInfo);
    }

    private void assertBatchParentAssociationsPresent(UUID certificateUuid) {
        UUID keyUuid = key.getUuid();
        Assertions.assertTrue(cryptographicKeyRepository.existsById(keyUuid));
        Certificate certificate = certificateRepository.findById(certificateUuid).orElseThrow();
        Assertions.assertEquals(keyUuid, certificate.getKeyUuid());
        Assertions.assertEquals(keyUuid, certificate.getAltKeyUuid());
        Assertions
                .assertNotNull(
                        ownerAssociationRepository.findByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, keyUuid));
        var groups = groupAssociationRepository.findByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, keyUuid);
        Assertions.assertEquals(1, groups.size());
        Assertions.assertEquals(group.getUuid(), groups.getFirst().getGroupUuid());
        Assertions.assertTrue(commentRepository.existsByResourceAndObjectUuid(Resource.CRYPTOGRAPHIC_KEY, keyUuid));
        Assertions.assertEquals(1, attributeLinkCount(keyUuid));
    }

    private int attributeLinkCount(UUID objectUuid) {
        return jdbcTemplate
                .queryForObject(
                        "SELECT COUNT(*) FROM " + dbSchema
                                + ".attribute_content_2_object WHERE object_type = ? AND object_uuid = ?",
                        Integer.class, Resource.CRYPTOGRAPHIC_KEY.name(), objectUuid);
    }

    @Test
    void testEnableDisableKey() throws NotFoundException {
        cryptographicKeyService.disableKey(key.getUuid(), List.of());

        KeyDetailDto keyDetailDto = cryptographicKeyService.getKey(SecuredUUID.fromUUID(key.getUuid()));
        Assertions.assertEquals(2, keyDetailDto.getItems().size());
        for (KeyItemDetailDto keyItemDto : keyDetailDto.getItems()) {
            Assertions.assertFalse(keyItemDto.isEnabled());
        }

        cryptographicKeyService.enableKey(key.getUuid(), List.of(privateKeyItem.getUuid().toString()));
        keyDetailDto = cryptographicKeyService.getKey(SecuredUUID.fromUUID(key.getUuid()));
        for (KeyItemDetailDto keyItemDto : keyDetailDto.getItems()) {
            if (keyItemDto.getUuid().equals(privateKeyItem.getUuid().toString())) {
                Assertions.assertTrue(keyItemDto.isEnabled());
            } else {
                Assertions.assertFalse(keyItemDto.isEnabled());
            }
        }

        cryptographicKeyService.disableKeyItems(List.of(privateKeyItem.getUuid().toString()));
        cryptographicKeyService.enableKey(List.of(key.getUuid().toString()));
        keyDetailDto = cryptographicKeyService.getKey(SecuredUUID.fromUUID(key.getUuid()));
        Assertions.assertEquals(2, keyDetailDto.getItems().size());
        for (KeyItemDetailDto keyItemDto : keyDetailDto.getItems()) {
            Assertions.assertTrue(keyItemDto.isEnabled());
        }
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void setKeyItemEnabled_returnsTrueAndPersistsChangedState(boolean enabled) {
        // given
        UUID itemUuid = privateKeyItem.getUuid();
        cryptographicKeyWriter.setKeyItemEnabled(itemUuid, !enabled);

        // when
        boolean changed = cryptographicKeyWriter.setKeyItemEnabled(itemUuid, enabled);

        // then
        Assertions.assertTrue(changed);
        CryptographicKeyItem storedItem = cryptographicKeyItemRepository.findByUuid(itemUuid).orElseThrow();
        Assertions.assertEquals(enabled, storedItem.isEnabled());
        Assertions.assertEquals(privateKeyItem.getKeyData(), storedItem.getKeyData());
    }

    @ParameterizedTest
    @CsvSource({
            "PRE_ACTIVE, DESTROYED",
            "ACTIVE, DESTROYED",
            "DEACTIVATED, DESTROYED",
            "COMPROMISED, DESTROYED_COMPROMISED",
            "DESTROYED, DESTROYED",
            "DESTROYED_COMPROMISED, DESTROYED_COMPROMISED"})
    void finalizeKeyItemDestruction_derivesFinalStateFromStoredState(KeyState entryState, KeyState expectedState)
            throws NotFoundException {
        // given
        UUID itemUuid = privateKeyItem.getUuid();
        LocalDateTime previousUpdate = LocalDateTime.of(2020, Month.JANUARY, 1, 0, 0);
        jdbcTemplate
                .update("UPDATE " + dbSchema + ".cryptographic_key_item SET state = ?, updated_at = ? WHERE uuid = ?",
                        entryState.name(), previousUpdate, itemUuid);

        // when
        cryptographicKeyWriter.finalizeKeyItemDestruction(itemUuid);

        // then
        CryptographicKeyItem storedItem = cryptographicKeyItemRepository.findByUuid(itemUuid).orElseThrow();
        Assertions.assertNull(storedItem.getKeyData());
        Assertions.assertEquals(expectedState, storedItem.getState());
        Assertions.assertTrue(storedItem.getUpdatedAt().isAfter(previousUpdate));
        Assertions.assertEquals(privateKeyItem.getKeyUuid(), storedItem.getKeyUuid());
        CryptographicKeyItem otherItem = cryptographicKeyItemRepository
                .findByUuid(publicKeyItem.getUuid())
                .orElseThrow();
        Assertions.assertEquals(publicKeyItem.getKeyData(), otherItem.getKeyData());
        Assertions.assertEquals(publicKeyItem.getState(), otherItem.getState());
    }

    @Test
    void finalizeKeyItemDestruction_throwsNotFoundException_whenItemDoesNotExist() {
        // given
        UUID missingItemUuid = UUID.randomUUID();

        // when
        Executable finalizeDestruction = () -> cryptographicKeyWriter.finalizeKeyItemDestruction(missingItemUuid);

        // then
        Assertions.assertThrows(NotFoundException.class, finalizeDestruction);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void setKeyItemEnabled_returnsFalseAndPreservesTimestamp_whenAlreadyInRequestedState(boolean enabled) {
        // given
        UUID itemUuid = privateKeyItem.getUuid();
        cryptographicKeyWriter.setKeyItemEnabled(itemUuid, enabled);
        var previousUpdate = cryptographicKeyItemRepository.findByUuid(itemUuid).orElseThrow().getUpdatedAt();

        // when
        boolean changed = cryptographicKeyWriter.setKeyItemEnabled(itemUuid, enabled);

        // then
        Assertions.assertFalse(changed);
        CryptographicKeyItem storedItem = cryptographicKeyItemRepository.findByUuid(itemUuid).orElseThrow();
        Assertions.assertEquals(enabled, storedItem.isEnabled());
        Assertions.assertEquals(previousUpdate, storedItem.getUpdatedAt());
    }

    @Test
    void setKeyItemEnabled_returnsFalse_whenItemDoesNotExist() {
        // given
        UUID missingItemUuid = UUID.randomUUID();
        boolean enabled = false;

        // when
        boolean changed = cryptographicKeyWriter.setKeyItemEnabled(missingItemUuid, enabled);

        // then
        Assertions.assertFalse(changed);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void setKeyItemsEnabled_doesNotRecordHistory_whenAlreadyInRequestedState(boolean enabled) throws NotFoundException {
        // given
        UUID itemUuid = privateKeyItem.getUuid();
        cryptographicKeyWriter.setKeyItemEnabled(itemUuid, enabled);
        List<String> itemUuids = List.of(itemUuid.toString());
        long historyCount = cryptographicKeyEventHistoryRepository.count();

        // when
        if (enabled) {
            cryptographicKeyService.enableKeyItems(itemUuids);
        } else {
            cryptographicKeyService.disableKeyItems(itemUuids);
        }

        // then
        Assertions.assertEquals(historyCount, cryptographicKeyEventHistoryRepository.count());
    }

    @Test
    void testKeyWithoutTokenOperations() throws ConnectorException, AttributeException, NotFoundException {
        KeyDetailDto keyDetailDto = cryptographicKeyService.getKey(keyWithoutToken.getSecuredUuid());
        Assertions.assertEquals(1, keyDetailDto.getItems().size());

        String keyItemUuid = keyDetailDto.getItems().getFirst().getUuid();
        cryptographicKeyService.getKeyItem(keyWithoutToken.getSecuredUuid(), keyItemUuid);

        // try different operations if null token and profile is handled
        cryptographicKeyService.editKey(keyWithoutToken.getSecuredUuid(), new EditKeyRequestDto());
        cryptographicKeyService.disableKey(keyWithoutToken.getUuid(), List.of(keyItemUuid));
        cryptographicKeyService.enableKey(keyWithoutToken.getUuid(), null);

        CompromiseKeyRequestDto compromiseKeyRequestDto = new CompromiseKeyRequestDto();
        compromiseKeyRequestDto.setReason(KeyCompromiseReason.UNAUTHORIZED_MODIFICATION);
        cryptographicKeyService.compromiseKey(keyWithoutToken.getUuid(), compromiseKeyRequestDto);
        KeyItemDetailDto keyItemDetailDto = cryptographicKeyService
                .getKeyItem(keyWithoutToken.getSecuredUuid(), keyItemUuid);
        Assertions.assertEquals(KeyState.COMPROMISED, keyItemDetailDto.getState());
        Assertions.assertEquals(KeyCompromiseReason.UNAUTHORIZED_MODIFICATION, keyItemDetailDto.getReason());

        cryptographicKeyService.destroyKey(keyWithoutToken.getUuid(), null);
        keyItemDetailDto = cryptographicKeyService.getKeyItem(keyWithoutToken.getSecuredUuid(), keyItemUuid);
        Assertions.assertEquals(KeyState.DESTROYED_COMPROMISED, keyItemDetailDto.getState());

        cryptographicKeyService.deleteKey(keyWithoutToken.getUuid(), List.of(keyItemUuid));
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> cryptographicKeyService.getKeyItem(keyWithoutToken.getSecuredUuid(), keyItemUuid));
    }

    @Test
    void testDeleteKeyItems() throws ConnectorException {
        // Prepare 3 keys with different scenarios

        // 1. Key with multiple items. One key item will be deleted, one key item should remain.
        // This key is prepared in `setUp`.

        // 2. Key with one item. The key item will be deleted, and the whole key should be deleted as well.
        CryptographicKey keyToDelete = createKey("keyToDelete", tokenProfile, tokenInstanceReference);
        CryptographicKeyItem itemToDelete = createKeyItem(keyToDelete, KeyType.SECRET_KEY, KeyState.ACTIVE, true);
        keyToDelete.setItems(Set.of(itemToDelete));
        cryptographicKeyRepository.saveAndFlush(keyToDelete);

        // 3. Key without token instance reference
        CryptographicKey keyNoToken = createKey("keyNoToken", null, null);
        CryptographicKeyItem itemNoToken = createKeyItem(keyNoToken, KeyType.SECRET_KEY, KeyState.ACTIVE, true);
        keyNoToken.setItems(Set.of(itemNoToken));
        cryptographicKeyRepository.saveAndFlush(keyNoToken);

        mockConnectorDeleteKey();

        // UUIDs to delete: publicKeyItem.uuid (from 'key'), itemToDelete.uuid, itemNoToken.uuid, and a random one
        List<String> uuidsToDelete = new ArrayList<>();
        UUID nonExistingUuid = UUID.randomUUID();
        uuidsToDelete.add(publicKeyItem.getUuid().toString());
        uuidsToDelete.add(itemToDelete.getUuid().toString());
        uuidsToDelete.add(itemNoToken.getUuid().toString());
        uuidsToDelete.add(nonExistingUuid.toString());

        // Perform deletion
        cryptographicKeyService.deleteKeyItems(SecurityFilter.create(), uuidsToDelete);

        // Assertions
        // 1. 'key' should still exist but only with privateKeyItem
        Assertions.assertTrue(cryptographicKeyRepository.findById(key.getUuid()).isPresent());
        List<CryptographicKeyItem> remainingItems = cryptographicKeyItemRepository
                .findByKeyUuidIn(List.of(key.getUuid()));
        Assertions.assertEquals(1, remainingItems.size());
        Assertions.assertEquals(privateKeyItem.getUuid(), remainingItems.getFirst().getUuid());

        // 2. 'keyToDelete' should be deleted because its only item was deleted
        Assertions.assertTrue(cryptographicKeyRepository.findById(keyToDelete.getUuid()).isEmpty());
        Assertions.assertTrue(cryptographicKeyItemRepository.findById(itemToDelete.getUuid()).isEmpty());

        // 3. 'keyNoToken' should be deleted, and it should have worked even without token
        Assertions.assertTrue(cryptographicKeyRepository.findById(keyNoToken.getUuid()).isEmpty());
        Assertions.assertTrue(cryptographicKeyItemRepository.findById(itemNoToken.getUuid()).isEmpty());

        verify(notificationProducer, times(1))
                .produceInternalNotificationMessage(eq(Resource.CRYPTOGRAPHIC_KEY_ITEM), eq(nonExistingUuid), any(),
                        contains("Unable to delete cryptographic key item"), anyString());
    }

    @Test
    void testDeleteKeyItems_bulk() throws ConnectorException {
        // Prepare 100 key items for deletion. Two batches will be processed based on bulkDeleteBatchSize (50 in test)
        List<UUID> uuidsToDelete = new ArrayList<>();
        List<UUID> keyUuids = new ArrayList<>();

        for (int i = 0; i < 100; i++) {
            CryptographicKey createdKey = createKey("bulkKey" + i, tokenProfile, tokenInstanceReference);
            CryptographicKeyItem item = createKeyItem(createdKey, KeyType.SECRET_KEY, KeyState.ACTIVE, true);
            createdKey.setItems(Set.of(item));
            cryptographicKeyRepository.saveAndFlush(createdKey);
            uuidsToDelete.add(item.getUuid());
            keyUuids.add(createdKey.getUuid());
        }

        mockConnectorDeleteKey();

        // Perform deletion
        cryptographicKeyService
                .deleteKeyItems(SecurityFilter.create(), uuidsToDelete.stream().map(UUID::toString).toList());

        // Assertions
        Assertions.assertTrue(cryptographicKeyItemRepository.findByUuidIn(uuidsToDelete).isEmpty());
        Assertions.assertTrue(cryptographicKeyRepository.findByUuidIn(keyUuids).isEmpty());
    }

    @Test
    void testDeleteKeyItems_evaluatePermissionsWithNoParent() throws ConnectorException {
        UUID forbiddenKeyUuid = UUID.fromString("ed337973-ad11-441f-91c7-6112309e8776");
        CryptographicKey forbiddenKey = createKey("forbiddenKey", tokenProfile, tokenInstanceReference);
        forbiddenKey.setUuid(forbiddenKeyUuid);
        cryptographicKeyRepository.saveAndFlush(forbiddenKey);

        UUID forbiddenKeyItemUuid = UUID.fromString("7374a824-b163-49e1-a7e7-8be48d24ed52");
        CryptographicKeyItem forbiddenKeyItem = createKeyItem(forbiddenKey, KeyType.SECRET_KEY, KeyState.ACTIVE, true);
        forbiddenKeyItem.setUuid(forbiddenKeyItemUuid);
        forbiddenKeyItem = cryptographicKeyItemRepository.saveAndFlush(forbiddenKeyItem);
        forbiddenKey.setItems(Set.of(forbiddenKeyItem));
        cryptographicKeyRepository.saveAndFlush(forbiddenKey);

        mockConnectorDeleteKey();

        // Reject key item deletion for the forbidden key.
        mockOpaAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.DELETE, List.of(key.getUuid().toString()),
                List.of(forbiddenKeyUuid.toString()));

        // Should not throw exception, but log error for the forbidden UUID
        cryptographicKeyService
                .deleteKeyItems(SecurityFilter.create(),
                        List.of(publicKeyItem.getUuid().toString(), forbiddenKeyItem.getUuid().toString()));

        Assertions
                .assertThrows(NotFoundException.class, () -> cryptographicKeyService
                        .getKeyItem(key.getSecuredUuid(), publicKeyItem.getUuid().toString()));
        Assertions
                .assertDoesNotThrow(() -> cryptographicKeyService
                        .getKeyItem(SecuredUUID.fromUUID(forbiddenKeyUuid), forbiddenKeyItemUuid.toString()));
    }

    @Test
    void testDeleteKeyItems_evaluatePermissionsWithTokenInstanceParent() throws ConnectorException {
        // Reject key item deletion for the parent token instance.
        mockOpaAccess(Resource.TOKEN, ResourceAction.MEMBERS, List.of(),
                List.of(tokenInstanceReference.getUuid().toString()));

        mockConnectorDeleteKey();

        // Should not throw exception, but log error for the forbidden UUID
        cryptographicKeyService.deleteKeyItems(SecurityFilter.create(), List.of(privateKeyItem.getUuid().toString()));

        Assertions
                .assertDoesNotThrow(() -> cryptographicKeyService
                        .getKeyItem(key.getSecuredUuid(), privateKeyItem.getUuid().toString()));
    }

    @Test
    void testDeleteKeyItems_evaluatePermissionsWithTokenProfileParent() throws ConnectorException {
        // Reject key item deletion for the parent token profile.
        mockOpaAccess(Resource.TOKEN_PROFILE, ResourceAction.MEMBERS, List.of(),
                List.of(tokenProfile.getUuid().toString()));

        mockConnectorDeleteKey();

        // Should not throw exception, but log error for the forbidden UUID
        cryptographicKeyService.deleteKeyItems(SecurityFilter.create(), List.of(privateKeyItem.getUuid().toString()));

        Assertions
                .assertDoesNotThrow(() -> cryptographicKeyService
                        .getKeyItem(key.getSecuredUuid(), privateKeyItem.getUuid().toString()));
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = cryptographicKeyInternalService.getResourceObjectInternal(key.getUuid());
        Assertions.assertEquals(key.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(key.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = cryptographicKeyInternalService.getResourceObjectExternal(key.getSecuredUuid());
        Assertions.assertEquals(key.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(key.getName(), nameAndUuidDto.getName());
    }

    @Test
    void getSearchableFieldInformation_deniesWhenUnauthorized() {
        // given - the caller is denied the CRYPTOGRAPHIC_KEY LIST resource action
        denyResourceAccess(Resource.CRYPTOGRAPHIC_KEY, ResourceAction.LIST);

        // when / then - @ExternalAuthorization rejects before the method body runs
        Assertions
                .assertThrows(AccessDeniedException.class,
                        () -> cryptographicKeyService.getSearchableFieldInformation());
    }

    private void mockConnectorDeleteKey() {
        mockServer
                .stubFor(WireMock
                        .delete(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+"))
                        .willReturn(WireMock.ok()));
    }

    @Test
    void disableKeyExport_withdrawsThePermissionAndReportsItBack() throws NotFoundException {
        // given
        CryptographicKeyItem exportable = createExportableKeyItem();

        // when
        KeyItemDetailDto afterwards = cryptographicKeyService
                .disableKeyExport(key.getSecuredUuid(), exportable.getUuid().toString());

        // then
        Assertions.assertFalse(afterwards.isExportable(), "the answer must not be read from a pre-update copy");
        CryptographicKeyItem stored = cryptographicKeyItemRepository.findByUuid(exportable.getUuid()).orElseThrow();
        Assertions.assertFalse(stored.isExportable());
        List<CryptographicKeyEventHistory> events = exportDisabledEvents(stored);
        Assertions.assertEquals(1, events.size());
        Assertions.assertEquals(KeyEventStatus.SUCCESS, events.getFirst().getStatus());
    }

    @Test
    void disableKeyExport_doesNotRequireTokenUpdateAccess() throws NotFoundException {
        // given
        CryptographicKeyItem exportable = createExportableKeyItem();
        denyResourceAccess(Resource.TOKEN, ResourceAction.UPDATE);

        // when
        KeyItemDetailDto afterwards = cryptographicKeyService
                .disableKeyExport(key.getSecuredUuid(), exportable.getUuid().toString());

        // then
        Assertions.assertFalse(afterwards.isExportable());
    }

    @Test
    void getKey_reportsTheExportPermissionOnItsItems() throws NotFoundException {
        // given
        CryptographicKeyItem exportable = createExportableKeyItem();

        // when
        KeyDetailDto detail = cryptographicKeyService.getKey(key.getSecuredUuid());

        // then
        Assertions
                .assertTrue(detail
                        .getItems()
                        .stream()
                        .filter(item -> item.getUuid().equals(exportable.getUuid().toString()))
                        .findFirst()
                        .orElseThrow()
                        .isExportable());
    }

    @Test
    void disableKeyExport_isAnsweredForAKeyThatCouldNotBeExportedAnyway() throws NotFoundException {
        // given
        Assertions.assertFalse(privateKeyItem.isExportable());

        // when
        KeyItemDetailDto afterwards = cryptographicKeyService
                .disableKeyExport(key.getSecuredUuid(), privateKeyItem.getUuid().toString());

        // then
        Assertions.assertFalse(afterwards.isExportable());
        Assertions.assertTrue(exportDisabledEvents(privateKeyItem).isEmpty());
    }

    /** The compliance pass saves key items it loaded earlier, so a copy taken before the withdrawal is realistic. */
    @Test
    void disableKeyExport_isNotUndoneByAStaleCopySavedElsewhere() throws NotFoundException {
        // given
        CryptographicKeyItem exportable = createExportableKeyItem();
        CryptographicKeyItem loadedBeforeWithdrawal = cryptographicKeyItemRepository
                .findByUuid(exportable.getUuid())
                .orElseThrow();
        cryptographicKeyService.disableKeyExport(key.getSecuredUuid(), exportable.getUuid().toString());

        // when the holder of that copy writes it back for an unrelated reason
        loadedBeforeWithdrawal.setComplianceStatus(ComplianceStatus.OK);
        cryptographicKeyItemRepository.saveAndFlush(loadedBeforeWithdrawal);

        // then
        Assertions
                .assertFalse(
                        cryptographicKeyItemRepository.findByUuid(exportable.getUuid()).orElseThrow().isExportable(),
                        "a stale copy must not restore the export permission");
    }

    @Test
    void disableKeyExport_rejectsAKeyItemOfAnotherKey() {
        // given
        String itemOfAnotherKey = privateKeyItem.getUuid().toString();
        SecuredUUID otherKey = createKey("unrelated key", tokenProfile, tokenInstanceReference).getSecuredUuid();

        // when
        Executable disable = () -> cryptographicKeyService.disableKeyExport(otherKey, itemOfAnotherKey);

        // then
        Assertions.assertThrows(NotFoundException.class, disable);
    }

    private CryptographicKey createKey(String name, TokenProfile tokenProfile,
            TokenInstanceReference tokenInstanceReference) {
        CryptographicKey newKey = new CryptographicKey();
        newKey.setName(name);
        newKey.setTokenProfile(tokenProfile);
        newKey.setTokenInstanceReference(tokenInstanceReference);
        return cryptographicKeyRepository.saveAndFlush(newKey);
    }

    private void createKeyItemWithReference(CryptographicKey key, UUID remoteReference) {
        CryptographicKeyItem item = createKeyItem(key, KeyType.PUBLIC_KEY, KeyState.ACTIVE, true);
        item.setKeyReferenceUuid(remoteReference);
        cryptographicKeyItemRepository.saveAndFlush(item);
    }

    /**
     * Inserts a key item that already carries the export permission. The column is not updatable, so the permission
     * cannot be added to a row that already exists — production sets it the same way, when the key is created.
     */
    private CryptographicKeyItem createExportableKeyItem() {
        CryptographicKeyItem item = new CryptographicKeyItem();
        item.setKey(key);
        item.setKeyUuid(key.getUuid());
        item.setType(KeyType.PRIVATE_KEY);
        item.setState(KeyState.ACTIVE);
        item.setEnabled(true);
        item.setExportable(true);
        return cryptographicKeyItemRepository.saveAndFlush(item);
    }

    private boolean storedExportable(KeyItemDetailDto item) {
        return cryptographicKeyItemRepository.findByUuid(UUID.fromString(item.getUuid())).orElseThrow().isExportable();
    }

    private List<CryptographicKeyEventHistory> exportDisabledEvents(CryptographicKeyItem item) {
        return cryptographicKeyEventHistoryRepository
                .findByKeyOrderByCreatedDesc(item)
                .stream()
                .filter(event -> event.getEvent() == KeyEvent.EXPORT_DISABLED)
                .toList();
    }

    private CryptographicKeyItem createKeyItem(CryptographicKey key, KeyType type, KeyState state, boolean enabled) {
        CryptographicKeyItem item = new CryptographicKeyItem();
        item.setKey(key);
        item.setKeyUuid(key.getUuid());
        item.setType(type);
        item.setState(state);
        item.setEnabled(enabled);
        item = cryptographicKeyItemRepository.saveAndFlush(item);
        item.setKeyReferenceUuid(item.getUuid());
        return cryptographicKeyItemRepository.saveAndFlush(item);
    }

    private void mockOpaAccess(Resource resource, ResourceAction action, List<String> allowed, List<String> forbidden) {
        OpaObjectAccessResult objectAccessResult = new OpaObjectAccessResult();
        objectAccessResult.setAllowedObjects(allowed);
        objectAccessResult.setForbiddenObjects(forbidden);
        when(opaClient
                .checkObjectAccess(any(),
                        argThat(requestedResource -> isObjectAccessRequestForResource(requestedResource,
                                resource.getCode(), action.getCode())),
                        any(), any()))
                .thenReturn(objectAccessResult);
    }

    private static boolean isObjectAccessRequestForResource(OpaRequestedResource resource, String name, String action) {
        return resource != null && resource.getProperties() != null
                && (resource.getProperties().containsKey("name") && resource.getProperties().get("name").equals(name))
                && (resource.getProperties().containsKey("action")
                        && resource.getProperties().get("action").equals(action));
    }

    /**
     * The second upload stands in for the losing side of a concurrent race: {@code uploadCertificatePublicKey} carries
     * no fingerprint pre-check of its own — that guard lives in its callers — so the second call always reaches the
     * conflict-resolving insert and takes the adopt path. A two-thread version would deadlock, the holder of the open
     * transaction waiting on a thread blocked inside its own insert.
     */
    @Test
    void uploadingTheSameKeyTwiceConvergesOnOneKeyAndLeavesNoOrphan() throws NoSuchAlgorithmException {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        PublicKey publicKey = generator.generateKeyPair().getPublic();
        int keyLength = KeySizeUtil.getKeyLength(publicKey);
        String fingerprint = CertificateUtil
                .getThumbprint(
                        Base64.getEncoder().encodeToString(publicKey.getEncoded()).getBytes(StandardCharsets.UTF_8));

        UUID firstKeyUuid = cryptographicKeyInternalService
                .uploadCertificatePublicKey("certKey_first", publicKey, keyLength, fingerprint);
        long keysAfterFirstUpload = cryptographicKeyRepository.count();
        UUID secondKeyUuid = cryptographicKeyInternalService
                .uploadCertificatePublicKey("certKey_second", publicKey, keyLength, fingerprint);

        Assertions.assertNotNull(firstKeyUuid);
        Assertions
                .assertEquals(firstKeyUuid, secondKeyUuid,
                        "the second caller must adopt the surviving key, not the parent it created itself");
        Assertions
                .assertEquals(firstKeyUuid,
                        cryptographicKeyItemRepository.findByFingerprint(fingerprint).orElseThrow().getKey().getUuid(),
                        "the surviving key item must belong to the adopted key");
        Assertions
                .assertEquals(keysAfterFirstUpload, cryptographicKeyRepository.count(),
                        "the discarded key must not be left behind");
    }

    @Test
    void uploadCertificatePublicKey_rollsBackParentAndItemWithCaller() throws NoSuchAlgorithmException {
        // given
        PublicKey publicKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPublic();
        int keyLength = KeySizeUtil.getKeyLength(publicKey);
        String fingerprint = CertificateUtil.getThumbprint(publicKey.getEncoded());
        long originalParentCount = cryptographicKeyRepository.count();
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);

        // when
        UUID importedParent = transaction.execute(status -> {
            UUID result = cryptographicKeyInternalService
                    .uploadCertificatePublicKey("rolled-back-certificate-key", publicKey, keyLength, fingerprint);
            Assertions.assertTrue(cryptographicKeyItemRepository.findByFingerprint(fingerprint).isPresent());
            status.setRollbackOnly();
            return result;
        });

        // then
        Assertions.assertFalse(cryptographicKeyRepository.existsById(importedParent));
        Assertions.assertTrue(cryptographicKeyItemRepository.findByFingerprint(fingerprint).isEmpty());
        Assertions.assertEquals(originalParentCount, cryptographicKeyRepository.count());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void updateAssociations_refreshesAlreadyInitializedGroups(boolean updateOwnerAndGroups) {
        // given
        UUID parentUuid = keyWithoutToken.getUuid();
        Set<UUID> requestedGroups = Set.of(group.getUuid());
        TransactionTemplate transaction = new TransactionTemplate(transactionManager);

        // when
        CryptographicKeyFullModel updated = transaction.execute(status -> {
            var initial = cryptographicKeyRepository.findFullModelByUuid(parentUuid).orElseThrow();
            Assertions.assertTrue(initial.groups().isEmpty());
            try {
                if (updateOwnerAndGroups) {
                    return cryptographicKeyWriter.updateOwnerAndGroups(initial, requestedGroups);
                }
                EditKeyRequestDto request = new EditKeyRequestDto();
                request.setGroupUuids(requestedGroups.stream().map(UUID::toString).toList());
                return cryptographicKeyWriter.update(parentUuid, request, null, null);
            } catch (Exception e) {
                throw new AssertionError("Updating existing key associations failed", e);
            }
        });

        // then
        Assertions
                .assertEquals(requestedGroups,
                        updated.groups().stream().map(GroupModel::uuid).collect(Collectors.toSet()));
        Assertions
                .assertEquals(requestedGroups,
                        cryptographicKeyRepository
                                .findFullModelByUuid(parentUuid)
                                .orElseThrow()
                                .groups()
                                .stream()
                                .map(GroupModel::uuid)
                                .collect(Collectors.toSet()));
    }

}
