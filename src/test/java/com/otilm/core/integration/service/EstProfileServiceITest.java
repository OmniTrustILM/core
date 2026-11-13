package com.otilm.core.integration.service;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.est.EstProfileEditRequestDto;
import com.otilm.api.model.client.est.EstProfileRequestDto;
import com.otilm.api.model.common.BulkActionMessageDto;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.AttributeVersion;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.CustomAttributeProperties;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.CustomAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.secrets.SecretType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateSubjectType;
import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.est.EstProfileDetailDto;
import com.otilm.api.model.core.est.EstProfileDto;
import com.otilm.api.model.core.protocol.ProtocolCertificateAssociationsRequestDto;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RaProfileProtocolAttribute;
import com.otilm.core.dao.entity.Secret;
import com.otilm.core.dao.entity.SecretVersion;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.entity.VaultInstance;
import com.otilm.core.dao.entity.VaultProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.ProtocolCertificateAssociationsRepository;
import com.otilm.core.dao.repository.RaProfileProtocolAttributeRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.SecretRepository;
import com.otilm.core.dao.repository.SecretVersionRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.dao.repository.VaultInstanceRepository;
import com.otilm.core.dao.repository.VaultProfileRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.service.EstProfileExternalService;
import com.otilm.core.service.EstProfileInternalService;
import com.otilm.core.service.impl.EstProfileServiceImpl;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.LoopbackWireMock;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.builders.EstProfileRequestDtoBuilder;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import com.otilm.core.util.seeders.TokenProfileSeeder;
import jakarta.persistence.EntityManager;
import java.time.Duration;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.awaitility.Awaitility;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.transaction.support.TransactionTemplate;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static com.otilm.core.util.builders.EstProfileRequestDtoBuilder.anEstProfileRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

class EstProfileServiceITest extends BaseSpringBootTest {

    private static final String ORIGIN = "https://ilm.example.com";
    private static final String SYSTEM_DEFAULT_CLASH = "Another EST Profile became the system default at the same time; repeat the request";
    private static final String CREDENTIALS_CHANGED = "The basic credentials of the EST Profile changed at the same time; repeat the request";
    private static final UUID KEY_ATTRIBUTE_UUID = UUID.fromString("5e3f0f7e-3d56-4a41-9a1b-6f0d7c2a8b11");
    private static final String CHANGED_MEANWHILE = "changed meanwhile";
    private static final String ISSUE_ATTRIBUTES_VALIDATION = "/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes/validate";
    private static final String ISSUE_ATTRIBUTES_OF_THE_CURRENT_CONNECTOR = "The issue certificate attributes of the EST Profile are for the connector of its current RA Profile; update the EST Profile with issue certificate attributes for the new RA Profile instead";

    @Autowired
    private EstProfileExternalService estProfileService;

    @Autowired
    private EstProfileInternalService estProfileInternalService;

    @Autowired
    private EstProfileRepository estProfileRepository;

    @Autowired
    private RaProfileRepository raProfileRepository;

    @Autowired
    private SecretRepository secretRepository;

    @Autowired
    private SecretVersionRepository secretVersionRepository;

    @Autowired
    private VaultInstanceRepository vaultInstanceRepository;

    @Autowired
    private VaultProfileRepository vaultProfileRepository;

    @Autowired
    private CertificateRepository certificateRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private RaProfileProtocolAttributeRepository raProfileProtocolAttributeRepository;

    @Autowired
    private ProtocolCertificateAssociationsRepository certificateAssociationsRepository;

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private FunctionGroupRepository functionGroupRepository;

    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;

    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private AttributeEngine attributeEngine;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Autowired
    private TransactionTemplate transactionTemplate;

    @Autowired
    private TokenProfileSeeder tokenProfiles;

    @Autowired
    private ConnectorMockFactory connectorMockFactory;

    @Autowired
    private EntityManager entityManager;

    /**
     * At most one profile is the system default through a partial unique index, a shape no entity annotation expresses,
     * so the entity-generated test schema lacks it. Each test runs against the index the migration creates rather than
     * against a schema that would quietly accept two defaults.
     */
    @BeforeEach
    void createSingleSystemDefaultIndex() {
        jdbcTemplate
                .execute("CREATE UNIQUE INDEX IF NOT EXISTS \"uk_est_profile_single_system_default\" ON " + dbSchema
                        + ".\"est_profile\" (\"system_default\") WHERE \"system_default\"");
    }

    @AfterEach
    void dropSingleSystemDefaultIndex() {
        jdbcTemplate.execute("DROP INDEX IF EXISTS " + dbSchema + ".\"uk_est_profile_single_system_default\"");
    }

    // ── CreateEstProfile ──────────────────────────────────────────────────────

    @Nested
    class CreateEstProfile {

        private CryptographyProviderV2ConnectorMock token;

        @AfterEach
        void stopToken() {
            if (token != null) {
                token.stop();
            }
        }

        @Test
        void createsDisabledProfileWithEveryReference_whenRequestCarriesAllOfThem() throws Exception {
            // given
            var secretName = "ra-credential";
            var tokenProfileName = "recovery-token";
            var keyAttributeName = "keyAlgorithm";
            var keyAlgorithm = "RSA";
            UUID secret = saveSecret(secretName, SecretType.BASIC_AUTH, true);
            token = connectorMockFactory.startCryptographyProviderV2();
            token.stubCreateKeyAttributes(keyAttributeDefinition(keyAttributeName));
            TokenProfile exportingProfile = tokenProfiles
                    .seedKeyExportingTokenProfile(token.getUrl(), KeyAlgorithm.RSA);
            exportingProfile.setName(tokenProfileName);
            UUID tokenProfile = tokenProfileRepository.saveAndFlush(exportingProfile).getUuid();
            var owner = UUID.randomUUID();
            EstProfileRequestDto request = anEstProfileRequest()
                    .withAuthenticationPolicy(EstAuthenticationPolicy.RA_BASIC)
                    .withBasicCredentialSecrets(secret)
                    .withKeyRecovery(tokenProfile, List.of(createKeyAttribute(keyAttributeName, keyAlgorithm)))
                    .withCertificateAssociations(createAssociations(owner))
                    .build();

            // when
            EstProfileDetailDto created = estProfileService.createEstProfile(request, ORIGIN);

            // then
            EstProfileDetailDto read = estProfileService
                    .getEstProfile(SecuredUUID.fromString(created.getUuid()), ORIGIN);
            assertThat(created.isEnabled()).isFalse();
            assertThat(created.getBasicCredentialSecrets()).containsExactly(new NameAndUuidDto(secret, secretName));
            assertThat(read.getBasicCredentialSecrets()).containsExactly(new NameAndUuidDto(secret, secretName));
            assertThat(read.getAuthenticationPolicy()).isEqualTo(EstAuthenticationPolicy.RA_BASIC);
            assertThat(read.getKeyRecoveryTokenProfile()).isEqualTo(new NameAndUuidDto(tokenProfile, tokenProfileName));
            assertThat(read.getKeyRecoveryKeyAttributes())
                    .extracting(ResponseAttribute::getName)
                    .containsExactly(keyAttributeName);
            assertThat(readContentData(read.getKeyRecoveryKeyAttributes().getFirst())).containsExactly(keyAlgorithm);
            assertThat(read.getCertificateAssociations().getOwnerUuid()).isEqualTo(owner);
        }

        @Test
        void storesTimings_whenRequestCarriesThem() throws Exception {
            // given
            var issueWaitTimeout = 3;
            var retryAfter = 7;
            var serverKeyGenerationTimeout = 45;
            EstProfileRequestDto request = anEstProfileRequest()
                    .withTimings(issueWaitTimeout, retryAfter, serverKeyGenerationTimeout)
                    .build();

            // when
            EstProfileDetailDto created = estProfileService.createEstProfile(request, ORIGIN);

            // then
            EstProfile stored = estProfileRepository.findById(UUID.fromString(created.getUuid())).orElseThrow();
            EstProfileDetailDto read = estProfileService
                    .getEstProfile(SecuredUUID.fromString(created.getUuid()), ORIGIN);
            assertThat(stored.getIssueWaitTimeout()).isEqualTo(issueWaitTimeout);
            assertThat(stored.getRetryAfter()).isEqualTo(retryAfter);
            assertThat(stored.getServerKeyGenerationTimeout()).isEqualTo(serverKeyGenerationTimeout);
            assertThat(read.getIssueWaitTimeout()).isEqualTo(issueWaitTimeout);
            assertThat(read.getRetryAfter()).isEqualTo(retryAfter);
            assertThat(read.getServerKeyGenerationTimeout()).isEqualTo(serverKeyGenerationTimeout);
        }

        @Test
        void storesDefaultTimings_whenRequestOmitsThem() throws Exception {
            // given
            EstProfileRequestDto request = anEstProfileRequest().build();

            // when
            EstProfileDetailDto created = estProfileService.createEstProfile(request, ORIGIN);

            // then
            EstProfile stored = estProfileRepository.findById(UUID.fromString(created.getUuid())).orElseThrow();
            assertThat(stored.getIssueWaitTimeout()).isEqualTo(10);
            assertThat(stored.getRetryAfter()).isEqualTo(30);
            assertThat(stored.getServerKeyGenerationTimeout()).isEqualTo(30);
            assertThat(created.getIssueWaitTimeout()).isEqualTo(10);
            assertThat(created.getRetryAfter()).isEqualTo(30);
            assertThat(created.getServerKeyGenerationTimeout()).isEqualTo(30);
        }

        @Test
        void throwsAlreadyExists_whenNameIsTaken() throws Exception {
            // given
            var takenName = "est-devices";
            createProfile(takenName);
            EstProfileRequestDto duplicate = anEstProfileRequest().withName(takenName).build();

            // when
            ThrowingCallable createDuplicate = () -> estProfileService.createEstProfile(duplicate, ORIGIN);

            // then
            assertThatThrownBy(createDuplicate).isInstanceOf(AlreadyExistException.class);
            assertThat(estProfileRepository.count()).isEqualTo(1);
        }

        @Test
        void throwsValidation_whenNameIsTheEstLabelOfAnRaProfile() {
            // given
            var labelOfRaProfile = "devices";
            EstProfile activated = estProfileRepository.save(anEstProfile().withName("est-other").build());
            RaProfile withEstActivated = saveRaProfile(labelOfRaProfile);
            withEstActivated.setEstProfile(activated);
            raProfileRepository.save(withEstActivated);
            EstProfileRequestDto request = anEstProfileRequest().withName(labelOfRaProfile).build();

            // when
            ThrowingCallable createUnderTheLabel = () -> estProfileService.createEstProfile(request, ORIGIN);

            // then
            assertThatThrownBy(createUnderTheLabel)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Name is already the EST label of RA Profile " + labelOfRaProfile);
            assertThat(estProfileRepository.findByName(labelOfRaProfile)).isEmpty();
        }

        @Test
        void createsProfile_whenNameIsOfAnRaProfileWithoutEstActivated() throws Exception {
            // given
            var nameOfRaProfileWithoutEst = "plain";
            saveRaProfile(nameOfRaProfileWithoutEst);
            EstProfileRequestDto request = anEstProfileRequest().withName(nameOfRaProfileWithoutEst).build();

            // when
            EstProfileDetailDto created = estProfileService.createEstProfile(request, ORIGIN);

            // then
            assertThat(created)
                    .describedAs("an RA Profile without EST activated does not hold its name as a label")
                    .extracting(EstProfileDto::getName)
                    .isEqualTo(nameOfRaProfileWithoutEst);
        }

        @Test
        void throwsValidation_whenTrustedCaIsAnEndEntityCertificate() {
            // given
            var endEntityName = "device-1";
            UUID endEntity = saveCertificate(endEntityName, CertificateSubjectType.END_ENTITY);
            EstProfileRequestDto request = anEstProfileRequest()
                    .withAuthenticationPolicy(EstAuthenticationPolicy.VENDOR_MTLS)
                    .withTrustedCaCertificates(endEntity)
                    .build();

            // when
            ThrowingCallable createWithEndEntityAsTrustAnchor = () -> estProfileService
                    .createEstProfile(request, ORIGIN);

            // then
            assertThatThrownBy(createWithEndEntityAsTrustAnchor)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(endEntityName);
            assertThat(estProfileRepository.count()).isZero();
        }

        @Test
        void storesDuplicateTrustedCaOnce_whenRequestRepeatsIt() throws Exception {
            // given
            var profileName = "est-devices";
            var rootName = "Vendor Root CA";
            var intermediateName = "Vendor Issuing CA";
            UUID root = saveCertificate(rootName, CertificateSubjectType.ROOT_CA);
            UUID intermediate = saveCertificate(intermediateName, CertificateSubjectType.INTERMEDIATE_CA);
            EstProfileRequestDto request = anEstProfileRequest()
                    .withName(profileName)
                    .withAuthenticationPolicy(EstAuthenticationPolicy.VENDOR_MTLS)
                    .withTrustedCaCertificates(root, root, intermediate)
                    .build();

            // when
            EstProfileDetailDto created = estProfileService.createEstProfile(request, ORIGIN);

            // then
            assertThat(created.getTrustedCaCertificates())
                    .containsExactly(new NameAndUuidDto(root, rootName),
                            new NameAndUuidDto(intermediate, intermediateName));
            assertThat(estProfileRepository.findByName(profileName).orElseThrow().getTrustedCaCertificateUuids())
                    .containsExactly(root, intermediate);
        }

        @Test
        void throwsValidation_whenKeyRecoveryTokenProfileIsDisabled() {
            // given
            var disabledTokenProfileName = "retired-token";
            UUID tokenProfile = saveTokenProfile(disabledTokenProfileName, false);
            EstProfileRequestDto request = anEstProfileRequest().withKeyRecovery(tokenProfile, List.of()).build();

            // when
            ThrowingCallable createWithDisabledTokenProfile = () -> estProfileService.createEstProfile(request, ORIGIN);

            // then
            assertThatThrownBy(createWithDisabledTokenProfile)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(disabledTokenProfileName);
            assertThat(estProfileRepository.count()).isZero();
        }

        /**
         * The authorization service may take as long as it likes to answer, so the caller's custom attribute
         * permissions are not asked for while a write holds the profile: an open transaction waits for the answer as a
         * session idle in transaction, and only such sessions that hold a lock on est_profile count.
         */
        @Test
        void asksForCustomAttributePermissionsWithoutHoldingTheProfile_whenCreating() throws Exception {
            // given
            RequestAttributeV3 owner = createCustomAttribute("estOwner", "PKI team");
            List<Long> sessionsHoldingAProfile = stubObjectAccessCountingSessionsHoldingAProfile(Resource.ATTRIBUTE,
                    ResourceAction.MEMBERS);
            EstProfileRequestDto request = anEstProfileRequest().withCustomAttributes(List.of(owner)).build();

            // when
            estProfileService.createEstProfile(request, ORIGIN);

            // then
            assertThat(sessionsHoldingAProfile).isNotEmpty().containsOnly(0L);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private UUID saveCertificate(String commonName, CertificateSubjectType subjectType) {
            return certificateRepository
                    .save(aCertificate().withCommonName(commonName).withSubjectType(subjectType).build())
                    .getUuid();
        }

        private UUID saveTokenProfile(String name, boolean enabled) {
            TokenProfile tokenProfile = new TokenProfile();
            tokenProfile.setName(name);
            tokenProfile.setEnabled(enabled);
            return tokenProfileRepository.save(tokenProfile).getUuid();
        }

        private static String keyAttributeDefinition(String name) {
            return "[{\"uuid\":\"" + KEY_ATTRIBUTE_UUID + "\",\"name\":\"" + name
                    + "\",\"type\":\"data\",\"contentType\":\"string\",\"version\":3,"
                    + "\"properties\":{\"label\":\"Key algorithm\",\"visible\":true,\"required\":true,"
                    + "\"readOnly\":false,\"list\":false,\"multiSelect\":false}}]";
        }

        private static RequestAttributeV3 createKeyAttribute(String name, String content) {
            return new RequestAttributeV3(KEY_ATTRIBUTE_UUID, name, AttributeContentType.STRING,
                    List.of(new StringAttributeContentV3(content)));
        }
    }

    // ── BasicCredentials ──────────────────────────────────────────────────────

    @Nested
    class BasicCredentials {

        @Test
        void throwsValidation_whenSecretIsOfAnotherType() {
            // given
            var apiKeyName = "api-key";
            UUID apiKey = saveSecret(apiKeyName, SecretType.API_KEY, true);
            EstProfileRequestDto request = anEstProfileRequest()
                    .withAuthenticationPolicy(EstAuthenticationPolicy.RA_BASIC)
                    .withBasicCredentialSecrets(apiKey)
                    .build();

            // when
            ThrowingCallable createWithApiKeySecret = () -> estProfileService.createEstProfile(request, ORIGIN);

            // then
            assertThatThrownBy(createWithApiKeySecret)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(apiKeyName);
            assertThat(estProfileRepository.count()).isZero();
        }

        @Test
        void throwsNotFound_whenSecretDoesNotExist() {
            // given
            var unknownSecret = UUID.randomUUID();
            EstProfileRequestDto request = anEstProfileRequest()
                    .withAuthenticationPolicy(EstAuthenticationPolicy.RA_BASIC)
                    .withBasicCredentialSecrets(unknownSecret)
                    .build();

            // when
            ThrowingCallable createWithUnknownSecret = () -> estProfileService.createEstProfile(request, ORIGIN);

            // then
            assertThatThrownBy(createWithUnknownSecret).isInstanceOf(NotFoundException.class);
        }

        @Test
        void throwsValidation_whenSecretIsDisabled() {
            // given
            var disabledSecretName = "retired-credential";
            UUID disabled = saveSecret(disabledSecretName, SecretType.BASIC_AUTH, false);
            EstProfileRequestDto request = anEstProfileRequest()
                    .withAuthenticationPolicy(EstAuthenticationPolicy.RA_BASIC)
                    .withBasicCredentialSecrets(disabled)
                    .build();

            // when
            ThrowingCallable createWithDisabledSecret = () -> estProfileService.createEstProfile(request, ORIGIN);

            // then
            assertThatThrownBy(createWithDisabledSecret)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(disabledSecretName);
            assertThat(estProfileRepository.count()).isZero();
        }

        /**
         * A secret made an RA credential lets whoever knows its content enroll, so the operator putting it in charge
         * must be able to read that content: the content permission on the secret and membership of its vault profile.
         */
        @Test
        void throwsAccessDenied_whenCallerCannotReadTheContentOfTheSecret() {
            // given
            UUID secret = saveSecret("ra-credential", SecretType.BASIC_AUTH, true);
            EstProfileRequestDto request = anEstProfileRequest()
                    .withAuthenticationPolicy(EstAuthenticationPolicy.RA_BASIC)
                    .withBasicCredentialSecrets(secret)
                    .build();
            denyResourceAccess(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT);

            // when
            ThrowingCallable createWithUnreadableSecret = () -> estProfileService.createEstProfile(request, ORIGIN);

            // then
            assertThatThrownBy(createWithUnreadableSecret).isInstanceOf(AccessDeniedException.class);
            assertThat(estProfileRepository.count()).isZero();
        }

        /**
         * A secret made an RA credential lets whoever knows its content enroll, so the operator putting it in charge
         * must be able to read that content: the content permission on the secret and membership of its vault profile.
         */
        @Test
        void throwsAccessDenied_whenCallerIsNoMemberOfTheVaultProfileOfTheSecret() {
            // given
            UUID secret = saveSecret("ra-credential", SecretType.BASIC_AUTH, true);
            EstProfileRequestDto request = anEstProfileRequest()
                    .withAuthenticationPolicy(EstAuthenticationPolicy.RA_BASIC)
                    .withBasicCredentialSecrets(secret)
                    .build();
            denyResourceAccess(Resource.VAULT_PROFILE, ResourceAction.MEMBERS);

            // when
            ThrowingCallable createWithSecretOfForeignVault = () -> estProfileService.createEstProfile(request, ORIGIN);

            // then
            assertThatThrownBy(createWithSecretOfForeignVault).isInstanceOf(AccessDeniedException.class);
            assertThat(estProfileRepository.count()).isZero();
        }

        /**
         * An edit replaces every setting, so a credential the profile already accepts must not stop an operator who
         * cannot read it from changing the others.
         */
        @Test
        void keepsCredential_whenCallerCannotReadItButChangesAnotherSetting() throws Exception {
            // given
            var secretName = "ra-credential";
            var changedDescription = "after";
            UUID kept = saveSecret(secretName, SecretType.BASIC_AUTH, true);
            EstProfileDetailDto created = estProfileService.createEstProfile(draftRaBasicRequest(kept).build(), ORIGIN);
            SecuredUUID uuid = SecuredUUID.fromString(created.getUuid());
            EstProfileEditRequestDto edit = draftRaBasicRequest(kept).withDescription(changedDescription).buildEdit();
            denyResourceAccess(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT);
            denyResourceAccess(Resource.VAULT_PROFILE, ResourceAction.MEMBERS);

            // when
            EstProfileDetailDto updated = estProfileService.updateEstProfile(uuid, edit, ORIGIN);

            // then
            assertThat(updated.getDescription()).isEqualTo(changedDescription);
            assertThat(updated.getBasicCredentialSecrets()).containsExactly(new NameAndUuidDto(kept, secretName));
        }

        /** Adding a credential takes both permissions, even though keeping one takes neither. */
        @Test
        void throwsAccessDenied_whenUpdateAddsCredentialTheCallerCannotRead() throws Exception {
            // given
            UUID kept = saveSecret("ra-credential", SecretType.BASIC_AUTH, true);
            UUID added = saveSecret("second-credential", SecretType.BASIC_AUTH, true);
            EstProfileDetailDto created = estProfileService.createEstProfile(draftRaBasicRequest(kept).build(), ORIGIN);
            SecuredUUID uuid = SecuredUUID.fromString(created.getUuid());
            EstProfileEditRequestDto adding = draftRaBasicRequest(kept, added).buildEdit();
            denyResourceAccess(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT);
            denyResourceAccess(Resource.VAULT_PROFILE, ResourceAction.MEMBERS);

            // when
            ThrowingCallable updateAddingSecret = () -> estProfileService.updateEstProfile(uuid, adding, ORIGIN);

            // then
            assertThatThrownBy(updateAddingSecret).isInstanceOf(AccessDeniedException.class);
            assertThat(estProfileRepository.findById(uuid.getValue()).orElseThrow().getBasicCredentialSecretUuids())
                    .containsExactly(kept);
        }

        @Test
        void throwsValidation_whenUpdateKeepsCredentialThatHasBeenDisabled() throws Exception {
            // given
            var secretName = "ra-credential";
            UUID kept = saveSecret(secretName, SecretType.BASIC_AUTH, true);
            EstProfileDetailDto created = estProfileService.createEstProfile(draftRaBasicRequest(kept).build(), ORIGIN);
            jdbcTemplate.update("UPDATE " + dbSchema + ".secret SET enabled = FALSE WHERE uuid = ?", kept);
            denyResourceAccess(Resource.SECRET, ResourceAction.GET_SECRET_CONTENT);
            SecuredUUID uuid = SecuredUUID.fromString(created.getUuid());
            EstProfileEditRequestDto keeping = draftRaBasicRequest(kept).buildEdit();

            // when
            ThrowingCallable updateKeepingDisabledSecret = () -> estProfileService
                    .updateEstProfile(uuid, keeping, ORIGIN);

            // then
            assertThatThrownBy(updateKeepingDisabledSecret)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Secret " + secretName + " is disabled");
        }

        /**
         * A credential passes without the content gate because the profile accepted it when the update began; one that
         * an update committed meanwhile dropped would otherwise come back unchecked.
         */
        @Test
        void throwsValidation_whenKeptCredentialIsDroppedWhileTheUpdateIsChecked() throws Exception {
            // given
            UUID kept = saveSecret("ra-credential", SecretType.BASIC_AUTH, true);
            UUID added = saveSecret("second-credential", SecretType.BASIC_AUTH, true);
            EstProfileDetailDto created = estProfileService.createEstProfile(draftRaBasicRequest(kept).build(), ORIGIN);
            UUID uuid = UUID.fromString(created.getUuid());
            SecuredUUID securedUuid = SecuredUUID.fromUUID(uuid);
            EstProfileEditRequestDto adding = draftRaBasicRequest(kept, added).buildEdit();
            stubConcurrentCredentialDropOnSecretContentCheck(uuid);

            // when
            ThrowingCallable updateWhileCredentialsAreDropped = () -> estProfileService
                    .updateEstProfile(securedUuid, adding, ORIGIN);

            // then
            assertThatThrownBy(updateWhileCredentialsAreDropped)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(CREDENTIALS_CHANGED);
            assertThat(estProfileRepository.findById(uuid).orElseThrow().getBasicCredentialSecretUuids()).isEmpty();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static EstProfileRequestDtoBuilder draftRaBasicRequest(UUID... secretUuids) {
            return anEstProfileRequest()
                    .withAuthenticationPolicy(EstAuthenticationPolicy.RA_BASIC)
                    .withBasicCredentialSecrets(secretUuids);
        }

        /**
         * Stands in for an update committed by another operator while the content access of a credential is checked.
         */
        private void stubConcurrentCredentialDropOnSecretContentCheck(UUID profileUuid) {
            OpaResourceAccessResult allowed = new OpaResourceAccessResult();
            allowed.setAuthorized(true);
            allowed.setAllow(List.of());
            when(opaClient
                    .checkResourceAccess(Mockito.any(),
                            Mockito
                                    .argThat(req -> req != null && req.getProperties() != null
                                            && Resource.SECRET.getCode().equals(req.getProperties().get("name"))
                                            && ResourceAction.GET_SECRET_CONTENT
                                                    .getCode()
                                                    .equals(req.getProperties().get("action"))),
                            Mockito.any(), Mockito.any()))
                    .thenAnswer(invocation -> {
                        jdbcTemplate
                                .update("UPDATE " + dbSchema
                                        + ".est_profile SET basic_credential_secret_uuids = '{}' WHERE uuid = ?",
                                        profileUuid);
                        return allowed;
                    });
        }
    }

    // ── IssueAttributes ───────────────────────────────────────────────────────

    @Nested
    class IssueAttributes {

        private WireMockServer connectorServer;

        @BeforeEach
        void startConnector() {
            connectorServer = LoopbackWireMock.start();
        }

        @AfterEach
        void stopConnector() {
            connectorServer.stop();
        }

        @Test
        void throwsValidation_whenIssueAttributesComeWithAnRaProfileWithoutConnector() {
            // given
            RaProfile withoutAuthority = saveRaProfile("devices-ra");
            EstProfileRequestDto request = anEstProfileRequest()
                    .withRaProfile(withoutAuthority.getUuid())
                    .withIssueCertificateAttributes(List.of(createIssueAttribute(UUID.randomUUID(), "devices")))
                    .build();

            // when
            ThrowingCallable createWithIssueAttributesWithoutConnector = () -> estProfileService
                    .createEstProfile(request, ORIGIN);

            // then
            assertThatThrownBy(createWithIssueAttributesWithoutConnector)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(
                            "Issue certificate attributes need an RA Profile whose authority has a connector");
            assertThat(estProfileRepository.count()).isZero();
        }

        @Test
        void keepsIssueAttributes_whenConnectorValidatesThem() throws Exception {
            // given
            RaProfile raProfile = AuthorityFixtures
                    .v2Authority(collectAuthorityRepos(), connectorServer, "MOCK")
                    .raProfile();
            var attributeUuid = UUID.randomUUID();
            var attributeContent = "devices";
            stubIssueAttributes(connectorServer, attributeUuid);
            EstProfileRequestDto request = anEstProfileRequest()
                    .withRaProfile(raProfile.getUuid())
                    .withIssueCertificateAttributes(List.of(createIssueAttribute(attributeUuid, attributeContent)))
                    .build();

            // when
            EstProfileDetailDto created = estProfileService.createEstProfile(request, ORIGIN);

            // then
            EstProfileDetailDto read = estProfileService
                    .getEstProfile(SecuredUUID.fromString(created.getUuid()), ORIGIN);
            assertThat(read.getIssueCertificateAttributes())
                    .extracting(ResponseAttribute::getUuid)
                    .containsExactly(attributeUuid);
            assertThat(readContentData(read.getIssueCertificateAttributes().getFirst()))
                    .containsExactly(attributeContent);
            connectorServer
                    .verify(1, WireMock
                            .postRequestedFor(WireMock.urlPathMatching(".*/certificates/issue/attributes/validate")));
        }

        /**
         * The name was free as a label when it was checked before the connector call, which is as long ago as the
         * connector is slow.
         */
        @Test
        void throwsValidation_whenRaProfileTakesTheNameWhileTheConnectorIsCalled() {
            // given
            var contestedName = "devices";
            RaProfile issuing = AuthorityFixtures
                    .v2Authority(collectAuthorityRepos(), connectorServer, "MOCK")
                    .raProfile();
            var attributeUuid = UUID.randomUUID();
            stubIssueAttributes(connectorServer, attributeUuid, 1000);
            UUID devices = saveRaProfile(contestedName).getUuid();
            UUID activated = estProfileRepository.save(anEstProfile().withName("est-other").build()).getUuid();
            EstProfileRequestDto request = anEstProfileRequest()
                    .withName(contestedName)
                    .withRaProfile(issuing.getUuid())
                    .withIssueCertificateAttributes(List.of(createIssueAttribute(attributeUuid, "devices")))
                    .build();
            Runnable activation = () -> jdbcTemplate
                    .update("UPDATE " + dbSchema + ".ra_profile SET est_profile_uuid = ? WHERE uuid = ?", activated,
                            devices);
            Callable<EstProfileDetailDto> creation = () -> estProfileService.createEstProfile(request, ORIGIN);

            // when
            ThrowingCallable createWhileTheConnectorValidates = () -> runWhileTheConnectorValidates(connectorServer,
                    activation, creation);

            // then
            assertThatThrownBy(createWhileTheConnectorValidates)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Name is already the EST label of RA Profile " + contestedName);
            assertThat(estProfileRepository.findByName(contestedName)).isEmpty();
            assertThat(estProfileRepository.count()).isEqualTo(1);
        }

        @Test
        void dropsIssueAttributes_whenEditLeavesTheRaProfile() throws Exception {
            // given
            AuthorityFixtures.Fixture authority = AuthorityFixtures
                    .v2Authority(collectAuthorityRepos(), connectorServer, "MOCK");
            var attributeUuid = UUID.randomUUID();
            stubIssueAttributes(connectorServer, attributeUuid);
            EstProfileDetailDto created = createProfileWithIssueAttributes(authority.raProfile(), attributeUuid);
            UUID profileUuid = UUID.fromString(created.getUuid());
            EstProfileEditRequestDto edit = anEstProfileRequest().buildEdit();

            // when
            EstProfileDetailDto updated = estProfileService
                    .updateEstProfile(SecuredUUID.fromUUID(profileUuid), edit, ORIGIN);

            // then
            assertThat(updated.getIssueCertificateAttributes()).isEmpty();
            assertThat(attributeEngine
                    .getObjectDataAttributesContent(ObjectAttributeContentInfo
                            .builder(Resource.EST_PROFILE, profileUuid)
                            .connector(authority.connector().getUuid())
                            .operation(AttributeOperation.CERTIFICATE_ISSUE)
                            .build()))
                    .describedAs("the attributes stored for the connector of the RA Profile left behind are deleted")
                    .isEmpty();
        }

        @Test
        void keepsIssueAttributes_whenNewRaProfileIsOfTheSameConnector() throws Exception {
            // given
            AuthorityFixtures.Fixture authority = AuthorityFixtures
                    .v2Authority(collectAuthorityRepos(), connectorServer, "MOCK");
            var attributeUuid = UUID.randomUUID();
            stubIssueAttributes(connectorServer, attributeUuid);
            EstProfileDetailDto created = createProfileWithIssueAttributes(authority.raProfile(), attributeUuid);
            var siblingName = "servers-ra";
            RaProfile sibling = saveRaProfile(siblingName);
            sibling.setAuthorityInstanceReference(authority.authority());
            sibling.setAuthorityInstanceReferenceUuid(authority.authority().getUuid());
            raProfileRepository.save(sibling);
            SecuredUUID uuid = SecuredUUID.fromString(created.getUuid());

            // when
            estProfileService.updateRaProfile(uuid, sibling.getUuid());

            // then
            EstProfileDetailDto read = estProfileService.getEstProfile(uuid, ORIGIN);
            assertThat(read.getRaProfile().getName()).isEqualTo(siblingName);
            assertThat(read.getIssueCertificateAttributes())
                    .extracting(ResponseAttribute::getUuid)
                    .containsExactly(attributeUuid);
        }

        /**
         * Issue attributes are stored keyed by the connector of the default RA Profile, so a default of another
         * connector, or none, would leave them behind: no longer applied, not deleted by a later update, and applied
         * again if the profile came back.
         */
        @Test
        void throwsValidation_whenMovingToAnotherConnectorWhileIssueAttributesAreStored() throws Exception {
            // given
            RaProfile current = AuthorityFixtures
                    .v2Authority(collectAuthorityRepos(), connectorServer, "MOCK")
                    .raProfile();
            var attributeUuid = UUID.randomUUID();
            stubIssueAttributes(connectorServer, attributeUuid);
            EstProfileDetailDto created = createProfileWithIssueAttributes(current, attributeUuid);
            SecuredUUID uuid = SecuredUUID.fromString(created.getUuid());
            UUID ofAnotherConnector = AuthorityFixtures
                    .v2Authority(collectAuthorityRepos(), "OTHER")
                    .raProfile()
                    .getUuid();

            // when
            ThrowingCallable moveToAnotherConnector = () -> estProfileService.updateRaProfile(uuid, ofAnotherConnector);

            // then
            assertThatThrownBy(moveToAnotherConnector)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(ISSUE_ATTRIBUTES_OF_THE_CURRENT_CONNECTOR);
            EstProfileDetailDto read = estProfileService.getEstProfile(uuid, ORIGIN);
            assertThat(read.getRaProfile().getUuid()).isEqualTo(current.getUuid().toString());
            assertThat(read.getIssueCertificateAttributes())
                    .extracting(ResponseAttribute::getUuid)
                    .containsExactly(attributeUuid);
        }

        /**
         * Issue attributes are stored keyed by the connector of the default RA Profile, so a default of another
         * connector, or none, would leave them behind: no longer applied, not deleted by a later update, and applied
         * again if the profile came back.
         */
        @Test
        void throwsValidation_whenClearingTheRaProfileWhileIssueAttributesAreStored() throws Exception {
            // given
            RaProfile current = AuthorityFixtures
                    .v2Authority(collectAuthorityRepos(), connectorServer, "MOCK")
                    .raProfile();
            var attributeUuid = UUID.randomUUID();
            stubIssueAttributes(connectorServer, attributeUuid);
            EstProfileDetailDto created = createProfileWithIssueAttributes(current, attributeUuid);
            SecuredUUID uuid = SecuredUUID.fromString(created.getUuid());

            // when
            ThrowingCallable clearTheRaProfile = () -> estProfileService.updateRaProfile(uuid, null);

            // then
            assertThatThrownBy(clearTheRaProfile)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(ISSUE_ATTRIBUTES_OF_THE_CURRENT_CONNECTOR);
            EstProfileDetailDto read = estProfileService.getEstProfile(uuid, ORIGIN);
            assertThat(read.getRaProfile().getUuid()).isEqualTo(current.getUuid().toString());
            assertThat(read.getIssueCertificateAttributes())
                    .extracting(ResponseAttribute::getUuid)
                    .containsExactly(attributeUuid);
        }

        @Test
        void setsRaProfileOfAnotherConnector_whenNoIssueAttributesAreStored() throws Exception {
            // given
            RaProfile current = AuthorityFixtures.v2Authority(collectAuthorityRepos(), "MOCK").raProfile();
            UUID ofAnotherConnector = AuthorityFixtures
                    .v2Authority(collectAuthorityRepos(), "OTHER")
                    .raProfile()
                    .getUuid();
            UUID uuid = estProfileRepository.save(anEstProfile().withRaProfile(current).build()).getUuid();

            // when
            estProfileService.updateRaProfile(SecuredUUID.fromUUID(uuid), ofAnotherConnector);

            // then
            assertThat(estProfileRepository.findById(uuid).orElseThrow().getRaProfileUuid())
                    .isEqualTo(ofAnotherConnector);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private AuthorityFixtures.Repos collectAuthorityRepos() {
            return new AuthorityFixtures.Repos(connectorRepository, functionGroupRepository,
                    connector2FunctionGroupRepository, authorityInstanceReferenceRepository, raProfileRepository,
                    connectorInterfaceRepository);
        }

        private EstProfileDetailDto createProfileWithIssueAttributes(RaProfile raProfile, UUID attributeUuid)
                throws Exception {
            EstProfileRequestDto request = anEstProfileRequest()
                    .withRaProfile(raProfile.getUuid())
                    .withIssueCertificateAttributes(List.of(createIssueAttribute(attributeUuid, "devices")))
                    .build();
            return estProfileService.createEstProfile(request, ORIGIN);
        }

        private static void stubIssueAttributes(WireMockServer connectorServer, UUID attributeUuid) {
            stubIssueAttributes(connectorServer, attributeUuid, 0);
        }

        /** Stubs the connector's issue attribute schema and validation, and answers the validation after the delay. */
        private static void stubIssueAttributes(WireMockServer connectorServer, UUID attributeUuid,
                int validationDelayMillis) {
            connectorServer
                    .stubFor(WireMock
                            .post(WireMock.urlPathMatching(ISSUE_ATTRIBUTES_VALIDATION))
                            .willReturn(WireMock.okJson("true").withFixedDelay(validationDelayMillis)));
            connectorServer
                    .stubFor(WireMock
                            .get(WireMock
                                    .urlPathMatching(
                                            "/v2/authorityProvider/authorities/[^/]+/certificates/issue/attributes"))
                            .willReturn(WireMock
                                    .okJson(AttributeDefinitionUtils
                                            .serialize(List.of(createIssueAttributeDefinition(attributeUuid))))));
        }

        /**
         * Runs the call on this thread while another thread waits for the connector's validation request to arrive and
         * then makes the change. The connector answers the request late, so the change is made while the call waits for
         * the answer. A call that fails ends the wait, so its failure is the one reported.
         */
        private static <T> T runWhileTheConnectorValidates(WireMockServer connectorServer, Runnable meanwhile,
                Callable<T> call) throws Exception {
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                Future<?> change = executor.submit(() -> {
                    Awaitility
                            .await()
                            .pollInterval(Duration.ofMillis(10))
                            .atMost(Duration.ofSeconds(10))
                            .until(() -> !connectorServer
                                    .findAll(WireMock
                                            .postRequestedFor(WireMock.urlPathMatching(ISSUE_ATTRIBUTES_VALIDATION)))
                                    .isEmpty());
                    meanwhile.run();
                });
                T result = call.call();
                change.get(30, TimeUnit.SECONDS);
                return result;
            } finally {
                executor.shutdownNow();
            }
        }

        private static DataAttributeV2 createIssueAttributeDefinition(UUID uuid) {
            DataAttributeV2 definition = new DataAttributeV2();
            definition.setUuid(uuid.toString());
            definition.setName("profileName");
            definition.setContentType(AttributeContentType.STRING);
            DataAttributeProperties properties = new DataAttributeProperties();
            properties.setLabel("Profile name");
            definition.setProperties(properties);
            return definition;
        }

        private static RequestAttributeV2 createIssueAttribute(UUID uuid, String content) {
            return new RequestAttributeV2(uuid, "profileName", AttributeContentType.STRING,
                    List.of(new StringAttributeContentV2(content)), AttributeVersion.V2);
        }
    }

    // ── SystemDefault ─────────────────────────────────────────────────────────

    @Nested
    class SystemDefault {

        @Test
        void replacesSystemDefault_whenCreatingAnotherOne() throws Exception {
            // given
            var newDefaultName = "est-b";
            EstProfileDetailDto first = estProfileService
                    .createEstProfile(anEstProfileRequest().withName("est-a").asSystemDefault().build(), ORIGIN);
            EstProfileRequestDto secondDefault = anEstProfileRequest()
                    .withName(newDefaultName)
                    .asSystemDefault()
                    .build();

            // when
            EstProfileDetailDto second = estProfileService.createEstProfile(secondDefault, ORIGIN);

            // then
            EstProfileDetailDto reloadedFirst = estProfileService
                    .getEstProfile(SecuredUUID.fromString(first.getUuid()), ORIGIN);
            assertThat(reloadedFirst.isSystemDefault()).isFalse();
            assertThat(second.isSystemDefault()).isTrue();
            assertThat(loadSystemDefaultNames()).containsExactly(newDefaultName);
        }

        @Test
        void replacesSystemDefault_whenUpdatingProfileToBeTheDefault() throws Exception {
            // given
            var newDefaultName = "est-b";
            var bystanderName = "est-c";
            estProfileService
                    .createEstProfile(anEstProfileRequest().withName("est-a").asSystemDefault().build(), ORIGIN);
            EstProfileDetailDto second = estProfileService
                    .createEstProfile(anEstProfileRequest().withName(newDefaultName).build(), ORIGIN);
            estProfileService.createEstProfile(anEstProfileRequest().withName(bystanderName).build(), ORIGIN);
            OffsetDateTime untouchedBefore = loadUpdatedAt(bystanderName);
            EstProfileEditRequestDto edit = anEstProfileRequest().asSystemDefault().buildEdit();

            // when
            EstProfileDetailDto updated = estProfileService
                    .updateEstProfile(SecuredUUID.fromString(second.getUuid()), edit, ORIGIN);

            // then
            assertThat(updated.isSystemDefault()).isTrue();
            assertThat(loadSystemDefaultNames()).containsExactly(newDefaultName);
            assertThat(loadUpdatedAt(bystanderName))
                    .describedAs("a profile that was not the default is left as it was")
                    .isEqualTo(untouchedBefore);
        }

        /**
         * The clearing update cannot see a default that another transaction has not committed, so the save waits on the
         * single-default index until that transaction commits, and is then refused with a message that asks for a
         * retry.
         */
        @Test
        void throwsValidationAskingForRetry_whenAnotherDefaultCommitsWhileTheSaveWaits() throws Exception {
            // given
            var concurrentDefaultName = "est-concurrent";
            var requestedName = "est-devices";
            EstProfileRequestDto request = anEstProfileRequest().withName(requestedName).asSystemDefault().build();
            SecurityContext context = SecurityContextHolder.getContext();
            ExecutorService executor = Executors.newSingleThreadExecutor();
            try {
                // when
                Future<EstProfileDetailDto> creation = transactionTemplate.execute(status -> {
                    estProfileRepository
                            .saveAndFlush(
                                    anEstProfile().withName(concurrentDefaultName).withSystemDefault(true).build());
                    Future<EstProfileDetailDto> waiting = executor
                            .submit(bindToCaller(context, () -> estProfileService.createEstProfile(request, ORIGIN)));
                    awaitAnEstProfileStatementBlockedBy(loadTransactionBackendPid());
                    return waiting;
                });
                ThrowingCallable awaitCreation = () -> creation.get(30, TimeUnit.SECONDS);

                // then
                assertThatThrownBy(awaitCreation)
                        .isInstanceOf(ExecutionException.class)
                        .cause()
                        .isInstanceOf(ValidationException.class)
                        .hasMessageContaining(SYSTEM_DEFAULT_CLASH);
                assertThat(loadSystemDefaultNames()).containsExactly(concurrentDefaultName);
                assertThat(estProfileRepository.findByName(requestedName)).isEmpty();
            } finally {
                executor.shutdownNow();
            }
            assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private List<String> loadSystemDefaultNames() {
            return jdbcTemplate
                    .queryForList("SELECT name FROM " + dbSchema + ".est_profile WHERE system_default", String.class);
        }

        private OffsetDateTime loadUpdatedAt(String name) {
            return jdbcTemplate
                    .queryForObject("SELECT i_upd FROM " + dbSchema + ".est_profile WHERE name = ?",
                            OffsetDateTime.class, name);
        }
    }

    // ── UpdateEstProfile ──────────────────────────────────────────────────────

    @Nested
    class UpdateEstProfile {

        /**
         * The update reads the profile under a row lock, so an enable committed while it waited survives the whole-row
         * write that follows.
         */
        @Test
        void keepsEnable_whenItIsCommittedWhileTheUpdateWaits() throws Exception {
            // given
            var updatedDescription = "updated";
            UUID uuid = createProfile("est-devices");
            EstProfileEditRequestDto edit = anEstProfileRequest().withDescription(updatedDescription).buildEdit();
            SecurityContext context = SecurityContextHolder.getContext();
            ExecutorService executor = Executors.newSingleThreadExecutor();

            // when
            EstProfileDetailDto updated;
            try {
                Future<EstProfileDetailDto> update = transactionTemplate.execute(status -> {
                    EstProfile enabled = estProfileRepository.findById(uuid).orElseThrow();
                    enabled.setEnabled(true);
                    estProfileRepository.saveAndFlush(enabled);
                    Future<EstProfileDetailDto> waiting = executor
                            .submit(bindToCaller(context, () -> estProfileService
                                    .updateEstProfile(SecuredUUID.fromUUID(uuid), edit, ORIGIN)));
                    awaitAnEstProfileStatementBlockedBy(loadTransactionBackendPid());
                    return waiting;
                });
                updated = update.get(30, TimeUnit.SECONDS);
            } finally {
                executor.shutdownNow();
            }

            // then
            assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
            assertThat(updated.getDescription()).isEqualTo(updatedDescription);
            EstProfile stored = estProfileRepository.findById(uuid).orElseThrow();
            assertThat(stored.isEnabled()).describedAs("the enable committed while the update waited").isTrue();
            assertThat(stored.getDescription()).isEqualTo(updatedDescription);
        }

        /**
         * The authorization service may take as long as it likes to answer, so the caller's custom attribute
         * permissions are not asked for while a write holds the profile: an open transaction waits for the answer as a
         * session idle in transaction, and only such sessions that hold a lock on est_profile count.
         */
        @Test
        void asksForCustomAttributePermissionsWithoutHoldingTheProfile_whenUpdating() throws Exception {
            // given
            var ownerAttributeName = "estOwner";
            RequestAttributeV3 owner = createCustomAttribute(ownerAttributeName, "PKI team");
            EstProfileDetailDto created = estProfileService
                    .createEstProfile(anEstProfileRequest().withCustomAttributes(List.of(owner)).build(), ORIGIN);
            SecuredUUID uuid = SecuredUUID.fromString(created.getUuid());
            EstProfileEditRequestDto edit = anEstProfileRequest().withCustomAttributes(List.of(owner)).buildEdit();
            List<Long> sessionsHoldingAProfile = stubObjectAccessCountingSessionsHoldingAProfile(Resource.ATTRIBUTE,
                    ResourceAction.MEMBERS);

            // when
            EstProfileDetailDto updated = estProfileService.updateEstProfile(uuid, edit, ORIGIN);

            // then
            assertThat(sessionsHoldingAProfile).isNotEmpty().containsOnly(0L);
            assertThat(updated.getCustomAttributes())
                    .extracting(ResponseAttribute::getName)
                    .containsExactly(ownerAttributeName);
        }

        @Test
        void rewritesCertificateAssociationsInPlace_whenEditChangesTheOwner() throws Exception {
            // given
            EstProfileDetailDto created = estProfileService
                    .createEstProfile(anEstProfileRequest()
                            .withCertificateAssociations(createAssociations(UUID.randomUUID()))
                            .build(), ORIGIN);
            UUID profileUuid = UUID.fromString(created.getUuid());
            UUID associationsUuid = estProfileRepository
                    .findById(profileUuid)
                    .orElseThrow()
                    .getCertificateAssociationsUuid();
            var newOwner = UUID.randomUUID();
            EstProfileEditRequestDto edit = anEstProfileRequest()
                    .withCertificateAssociations(createAssociations(newOwner))
                    .buildEdit();

            // when
            EstProfileDetailDto updated = estProfileService
                    .updateEstProfile(SecuredUUID.fromUUID(profileUuid), edit, ORIGIN);

            // then
            assertThat(updated.getCertificateAssociations().getOwnerUuid()).isEqualTo(newOwner);
            assertThat(estProfileRepository.findById(profileUuid).orElseThrow().getCertificateAssociationsUuid())
                    .isEqualTo(associationsUuid);
            assertThat(certificateAssociationsRepository.findById(associationsUuid).orElseThrow().getOwnerUuid())
                    .isEqualTo(newOwner);
            assertThat(certificateAssociationsRepository.count()).isEqualTo(1);
        }

        @Test
        void keepsName_whenEditReplacesSettings() throws Exception {
            // given
            var profileName = "est-devices";
            EstProfileDetailDto created = estProfileService
                    .createEstProfile(anEstProfileRequest()
                            .withName(profileName)
                            .withDescription("before")
                            .withCertificateAssociations(createAssociations(UUID.randomUUID()))
                            .build(), ORIGIN);
            EstProfileEditRequestDto edit = anEstProfileRequest()
                    .withDescription("after")
                    .withAllowRekey(false)
                    .withRenewalThreshold(30)
                    .buildEdit();

            // when
            EstProfileDetailDto updated = estProfileService
                    .updateEstProfile(SecuredUUID.fromString(created.getUuid()), edit, ORIGIN);

            // then
            assertThat(updated.getName()).isEqualTo(profileName);
        }

        @Test
        void replacesSettings_whenEditCarriesNewOnes() throws Exception {
            // given
            var updatedDescription = "after";
            var renewalThreshold = 30;
            EstProfileDetailDto created = estProfileService
                    .createEstProfile(anEstProfileRequest()
                            .withDescription("before")
                            .withCertificateAssociations(createAssociations(UUID.randomUUID()))
                            .build(), ORIGIN);
            EstProfileEditRequestDto edit = anEstProfileRequest()
                    .withDescription(updatedDescription)
                    .withAllowRekey(false)
                    .withRenewalThreshold(renewalThreshold)
                    .buildEdit();

            // when
            EstProfileDetailDto updated = estProfileService
                    .updateEstProfile(SecuredUUID.fromString(created.getUuid()), edit, ORIGIN);

            // then
            EstProfile stored = estProfileRepository.findById(UUID.fromString(created.getUuid())).orElseThrow();
            assertThat(updated.getDescription()).isEqualTo(updatedDescription);
            assertThat(updated.isAllowRekey()).isFalse();
            assertThat(stored.isAllowRekey()).isFalse();
            assertThat(stored.getRenewalThreshold()).isEqualTo(renewalThreshold);
            assertThat(updated.getCertificateAssociations()).isNull();
            assertThat(certificateAssociationsRepository.count())
                    .describedAs("the certificate associations the update dropped are deleted")
                    .isZero();
        }

        @Test
        void replacesTimings_whenEditCarriesNewOnes() throws Exception {
            // given
            var issueWaitTimeout = 0;
            var retryAfter = 7;
            var serverKeyGenerationTimeout = 45;
            EstProfileDetailDto created = estProfileService
                    .createEstProfile(anEstProfileRequest().withTimings(1, 2, 3).build(), ORIGIN);
            EstProfileEditRequestDto edit = anEstProfileRequest()
                    .withTimings(issueWaitTimeout, retryAfter, serverKeyGenerationTimeout)
                    .buildEdit();

            // when
            EstProfileDetailDto updated = estProfileService
                    .updateEstProfile(SecuredUUID.fromString(created.getUuid()), edit, ORIGIN);

            // then
            EstProfile stored = estProfileRepository.findById(UUID.fromString(created.getUuid())).orElseThrow();
            assertThat(stored.getIssueWaitTimeout()).isEqualTo(issueWaitTimeout);
            assertThat(stored.getRetryAfter()).isEqualTo(retryAfter);
            assertThat(stored.getServerKeyGenerationTimeout()).isEqualTo(serverKeyGenerationTimeout);
            assertThat(updated.getIssueWaitTimeout()).isEqualTo(issueWaitTimeout);
            assertThat(updated.getRetryAfter()).isEqualTo(retryAfter);
            assertThat(updated.getServerKeyGenerationTimeout()).isEqualTo(serverKeyGenerationTimeout);
        }

        @Test
        void throwsNotFound_whenProfileDoesNotExist() {
            // given
            SecuredUUID unknown = SecuredUUID.fromUUID(UUID.randomUUID());
            EstProfileEditRequestDto edit = anEstProfileRequest().buildEdit();

            // when
            ThrowingCallable updateUnknownProfile = () -> estProfileService.updateEstProfile(unknown, edit, ORIGIN);

            // then
            assertThatThrownBy(updateUnknownProfile).isInstanceOf(NotFoundException.class);
        }
    }

    // ── DeleteEstProfiles ─────────────────────────────────────────────────────

    @Nested
    class DeleteEstProfiles {

        @Test
        void throwsValidation_whenProfileIsActivatedOnRaProfiles() throws Exception {
            // given
            var raProfileName = "devices-ra";
            UUID uuid = createProfile("est-devices");
            activateEstOnNewRaProfile(raProfileName, uuid);
            SecuredUUID securedUuid = SecuredUUID.fromUUID(uuid);

            // when
            ThrowingCallable deleteActivatedProfile = () -> estProfileService.deleteEstProfile(securedUuid);

            // then
            assertThatThrownBy(deleteActivatedProfile)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("associated RA Profiles (1): " + raProfileName);
            assertThat(estProfileRepository.existsById(uuid)).isTrue();
        }

        /** Every RA Profile the profile is activated on is counted, and only those the caller may list are named. */
        @Test
        void throwsValidationNamingOnlyListableRaProfiles_whenSomeAreHidden() throws Exception {
            // given
            var visibleRaProfileName = "visible-ra";
            var hiddenRaProfileName = "hidden-ra";
            UUID uuid = createProfile("est-devices");
            activateEstOnNewRaProfile(visibleRaProfileName, uuid);
            RaProfile hidden = activateEstOnNewRaProfile(hiddenRaProfileName, uuid);
            forbidObjectAccess(Resource.RA_PROFILE, ResourceAction.LIST, List.of(hidden.getUuid()));
            SecuredUUID securedUuid = SecuredUUID.fromUUID(uuid);

            // when
            ThrowingCallable deleteProfileWithHiddenRaProfile = () -> estProfileService.deleteEstProfile(securedUuid);

            // then
            assertThatThrownBy(deleteProfileWithHiddenRaProfile)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(
                            "Cannot remove as there are associated RA Profiles (2): " + visibleRaProfileName)
                    .hasMessageNotContaining(hiddenRaProfileName);
            assertThat(estProfileRepository.existsById(uuid)).isTrue();
        }

        /** Every RA Profile the profile is activated on is counted, and only those the caller may list are named. */
        @Test
        void reportsFailureNamingOnlyListableRaProfiles_whenSomeAreHiddenFromBulkDelete() throws Exception {
            // given
            var visibleRaProfileName = "visible-ra";
            UUID uuid = createProfile("est-devices");
            activateEstOnNewRaProfile(visibleRaProfileName, uuid);
            RaProfile hidden = activateEstOnNewRaProfile("hidden-ra", uuid);
            forbidObjectAccess(Resource.RA_PROFILE, ResourceAction.LIST, List.of(hidden.getUuid()));
            List<SecuredUUID> bulk = List.of(SecuredUUID.fromUUID(uuid));

            // when
            List<BulkActionMessageDto> messages = estProfileService.bulkDeleteEstProfiles(bulk);

            // then
            assertThat(messages)
                    .singleElement()
                    .extracting(BulkActionMessageDto::getMessage)
                    .isEqualTo("Cannot remove as there are associated RA Profiles (2): " + visibleRaProfileName);
            assertThat(estProfileRepository.existsById(uuid)).isTrue();
        }

        @Test
        void deletesProfile_whenNoRaProfileHasItActivatedAndCallerMayNotListRaProfiles() throws Exception {
            // given
            UUID free = createProfile("est-free");
            UUID activated = createProfile("est-activated");
            activateEstOnNewRaProfile("first-ra", activated);
            denyResourceAccess(Resource.RA_PROFILE, ResourceAction.LIST);

            // when
            estProfileService.deleteEstProfile(SecuredUUID.fromUUID(free));

            // then
            assertThat(estProfileRepository.existsById(free)).isFalse();
            assertThat(estProfileRepository.existsById(activated)).isTrue();
        }

        @Test
        void throwsValidationWithCountOnly_whenCallerMayNotListRaProfiles() throws Exception {
            // given
            var firstRaProfileName = "first-ra";
            var secondRaProfileName = "second-ra";
            UUID activated = createProfile("est-activated");
            activateEstOnNewRaProfile(firstRaProfileName, activated);
            activateEstOnNewRaProfile(secondRaProfileName, activated);
            denyResourceAccess(Resource.RA_PROFILE, ResourceAction.LIST);
            SecuredUUID activatedUuid = SecuredUUID.fromUUID(activated);

            // when
            ThrowingCallable deleteActivatedProfile = () -> estProfileService.deleteEstProfile(activatedUuid);

            // then
            assertThatThrownBy(deleteActivatedProfile)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("Cannot remove as there are associated RA Profiles (2)")
                    .hasMessageNotContaining(firstRaProfileName)
                    .hasMessageNotContaining(secondRaProfileName);
            assertThat(estProfileRepository.existsById(activated)).isTrue();
        }

        /**
         * The RA Profiles the caller may list are asked for before the profile is locked, so the authorization service
         * is never waited for while a delete holds the profile.
         */
        @Test
        void asksForListableRaProfilesWithoutHoldingTheProfile_whenBulkDeleting() throws Exception {
            // given
            UUID activated = createProfile("est-activated");
            activateEstOnNewRaProfile("devices-ra", activated);
            SecuredUUID free = SecuredUUID.fromUUID(createProfile("est-free"));
            List<SecuredUUID> bulk = List.of(SecuredUUID.fromUUID(activated), free);
            List<Long> sessionsHoldingAProfile = stubObjectAccessCountingSessionsHoldingAProfile(Resource.RA_PROFILE,
                    ResourceAction.LIST);

            // when
            estProfileService.bulkDeleteEstProfiles(bulk);

            // then
            assertThat(sessionsHoldingAProfile).containsExactly(0L);
            assertThat(estProfileRepository.existsById(activated)).isTrue();
            assertThat(estProfileRepository.existsById(free.getValue())).isFalse();
        }

        @Test
        void deletesProfileWithItsAttributesAndAssociations_whenNoRaProfileHasItActivated() throws Exception {
            // given
            EstProfileDetailDto created = estProfileService
                    .createEstProfile(anEstProfileRequest()
                            .withCustomAttributes(List.of(createCustomAttribute("estOwner", "PKI team")))
                            .withCertificateAssociations(createAssociations(UUID.randomUUID()))
                            .build(), ORIGIN);
            UUID uuid = UUID.fromString(created.getUuid());
            assertThat(attributeEngine.getObjectCustomAttributesContent(Resource.EST_PROFILE, uuid)).isNotEmpty();
            assertThat(certificateAssociationsRepository.count()).isEqualTo(1);

            // when
            estProfileService.deleteEstProfile(SecuredUUID.fromUUID(uuid));

            // then
            assertThat(estProfileRepository.existsById(uuid)).isFalse();
            assertThat(attributeEngine.getObjectCustomAttributesContent(Resource.EST_PROFILE, uuid)).isEmpty();
            assertThat(certificateAssociationsRepository.count()).isZero();
        }

        @Test
        void deletesProfileAfterDeactivatingRaProfiles_whenForceDeleting() throws Exception {
            // given
            UUID uuid = createProfile("est-devices");
            RaProfile raProfile = activateEstOnNewRaProfile("devices-ra", uuid);
            List<SecuredUUID> forceDeleted = List.of(SecuredUUID.fromUUID(uuid));

            // when
            List<BulkActionMessageDto> messages = estProfileService.forceDeleteEstProfiles(forceDeleted);

            // then
            assertThat(messages).isEmpty();
            assertThat(estProfileRepository.existsById(uuid)).isFalse();
            assertThat(raProfileRepository.findById(raProfile.getUuid()).orElseThrow().getEstProfileUuid()).isNull();
            assertThat(loadEstIssueCertificateAttributes(raProfile)).isNull();
        }

        /**
         * An RA Profile can be activated with another EST Profile while the delete waits for its row. It keeps that
         * activation: the delete takes only the RA Profiles that still have the deleted profile once their locks are
         * held.
         */
        @Test
        void leavesRaProfileActivatedWithAnotherProfile_whenItIsActivatedWhileForceDeleteWaits() throws Exception {
            // given
            UUID deleted = createProfile("est-deleted");
            UUID other = createProfile("est-other");
            RaProfile raProfile = activateEstOnNewRaProfile("devices-ra", deleted);
            List<SecuredUUID> forceDeleted = List.of(SecuredUUID.fromUUID(deleted));

            // when
            List<BulkActionMessageDto> messages = runWhileAnActivationHoldsTheRaProfile(raProfile.getUuid(), other,
                    () -> estProfileService.forceDeleteEstProfiles(forceDeleted));

            // then
            assertThat(messages).isEmpty();
            assertThat(estProfileRepository.existsById(deleted)).isFalse();
            assertThat(raProfileRepository.findById(raProfile.getUuid()).orElseThrow().getEstProfileUuid())
                    .isEqualTo(other);
            assertThat(loadEstIssueCertificateAttributes(raProfile)).isEqualTo("[]");
        }

        @Test
        void reportsFailurePerProfile_whenBulkDeleteIsRefusedForSome() throws Exception {
            // given
            var activatedName = "est-activated";
            var raProfileName = "devices-ra";
            UUID activated = createProfile(activatedName);
            UUID free = createProfile("est-free");
            activateEstOnNewRaProfile(raProfileName, activated);
            List<SecuredUUID> bulk = List.of(SecuredUUID.fromUUID(activated), SecuredUUID.fromUUID(free));

            // when
            List<BulkActionMessageDto> messages = estProfileService.bulkDeleteEstProfiles(bulk);

            // then
            assertThat(messages).singleElement().satisfies(failure -> {
                assertThat(failure.getUuid()).isEqualTo(activated.toString());
                assertThat(failure.getName()).isEqualTo(activatedName);
                assertThat(failure.getMessage()).contains("associated RA Profiles (1): " + raProfileName);
            });
            assertThat(estProfileRepository.existsById(activated)).isTrue();
            assertThat(estProfileRepository.existsById(free)).isFalse();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /**
         * Runs the operation on another thread while a transaction of this thread holds an uncommitted activation of
         * the EST Profile on the RA Profile, and commits it once a statement of the operation waits for it.
         */
        private <T> T runWhileAnActivationHoldsTheRaProfile(UUID raProfileUuid, UUID estProfileUuid,
                Callable<T> operation) throws Exception {
            SecurityContext context = SecurityContextHolder.getContext();
            ExecutorService executor = Executors.newSingleThreadExecutor();
            T result;
            try {
                Future<T> waiting = transactionTemplate.execute(status -> {
                    RaProfile activated = raProfileRepository.findById(raProfileUuid).orElseThrow();
                    activated.setEstProfile(estProfileRepository.findById(estProfileUuid).orElseThrow());
                    raProfileRepository.saveAndFlush(activated);
                    Future<T> submitted = executor.submit(bindToCaller(context, operation));
                    awaitAStatementBlockedBy(loadTransactionBackendPid(), "ra_profile");
                    return submitted;
                });
                result = waiting.get(30, TimeUnit.SECONDS);
            } finally {
                executor.shutdownNow();
            }
            assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
            return result;
        }

        private String loadEstIssueCertificateAttributes(RaProfile raProfile) {
            return jdbcTemplate
                    .queryForObject(
                            "SELECT est_issue_certificate_attributes FROM " + dbSchema
                                    + ".ra_profile_protocol_attribute WHERE ra_profile_uuid = ?",
                            String.class, raProfile.getUuid());
        }
    }

    // ── BulkFailureLogging ────────────────────────────────────────────────────

    @Nested
    class BulkFailureLogging {

        private final ListAppender<ILoggingEvent> appender = new ListAppender<>();
        private final Logger logger = (Logger) LoggerFactory.getLogger(EstProfileServiceImpl.class);

        @BeforeEach
        void captureServiceLog() {
            appender.start();
            logger.addAppender(appender);
        }

        @AfterEach
        void releaseServiceLog() {
            logger.detachAppender(appender);
            appender.stop();
        }

        /** A refusal the platform shaped is expected in a bulk request: a warning with the profile and the reason. */
        @Test
        void logsWarningsWithoutTrace_whenBulkDeleteRefusesProfiles() throws Exception {
            // given
            var raProfileName = "devices-ra";
            UUID activated = createProfile("est-activated");
            activateEstOnNewRaProfile(raProfileName, activated);
            var unknown = SecuredUUID.fromUUID(UUID.randomUUID());
            List<SecuredUUID> refused = List.of(SecuredUUID.fromUUID(activated), unknown);

            // when
            estProfileService.bulkDeleteEstProfiles(refused);

            // then
            assertThat(appender.list).isNotEmpty().allSatisfy(event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getThrowableProxy()).isNull();
            });
            assertThat(appender.list)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .satisfiesExactly(message -> assertThat(message)
                            .isEqualTo("Could not delete EST Profile " + activated
                                    + ": Cannot remove as there are associated RA Profiles (1): " + raProfileName),
                            message -> assertThat(message)
                                    .startsWith("Could not delete EST Profile " + unknown + ": ")
                                    .endsWith("is not found."));
        }

        /** A refusal the platform shaped is expected in a bulk request: a warning with the profile and the reason. */
        @Test
        void logsWarningWithoutTrace_whenBulkEnableMeetsAnUnknownProfile() {
            // given
            var unknown = SecuredUUID.fromUUID(UUID.randomUUID());
            List<SecuredUUID> unknownOnly = List.of(unknown);

            // when
            estProfileService.bulkEnableEstProfiles(unknownOnly);

            // then
            assertThat(appender.list).isNotEmpty().allSatisfy(event -> {
                assertThat(event.getLevel()).isEqualTo(Level.WARN);
                assertThat(event.getThrowableProxy()).isNull();
            });
            assertThat(appender.list)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .satisfiesExactly(message -> assertThat(message)
                            .startsWith("Could not enable EST Profile " + unknown + ": ")
                            .endsWith("is not found."));
        }
    }

    // ── EnableAndDisable ──────────────────────────────────────────────────────

    @Nested
    class EnableAndDisable {

        @Test
        void enablesProfile_whenEnablingOne() throws Exception {
            // given
            var enabledName = "est-a";
            SecuredUUID toEnable = SecuredUUID.fromUUID(saveProfile(enabledName, false));
            saveProfile("est-b", false);

            // when
            estProfileService.enableEstProfile(toEnable);

            // then
            assertThat(loadEnabledNames()).containsExactly(enabledName);
        }

        @Test
        void disablesProfile_whenDisablingOne() throws Exception {
            // given
            SecuredUUID toDisable = SecuredUUID.fromUUID(saveProfile("est-a", true));
            saveProfile("est-b", false);

            // when
            estProfileService.disableEstProfile(toDisable);

            // then
            assertThat(loadEnabledNames()).isEmpty();
        }

        @Test
        void enablesKnownProfiles_whenBulkEnablingWithAnUnknownOne() {
            // given
            var firstName = "est-a";
            var secondName = "est-b";
            SecuredUUID first = SecuredUUID.fromUUID(saveProfile(firstName, false));
            SecuredUUID second = SecuredUUID.fromUUID(saveProfile(secondName, false));
            List<SecuredUUID> bothAndAnUnknown = List.of(first, SecuredUUID.fromUUID(UUID.randomUUID()), second);

            // when
            estProfileService.bulkEnableEstProfiles(bothAndAnUnknown);

            // then
            assertThat(loadEnabledNames()).containsExactlyInAnyOrder(firstName, secondName);
        }

        @Test
        void disablesKnownProfiles_whenBulkDisablingWithAnUnknownOne() {
            // given
            SecuredUUID first = SecuredUUID.fromUUID(saveProfile("est-a", true));
            SecuredUUID second = SecuredUUID.fromUUID(saveProfile("est-b", true));
            List<SecuredUUID> bothAndAnUnknown = List.of(first, SecuredUUID.fromUUID(UUID.randomUUID()), second);

            // when
            estProfileService.bulkDisableEstProfiles(bothAndAnUnknown);

            // then
            assertThat(loadEnabledNames()).isEmpty();
        }

        /**
         * Enabling reads the profile under the row lock, so an update committed while it waited survives the whole-row
         * write that follows.
         */
        @Test
        void keepsUpdate_whenItIsCommittedWhileTheEnableWaits() throws Exception {
            // given
            UUID uuid = createProfile("est-devices");
            Operation enable = () -> estProfileService.enableEstProfile(SecuredUUID.fromUUID(uuid));

            // when
            runWhileAnUpdateHoldsTheRow(uuid, enable);

            // then
            EstProfile stored = estProfileRepository.findById(uuid).orElseThrow();
            assertThat(stored.isEnabled()).isTrue();
            assertThat(stored.getDescription())
                    .describedAs("the update committed while the enable waited")
                    .isEqualTo(CHANGED_MEANWHILE);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private UUID saveProfile(String name, boolean enabled) {
            return estProfileRepository.save(anEstProfile().withName(name).withEnabled(enabled).build()).getUuid();
        }

        private List<String> loadEnabledNames() {
            return jdbcTemplate
                    .queryForList("SELECT name FROM " + dbSchema + ".est_profile WHERE enabled", String.class);
        }
    }

    // ── UpdateRaProfile ───────────────────────────────────────────────────────

    @Nested
    class UpdateRaProfile {

        @Test
        void setsDefaultRaProfile_whenItIsChanged() throws Exception {
            // given
            var newDefaultName = "servers-ra";
            RaProfile before = saveRaProfile("devices-ra");
            RaProfile after = saveRaProfile(newDefaultName);
            EstProfileDetailDto created = estProfileService
                    .createEstProfile(anEstProfileRequest().withRaProfile(before.getUuid()).build(), ORIGIN);
            SecuredUUID uuid = SecuredUUID.fromString(created.getUuid());

            // when
            estProfileService.updateRaProfile(uuid, after.getUuid());

            // then
            assertThat(estProfileService.getEstProfile(uuid, ORIGIN).getRaProfile().getName())
                    .isEqualTo(newDefaultName);
        }

        /** The RA Profile is authorized by its own read, never as one of the EST Profiles the update is checked on. */
        @Test
        void doesNotCheckRaProfileAsEstProfile_whenSettingTheDefault() throws Exception {
            // given
            RaProfile raProfile = saveRaProfile("devices-ra");
            UUID uuid = createProfile("est-devices");
            denyResourceAccess(Resource.EST_PROFILE, ResourceAction.UPDATE, raProfile.getUuid());

            // when
            estProfileService.updateRaProfile(SecuredUUID.fromUUID(uuid), raProfile.getUuid());

            // then
            assertThat(estProfileRepository.findById(uuid).orElseThrow().getRaProfileUuid())
                    .isEqualTo(raProfile.getUuid());
        }

        @Test
        void throwsAccessDenied_whenCallerCannotSeeTheRaProfile() throws Exception {
            // given
            UUID raProfileUuid = saveRaProfile("devices-ra").getUuid();
            UUID uuid = createProfile("est-devices");
            SecuredUUID securedUuid = SecuredUUID.fromUUID(uuid);
            denyResourceAccess(Resource.RA_PROFILE, ResourceAction.DETAIL);

            // when
            ThrowingCallable setRaProfileWithoutDetailAccess = () -> estProfileService
                    .updateRaProfile(securedUuid, raProfileUuid);

            // then
            assertThatThrownBy(setRaProfileWithoutDetailAccess).isInstanceOf(AccessDeniedException.class);
            assertThat(estProfileRepository.findById(uuid).orElseThrow().getRaProfileUuid()).isNull();
        }

        @Test
        void keepsUpdate_whenItIsCommittedWhileTheRaProfileChangeWaits() throws Exception {
            // given
            UUID raProfileUuid = saveRaProfile("devices-ra").getUuid();
            UUID uuid = createProfile("est-devices");
            Operation changeRaProfile = () -> estProfileService
                    .updateRaProfile(SecuredUUID.fromUUID(uuid), raProfileUuid);

            // when
            runWhileAnUpdateHoldsTheRow(uuid, changeRaProfile);

            // then
            EstProfile stored = estProfileRepository.findById(uuid).orElseThrow();
            assertThat(stored.getRaProfileUuid()).isEqualTo(raProfileUuid);
            assertThat(stored.getDescription())
                    .describedAs("the update committed while the RA Profile change waited")
                    .isEqualTo(CHANGED_MEANWHILE);
        }
    }

    // ── ReadEstProfiles ───────────────────────────────────────────────────────

    @Nested
    class ReadEstProfiles {

        @Test
        void returnsDetail_whenProfileHasRaProfileAndCustomAttributes() throws Exception {
            // given
            var profileName = "est-devices";
            var raProfileName = "devices-ra";
            var ownerAttributeName = "estOwner";
            RequestAttributeV3 owner = createCustomAttribute(ownerAttributeName, "PKI team");
            RaProfile raProfile = saveRaProfile(raProfileName);
            EstProfileDetailDto created = estProfileService
                    .createEstProfile(anEstProfileRequest()
                            .withName(profileName)
                            .withRaProfile(raProfile.getUuid())
                            .withCustomAttributes(List.of(owner))
                            .build(), ORIGIN);
            SecuredUUID uuid = SecuredUUID.fromString(created.getUuid());

            // when
            EstProfileDetailDto read = estProfileService.getEstProfile(uuid, ORIGIN);

            // then
            assertThat(read.getEstUrl()).isEqualTo(ORIGIN + "/.well-known/est/" + profileName);
            assertThat(read.getRaProfile().getName()).isEqualTo(raProfileName);
            assertThat(read.getCustomAttributes())
                    .extracting(ResponseAttribute::getName)
                    .containsExactly(ownerAttributeName);
        }

        @Test
        void returnsEveryProfile_whenCallerMayListThem() throws Exception {
            // given
            var firstName = "est-a";
            var secondName = "est-b";
            createProfile(firstName);
            createProfile(secondName);

            // when
            List<EstProfileDto> profiles = estProfileService.listEstProfiles(SecurityFilter.create(), ORIGIN);

            // then
            assertThat(profiles).extracting(EstProfileDto::getName).containsExactlyInAnyOrder(firstName, secondName);
        }
    }

    // ── ResourceObjects ───────────────────────────────────────────────────────

    @Nested
    class ResourceObjects {

        private static final String PROFILE_NAME = "est-devices";

        private UUID profileUuid;

        @BeforeEach
        void createEstDevicesProfile() throws Exception {
            profileUuid = createProfile(PROFILE_NAME);
        }

        @Test
        void returnsNameAndUuid_whenGettingTheResourceObjectInternally() throws Exception {
            // given — the profile created by createEstDevicesProfile()
            var expected = new NameAndUuidDto(profileUuid, PROFILE_NAME);

            // when
            NameAndUuidDto resourceObject = estProfileInternalService.getResourceObjectInternal(profileUuid);

            // then
            assertThat(resourceObject).isEqualTo(expected);
        }

        @Test
        void returnsNameAndUuid_whenGettingTheResourceObjectExternally() throws Exception {
            // given — the profile created by createEstDevicesProfile()
            var expected = new NameAndUuidDto(profileUuid, PROFILE_NAME);

            // when
            NameAndUuidDto resourceObject = estProfileInternalService
                    .getResourceObjectExternal(SecuredUUID.fromUUID(profileUuid));

            // then
            assertThat(resourceObject).isEqualTo(expected);
        }

        @Test
        void listsNameAndUuidOfEveryProfile_whenListingResourceObjects() {
            // given — the profile created by createEstDevicesProfile()
            var expected = new NameAndUuidDto(profileUuid, PROFILE_NAME);

            // when
            List<NameAndUuidDto> resourceObjects = estProfileInternalService
                    .listResourceObjects(SecurityFilter.create(), List.of(), null);

            // then
            assertThat(resourceObjects).containsExactly(expected);
        }

        @Test
        void doesNotThrow_whenEvaluatingThePermissionChainOfTheProfile() {
            // given — the profile created by createEstDevicesProfile()
            SecuredUUID uuid = SecuredUUID.fromUUID(profileUuid);

            // when
            ThrowingCallable evaluatePermissionChain = () -> estProfileInternalService.evaluatePermissionChain(uuid);

            // then
            assertThatCode(evaluatePermissionChain).doesNotThrowAnyException();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private UUID createProfile(String name) throws Exception {
        EstProfileDetailDto created = estProfileService
                .createEstProfile(anEstProfileRequest().withName(name).build(), ORIGIN);
        return UUID.fromString(created.getUuid());
    }

    /** Activates EST on a new RA Profile as an activation leaves it: the profile set and issue attributes stored. */
    private RaProfile activateEstOnNewRaProfile(String raProfileName, UUID estProfileUuid) {
        RaProfile raProfile = saveRaProfile(raProfileName);
        raProfile.setEstProfile(estProfileRepository.findById(estProfileUuid).orElseThrow());
        raProfileRepository.save(raProfile);
        RaProfileProtocolAttribute protocolAttribute = new RaProfileProtocolAttribute();
        protocolAttribute.setRaProfile(raProfile);
        protocolAttribute.setEstIssueCertificateAttributes("[]");
        raProfileProtocolAttributeRepository.save(protocolAttribute);
        return raProfile;
    }

    private RaProfile saveRaProfile(String name) {
        RaProfile raProfile = new RaProfile();
        raProfile.setName(name);
        raProfile.setEnabled(true);
        return raProfileRepository.save(raProfile);
    }

    private UUID saveSecret(String name, SecretType type, boolean enabled) {
        VaultInstance vaultInstance = new VaultInstance();
        vaultInstance.setName("vault-" + name);
        vaultInstanceRepository.save(vaultInstance);
        VaultProfile vaultProfile = new VaultProfile();
        vaultProfile.setName("vault-profile-" + name);
        vaultProfile.setVaultInstance(vaultInstance);
        vaultProfile.setVaultInstanceUuid(vaultInstance.getUuid());
        vaultProfile.setEnabled(true);
        vaultProfileRepository.save(vaultProfile);
        SecretVersion version = new SecretVersion();
        version.setVersion(1);
        version.setVaultProfile(vaultProfile);
        version.setFingerprint("fingerprint-" + name);
        secretVersionRepository.save(version);
        Secret secret = new Secret();
        secret.setName(name);
        secret.setType(type);
        secret.setState(SecretState.ACTIVE);
        secret.setSourceVaultProfile(vaultProfile);
        secret.setEnabled(enabled);
        secret.setLatestVersion(version);
        return secretRepository.save(secret).getUuid();
    }

    private RequestAttributeV3 createCustomAttribute(String name, String value) throws AttributeException {
        CustomAttributeV3 definition = new CustomAttributeV3();
        definition.setUuid(UUID.randomUUID().toString());
        definition.setName(name);
        definition.setType(AttributeType.CUSTOM);
        definition.setContentType(AttributeContentType.STRING);
        CustomAttributeProperties properties = new CustomAttributeProperties();
        properties.setLabel(name);
        definition.setProperties(properties);
        attributeEngine.updateCustomAttributeDefinition(definition, List.of(Resource.EST_PROFILE));
        return new RequestAttributeV3(UUID.fromString(definition.getUuid()), name, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3(value)));
    }

    private static ProtocolCertificateAssociationsRequestDto createAssociations(UUID owner) {
        ProtocolCertificateAssociationsRequestDto associations = new ProtocolCertificateAssociationsRequestDto();
        associations.setOwnerUuid(owner);
        return associations;
    }

    private static List<Object> readContentData(ResponseAttribute attribute) {
        List<? extends AttributeContent> content = attribute.getContent();
        return content.stream().<Object>map(AttributeContent::getData).toList();
    }

    private static <T> Callable<T> bindToCaller(SecurityContext context, Callable<T> call) {
        return () -> {
            SecurityContextHolder.setContext(context);
            try {
                return call.call();
            } finally {
                SecurityContextHolder.clearContext();
            }
        };
    }

    /**
     * Runs the operation on another thread while a transaction of this thread holds an uncommitted change of the
     * profile, and commits that change once the operation waits for it.
     */
    private void runWhileAnUpdateHoldsTheRow(UUID uuid, Operation operation) throws Exception {
        SecurityContext context = SecurityContextHolder.getContext();
        ExecutorService executor = Executors.newSingleThreadExecutor();
        try {
            Future<Object> waiting = transactionTemplate.execute(status -> {
                EstProfile changed = estProfileRepository.findById(uuid).orElseThrow();
                changed.setDescription(CHANGED_MEANWHILE);
                estProfileRepository.saveAndFlush(changed);
                Future<Object> submitted = executor.submit(bindToCaller(context, () -> {
                    operation.run();
                    return null;
                }));
                awaitAnEstProfileStatementBlockedBy(loadTransactionBackendPid());
                return submitted;
            });
            waiting.get(30, TimeUnit.SECONDS);
        } finally {
            executor.shutdownNow();
        }
        assertThat(executor.awaitTermination(30, TimeUnit.SECONDS)).isTrue();
    }

    /**
     * The database backend of the transaction this runs in. Asked through the entity manager because the JDBC template
     * does not join that transaction and would answer for a connection of its own.
     */
    private int loadTransactionBackendPid() {
        return ((Number) entityManager.createNativeQuery("SELECT pg_backend_pid()").getSingleResult()).intValue();
    }

    private void awaitAnEstProfileStatementBlockedBy(int lockHolderPid) {
        awaitAStatementBlockedBy(lockHolderPid, "est_profile");
    }

    /**
     * Waits until a statement naming the table is blocked by the given backend, so neither a waiting transaction of
     * another test nor one of a background job can end the wait.
     */
    private void awaitAStatementBlockedBy(int lockHolderPid, String table) {
        Awaitility.await().atMost(Duration.ofSeconds(10)).until(() -> jdbcTemplate.queryForObject("""
                SELECT count(*) FROM pg_stat_activity
                 WHERE ? = ANY(pg_blocking_pids(pid)) AND query ILIKE ?
                """, Long.class, lockHolderPid, "%" + table + "%") >= 1);
    }

    /**
     * Answers each request for the objects the caller may access with the action on the resource as the default stub
     * does, once it has counted the sessions that wait idle in transaction holding a lock on est_profile. Counted on
     * another thread, so the count is not taken on the caller's own connection.
     */
    private List<Long> stubObjectAccessCountingSessionsHoldingAProfile(Resource resource, ResourceAction action) {
        List<Long> counts = new CopyOnWriteArrayList<>();
        OpaObjectAccessResult allowed = new OpaObjectAccessResult();
        allowed.setActionAllowedForGroupOfObjects(true);
        allowed.setAllowedObjects(List.of());
        allowed.setForbiddenObjects(List.of());
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && resource.getCode().equals(req.getProperties().get("name"))
                                        && action.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenAnswer(invocation -> {
                    counts
                            .add(CompletableFuture
                                    .supplyAsync(this::countSessionsInTransactionHoldingAProfile)
                                    .get(10, TimeUnit.SECONDS));
                    return allowed;
                });
        return counts;
    }

    private long countSessionsInTransactionHoldingAProfile() {
        return jdbcTemplate.queryForObject("""
                SELECT count(DISTINCT a.pid)
                  FROM pg_stat_activity a
                  JOIN pg_locks l ON l.pid = a.pid AND l.granted AND l.locktype = 'relation'
                 WHERE a.datname = current_database()
                   AND a.state = 'idle in transaction'
                   AND l.relation = to_regclass(?)
                """, Long.class, dbSchema + ".est_profile");
    }

    @FunctionalInterface
    private interface Operation {
        void run() throws Exception;
    }
}
