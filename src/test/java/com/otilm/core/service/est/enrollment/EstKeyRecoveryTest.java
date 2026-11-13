package com.otilm.core.service.est.enrollment;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.cryptography.key.KeyExportRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestDto;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyItemDetailDto;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.attribute.SignatureAlgorithmMapping;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.est.EstProfile;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.ExportedKeyMaterial;
import com.otilm.core.model.crypto.ImmutableTokenProfileBasicModel;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.service.CryptographicKeyExportExternalService;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.enrollment.EstKeyRecovery.TokenKey;
import com.otilm.core.service.est.message.EstServerKeyGenerationRequest.Content;
import com.otilm.core.util.CertificateRequestUtils;
import com.otilm.core.util.ExportEnvelopeFixtures;
import com.otilm.core.util.PkiFixtures;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.Security;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicReference;
import java.util.stream.Stream;
import javax.security.auth.x500.X500Principal;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstKeyRecoveryTest {

    private static final String LABEL = "devices";
    private static final String KEY_ATTRIBUTE_NAME = "curve";

    @Mock
    private CryptographicKeyExternalService keyService;

    @Mock
    private CryptographicKeyExportExternalService keyExportService;

    @Mock
    private CryptographicOperationInternalService cryptographicOperationService;

    @Mock
    private TokenProfileRepository tokenProfileRepository;

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger recoveryLogger = (Logger) LoggerFactory.getLogger(EstKeyRecovery.class);
    private Level previousLevel;
    private boolean previousAdditive;

    private EstKeyRecovery keyRecovery;
    private final KeyPair tokenKeyPair = PkiFixtures.keyPair();
    private TokenKey tokenKey;

    @BeforeAll
    static void registerBouncyCastle() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    /** The logger is a process-wide singleton, so what is set on it here is taken off again after each test. */
    @BeforeEach
    void createKeyRecoveryAndCaptureTheLog() {
        keyRecovery = new EstKeyRecovery(keyService, keyExportService, cryptographicOperationService,
                tokenProfileRepository);
        tokenKey = new TokenKey(UUID.randomUUID(), UUID.randomUUID(), UUID.randomUUID(),
                SubjectPublicKeyInfo.getInstance(tokenKeyPair.getPublic().getEncoded()));
        previousLevel = recoveryLogger.getLevel();
        previousAdditive = recoveryLogger.isAdditive();
        recoveryLogger.setLevel(Level.DEBUG);
        recoveryLogger.setAdditive(false);
        logged.start();
        recoveryLogger.addAppender(logged);
    }

    @AfterEach
    void releaseTheLog() {
        recoveryLogger.detachAppender(logged);
        recoveryLogger.setLevel(previousLevel);
        recoveryLogger.setAdditive(previousAdditive);
    }

    // ── Create ────────────────────────────────────────────────────────────────

    @Nested
    class Create {

        private final UUID tokenProfileUuid = UUID.randomUUID();
        private final UUID tokenUuid = UUID.randomUUID();

        @BeforeEach
        void stubTheTokenProfile() {
            when(tokenProfileRepository.findBasicModelByUuid(tokenProfileUuid))
                    .thenReturn(Optional
                            .of(new ImmutableTokenProfileBasicModel(tokenProfileUuid, "recovery", null, "token",
                                    tokenUuid, true, List.of())));
        }

        @Test
        void createsAnExportableKeyPairWithTheStoredAttributes_whenCreating() throws Exception {
            // given
            var storedAttribute = keyAttribute("secp256r1");
            EstRoute route = routeRecoveringOn(tokenProfileUuid, List.of(storedAttribute));
            ArgumentCaptor<KeyRequestDto> request = ArgumentCaptor.forClass(KeyRequestDto.class);
            when(keyService
                    .createKey(eq(tokenUuid), argThat(profile -> profile.getValue().equals(tokenProfileUuid)),
                            eq(KeyRequestType.KEY_PAIR), request.capture()))
                    .thenReturn(createdKey(tokenKeyPair));

            // when
            keyRecovery.create(route);

            // then
            KeyRequestDto created = request.getValue();
            assertThat(created.getName()).matches("est-" + LABEL + "-[0-9a-f-]{36}");
            assertThat(created.getExportable()).isTrue();
            assertThat(created.getEnabled()).isTrue();
            assertThat(created.getAttributes())
                    .singleElement()
                    .satisfies(attribute -> assertThat(attribute.getName()).isEqualTo(KEY_ATTRIBUTE_NAME));
        }

        @Test
        void returnsTheKeyItsPrivateItemAndPublicKey_whenTheKeyIsCreated() throws Exception {
            // given
            EstRoute route = routeRecoveringOn(tokenProfileUuid, List.of());
            KeyDetailDto created = createdKey(tokenKeyPair);
            when(keyService.createKey(eq(tokenUuid), any(SecuredParentUUID.class), any(), any())).thenReturn(created);

            // when
            TokenKey key = keyRecovery.create(route);

            // then
            assertThat(key.keyUuid()).hasToString(created.getUuid());
            assertThat(key.privateKeyItemUuid()).hasToString(itemOf(created, KeyType.PRIVATE_KEY).getUuid());
            assertThat(key.tokenProfileUuid()).isEqualTo(tokenProfileUuid);
            assertThat(key.publicKey())
                    .isEqualTo(SubjectPublicKeyInfo.getInstance(tokenKeyPair.getPublic().getEncoded()));
        }

        @Test
        void destroysTheKeyAgain_whenTheCreatedKeyHoldsNoPublicKey() throws Exception {
            // given
            EstRoute route = routeRecoveringOn(tokenProfileUuid, List.of());
            KeyDetailDto created = createdKey(tokenKeyPair);
            created.setItems(List.of(itemOf(created, KeyType.PRIVATE_KEY)));
            when(keyService.createKey(eq(tokenUuid), any(SecuredParentUUID.class), any(), any())).thenReturn(created);

            // when
            ThrowingCallable create = () -> keyRecovery.create(route);

            // then
            assertThatThrownBy(create).isInstanceOf(IllegalStateException.class);
            verify(keyService).destroyKey(List.of(created.getUuid()));
        }
    }

    // ── SignRequest ───────────────────────────────────────────────────────────

    @Nested
    class SignRequest {

        @Test
        void signsForTheClientsContentWithTheDefaultAlgorithmOfTheKey_whenSigning() throws Exception {
            // given
            var subject = new X500Name("CN=device-1");
            var tokenSigned = requestSignedBy(tokenKeyPair, subject);
            when(cryptographicOperationService
                    .generateCsr(eq(tokenKey.keyUuid()), eq(tokenKey.tokenProfileUuid()),
                            eq(new X500Principal("CN=device-1")), isNull(),
                            argThat(attributes -> SignatureAlgorithmMapping
                                    .toAlgorithm(attributes) == SignatureAlgorithm.SHA256_WITH_ECDSA),
                            isNull(), isNull(), isNull()))
                    .thenReturn(CertificateRequestUtils.byteArrayCsrToString(tokenSigned));

            // when
            Pkcs10CertificateRequest request = keyRecovery.signRequest(tokenKey, new Content(subject, null));

            // then
            assertThat(request.getEncoded()).isEqualTo(tokenSigned);
        }

        @ParameterizedTest
        @MethodSource("keysAndTheirDefaultAlgorithms")
        void selectsTheDefaultSignatureAlgorithmOfTheKey_whenTheKeyIsOfASigningType(SubjectPublicKeyInfo key,
                SignatureAlgorithm defaultAlgorithm) throws Exception {
            // given — a key of the type

            // when
            List<RequestAttribute> attributes = EstKeyRecovery.signatureAttributesOf(key);

            // then
            assertThat(SignatureAlgorithmMapping.toAlgorithm(attributes)).isEqualTo(defaultAlgorithm);
        }

        @Test
        void throwsNoSignatureAlgorithm_whenThePlatformSignsWithNoAlgorithmOfTheKey() throws Exception {
            // given
            var falcon512 = publicKeyOf("Falcon-512");

            // when
            ThrowingCallable select = () -> EstKeyRecovery.signatureAttributesOf(falcon512);

            // then
            assertThatThrownBy(select).isInstanceOf(EstKeyRecovery.NoSignatureAlgorithmException.class);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        static Stream<Arguments> keysAndTheirDefaultAlgorithms() throws Exception {
            return Stream
                    .of(arguments(publicKeyOf("RSA"), SignatureAlgorithm.SHA256_WITH_RSA),
                            arguments(SubjectPublicKeyInfo.getInstance(PkiFixtures.keyPair().getPublic().getEncoded()),
                                    SignatureAlgorithm.SHA256_WITH_ECDSA),
                            arguments(publicKeyOf("ML-DSA-65"), SignatureAlgorithm.ML_DSA_65),
                            arguments(publicKeyOf("SLH-DSA-SHA2-128F"), SignatureAlgorithm.SLH_DSA_SHA2_128F));
        }

        private static SubjectPublicKeyInfo publicKeyOf(String algorithm) throws Exception {
            KeyPairGenerator generator = KeyPairGenerator.getInstance(algorithm, BouncyCastleProvider.PROVIDER_NAME);
            return SubjectPublicKeyInfo.getInstance(generator.generateKeyPair().getPublic().getEncoded());
        }

        private static byte[] requestSignedBy(KeyPair keyPair, X500Name subject) throws Exception {
            return new JcaPKCS10CertificationRequestBuilder(subject, keyPair.getPublic())
                    .build(new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate()))
                    .getEncoded();
        }
    }

    // ── Export ────────────────────────────────────────────────────────────────

    @Nested
    class Export {

        @Test
        void returnsThePrivateKeyOfTheExportUnderTheSentPassphrase_whenExporting() throws Exception {
            // given
            exportUnderTheSentPassphrase(tokenKeyPair);

            // when
            PrivateKeyInfo exported = keyRecovery.export(tokenKey);

            // then
            assertThat(exported.getEncoded()).isEqualTo(tokenKeyPair.getPrivate().getEncoded());
        }

        @Test
        void clearsThePassphraseAndOverwritesTheEnvelope_whenTheExportIsOpened() throws Exception {
            // given
            Exchange exchange = exportUnderTheSentPassphrase(tokenKeyPair);

            // when
            keyRecovery.export(tokenKey);

            // then
            assertThat(exchange.passphrase().get().characters()).isEmpty();
            assertThat(exchange.envelope().get()).containsOnly(0);
        }

        @Test
        void clearsThePassphraseAndOverwritesTheEnvelope_whenTheExportCannotBeOpened() throws Exception {
            // given
            Exchange exchange = exportUnder("not-the-sent-passphrase".toCharArray());

            // when
            ThrowingCallable export = () -> keyRecovery.export(tokenKey);

            // then
            assertThatThrownBy(export).isInstanceOf(ValidationException.class);
            assertThat(exchange.passphrase().get().characters()).isEmpty();
            assertThat(exchange.envelope().get()).containsOnly(0);
        }

        @Test
        void clearsThePassphrase_whenTheConnectorFailsTheExport() throws Exception {
            // given
            AtomicReference<Passphrase> sent = new AtomicReference<>();
            when(keyExportService.exportKey(eq(tokenKey.keyUuid()), eq(tokenKey.privateKeyItemUuid()), any()))
                    .thenAnswer(invocation -> {
                        sent.set(invocation.<KeyExportRequestDto>getArgument(2).getPassphrase());
                        throw new ConnectorException("export failed");
                    });

            // when
            ThrowingCallable export = () -> keyRecovery.export(tokenKey);

            // then
            assertThatThrownBy(export).isInstanceOf(ConnectorException.class);
            assertThat(sent.get().characters()).isEmpty();
        }

        @Test
        void returnsNoPublicKey_whenTheExportedKeyCannotBeRead() {
            // given
            var damagedEcKey = PrivateKeyInfo.getInstance(tokenKeyPair.getPrivate().getEncoded());
            Arrays.fill(damagedEcKey.getPrivateKey().getOctets(), (byte) 0);

            // when
            Optional<PublicKey> publicKey = keyRecovery.publicKeyOf(damagedEcKey);

            // then
            assertThat(publicKey).isEmpty();
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /** What the connector was sent and what it answered, to check after the export. */
        private record Exchange(AtomicReference<Passphrase> passphrase, AtomicReference<byte[]> envelope) {
        }

        private Exchange exportUnderTheSentPassphrase(KeyPair keyPair) throws Exception {
            return export(keyPair, null);
        }

        private Exchange exportUnder(char[] otherPassphrase) throws Exception {
            return export(tokenKeyPair, otherPassphrase);
        }

        private Exchange export(KeyPair keyPair, char[] otherPassphrase) throws Exception {
            Exchange exchange = new Exchange(new AtomicReference<>(), new AtomicReference<>());
            when(keyExportService.exportKey(eq(tokenKey.keyUuid()), eq(tokenKey.privateKeyItemUuid()), any()))
                    .thenAnswer(invocation -> {
                        Passphrase passphrase = invocation.<KeyExportRequestDto>getArgument(2).getPassphrase();
                        exchange.passphrase().set(passphrase);
                        char[] protecting = otherPassphrase != null ? otherPassphrase : passphrase.characters();
                        byte[] envelope = ExportEnvelopeFixtures.pinnedEnvelope(keyPair.getPrivate(), protecting);
                        exchange.envelope().set(envelope);
                        return new ExportedKeyMaterial("private", envelope);
                    });
            return exchange;
        }
    }

    // ── Destroy ───────────────────────────────────────────────────────────────

    @Nested
    class Destroy {

        @Test
        void destroysTheKeyOnceAndLogsItWithTheCertificate_whenDestroying() throws Exception {
            // given
            var certificateUuid = UUID.randomUUID();

            // when
            keyRecovery.destroy(certificateUuid, tokenKey);

            // then
            verify(keyService).destroyKey(List.of(tokenKey.keyUuid().toString()));
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.WARN)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .singleElement()
                    .satisfies(line -> assertThat(line)
                            .contains(tokenKey.keyUuid().toString(), certificateUuid.toString()));
        }

        @Test
        void logsTheFailureByItsClassWithoutThrowing_whenTheKeyCannotBeDestroyed() throws Exception {
            // given
            doThrow(new ConnectorException("token says no")).when(keyService).destroyKey(any());

            // when
            ThrowingCallable destroy = () -> keyRecovery.destroy(null, tokenKey);

            // then
            assertThatCode(destroy).doesNotThrowAnyException();
            assertThat(logged.list)
                    .filteredOn(event -> event.getLevel() == Level.ERROR)
                    .extracting(ILoggingEvent::getFormattedMessage)
                    .singleElement()
                    .satisfies(line -> assertThat(line)
                            .contains(tokenKey.keyUuid().toString(), ConnectorException.class.getName())
                            .doesNotContain("token says no"));
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static EstRoute routeRecoveringOn(UUID tokenProfileUuid, List<RequestAttribute> keyAttributes)
            throws Exception {
        EstProfile estProfile = anEstProfile()
                .withUuid(UUID.randomUUID())
                .withServerKeyGeneration(true)
                .withKeyRecovery(true)
                .withKeyRecoveryKeyAttributes(keyAttributes.isEmpty()
                        ? null
                        : ObjectMapperFactory.storage().writeValueAsString(keyAttributes))
                .build();
        estProfile.setKeyRecoveryTokenProfileUuid(tokenProfileUuid);
        return new EstRoute(estProfile, new RaProfile(), false, LABEL);
    }

    private static RequestAttribute keyAttribute(String value) {
        return new RequestAttributeV2(UUID.randomUUID(), KEY_ATTRIBUTE_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV2(value)));
    }

    private static KeyDetailDto createdKey(KeyPair keyPair) {
        KeyItemDetailDto privateKey = new KeyItemDetailDto();
        privateKey.setUuid(UUID.randomUUID().toString());
        privateKey.setType(KeyType.PRIVATE_KEY);
        KeyItemDetailDto publicKey = new KeyItemDetailDto();
        publicKey.setUuid(UUID.randomUUID().toString());
        publicKey.setType(KeyType.PUBLIC_KEY);
        publicKey.setKeyData(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));
        KeyDetailDto key = new KeyDetailDto();
        key.setUuid(UUID.randomUUID().toString());
        key.setItems(List.of(privateKey, publicKey));
        return key;
    }

    private static KeyItemDetailDto itemOf(KeyDetailDto key, KeyType type) {
        return key.getItems().stream().filter(item -> item.getType() == type).findFirst().orElseThrow();
    }
}
