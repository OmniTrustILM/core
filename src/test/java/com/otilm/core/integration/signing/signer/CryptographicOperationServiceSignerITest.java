package com.otilm.core.integration.signing.signer;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.properties.MetadataAttributeProperties;
import com.otilm.api.model.common.attribute.v3.MetadataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.core.connector.v2.ConnectorDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyDetailDto;
import com.otilm.api.model.core.cryptography.key.KeyItemDetailDto;
import com.otilm.api.model.core.cryptography.token.TokenInstanceDetailDto;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDetailDto;
import com.otilm.core.attribute.SignatureAlgorithmMapping;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.integration.service.V2TokenFixture;
import com.otilm.core.integration.service.V2TokenFixture.V2Token;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.otilm.core.service.CryptographicOperationInternalService;
import com.otilm.core.service.TokenInstanceExternalService;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.service.v2.ConnectorExternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.signer.CryptographicOperationServiceSigner;
import com.otilm.core.signing.engine.signer.Signer;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderConnectorMock;
import com.otilm.core.util.seeders.CryptographicKeySeeder;
import com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.ConnectorRequestDtoBuilder.aV1ConnectorRequest;
import static com.otilm.core.util.builders.KeyPairRequestDtoBuilder.aKeyPairRequest;
import static com.otilm.core.util.builders.TokenInstanceRequestDtoBuilder.aTokenInstanceRequest;
import static com.otilm.core.util.builders.TokenProfileRequestDtoBuilder.aTokenProfileRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Signs multi-item batches through the real v1 and v2 provider adapters against real-signing providers.
 */
class CryptographicOperationServiceSignerITest extends BaseSpringBootTest {

    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.SHA256_WITH_RSA;

    /** Four items. A reversed answer moves every one of them. */
    private static final List<byte[]> BATCH = Stream
            .of("first", "second", "third", "fourth")
            .map(item -> item.getBytes(StandardCharsets.UTF_8))
            .toList();

    @Autowired
    private CryptographicOperationInternalService cryptographicOperationService;
    @Autowired
    private ConnectorMockFactory connectorMockFactory;
    @Autowired
    private ConnectorExternalService connectorService;
    @Autowired
    private TokenInstanceExternalService tokenInstanceService;
    @Autowired
    private TokenProfileExternalService tokenProfileService;
    @Autowired
    private CryptographicKeyExternalService cryptographicKeyService;
    @Autowired
    private V2TokenFixture v2TokenFixture;
    @Autowired
    private CryptographicKeySeeder keySeeder;

    private KeyPair keyPair;

    @BeforeEach
    void generateKeyPair() throws Exception {
        keyPair = CertificateGeneratorHelper.generateKeyPair(KeyAlgorithm.RSA, null);
    }

    // ── V2Provider ────────────────────────────────────────────────────────────

    @Nested
    class V2Provider {

        private V2Token v2Token;
        private Signer signer;

        @BeforeEach
        void seedV2Key() throws Exception {
            v2Token = v2TokenFixture.start();
            v2Token.connectorMock().stubSignatureAlgorithmAttribute(SIGNATURE_ALGORITHM);
            CryptographicKey key = keySeeder
                    .seedKey("v2-batch-key", v2Token.profile(), v2Token.token(),
                            KeyItemSpec.signingPrivateKey(KeyAlgorithm.RSA).withKeyMeta(List.of(providerHandle())));
            signer = signerFor(v2Token.token().getUuid(), v2Token.profile().getUuid(), key.getUuid(),
                    privateKeyItemUuid(key));
        }

        @AfterEach
        void stopProvider() {
            v2Token.connectorMock().stop();
        }

        @Test
        void returnsEachSignatureForItsItem_whenProviderAnswersInReverseOrder() throws Exception {
            // given
            v2Token.connectorMock().stubRealSigningInReverseOrder(keyPair.getPrivate(), SIGNATURE_ALGORITHM);

            // when
            List<byte[]> signatures = signer.signAll(BATCH);

            // then
            assertEachSignatureVerifiesOverItsItem(signatures, keyPair.getPublic());
            v2Token.connectorMock().verifyOperationRequests("sign", 1);
        }

        @Test
        void throwsSignerFault_whenProviderOmitsIdentifiers() {
            // given
            v2Token.connectorMock().stubRealSigningWithoutIdentifiers(keyPair.getPrivate(), SIGNATURE_ALGORITHM);

            // when
            ThrowingCallable signBatch = () -> signer.signAll(BATCH);

            // then
            assertSignerFault(signBatch, "identifier is required");
            v2Token.connectorMock().verifyOperationRequests("sign", 1);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static UUID privateKeyItemUuid(CryptographicKey key) {
            return key
                    .getItems()
                    .stream()
                    .filter(item -> item.getType() == KeyType.PRIVATE_KEY)
                    .map(CryptographicKeyItem::getUuid)
                    .findFirst()
                    .orElseThrow();
        }

        private static MetadataAttribute providerHandle() {
            MetadataAttributeV3 handle = new MetadataAttributeV3();
            handle.setUuid(UUID.randomUUID().toString());
            handle.setName("provider-handle");
            handle.setType(AttributeType.META);
            handle.setContentType(AttributeContentType.STRING);
            handle.setProperties(new MetadataAttributeProperties());
            handle.setContent(List.of(new StringAttributeContentV3("hsm-batch-key")));
            return handle;
        }
    }

    // ── V1Provider ────────────────────────────────────────────────────────────

    @Nested
    class V1Provider {

        private CryptographyProviderConnectorMock providerMock;
        private Signer signer;

        @BeforeEach
        void createV1Key() throws Exception {
            providerMock = connectorMockFactory.startCryptographyProvider();
            ConnectorDetailDto connector = connectorService
                    .createConnector(
                            aV1ConnectorRequest().withName("v1-batch-provider").withUrl(providerMock.getUrl()).build());
            providerMock.stubTokenInstanceCreation(UUID.randomUUID());
            TokenInstanceDetailDto token = tokenInstanceService
                    .createTokenInstance(aTokenInstanceRequest()
                            .withName("v1-batch-token")
                            .withConnector(connector.getUuid())
                            .build());
            providerMock.stubTokenProfileCreation();
            TokenProfileDetailDto profile = tokenProfileService
                    .createTokenProfile(SecuredParentUUID.fromString(token.getUuid()),
                            aTokenProfileRequest().withName("v1-batch-profile").build());
            UUID privateKeyReference = UUID.randomUUID();
            providerMock
                    .stubKeyPairCreation(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()),
                            KeyAlgorithm.RSA, privateKeyReference)
                    .registerSigningKey(privateKeyReference, keyPair.getPrivate(), SIGNATURE_ALGORITHM);
            KeyDetailDto key = cryptographicKeyService
                    .createKey(UUID.fromString(token.getUuid()), SecuredParentUUID.fromString(profile.getUuid()),
                            KeyRequestType.KEY_PAIR, aKeyPairRequest().withName("v1-batch-key").build());
            signer = signerFor(UUID.fromString(token.getUuid()), UUID.fromString(profile.getUuid()),
                    UUID.fromString(key.getUuid()), privateKeyItemUuid(key));
        }

        @AfterEach
        void stopProvider() {
            providerMock.stop();
        }

        @Test
        void returnsEachSignatureForItsItem_whenProviderAnswersInReverseOrder() throws Exception {
            // given
            providerMock.stubRealSigningInReverseOrder();

            // when
            List<byte[]> signatures = signer.signAll(BATCH);

            // then
            assertEachSignatureVerifiesOverItsItem(signatures, keyPair.getPublic());
            providerMock.verifySignRequests(1);
        }

        @Test
        void throwsSignerFault_whenProviderOmitsIdentifiers() {
            // given
            providerMock.stubRealSigningWithoutIdentifiers();

            // when
            ThrowingCallable signBatch = () -> signer.signAll(BATCH);

            // then
            assertSignerFault(signBatch, "Signing operation returned a result without an identifier");
            providerMock.verifySignRequests(1);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static UUID privateKeyItemUuid(KeyDetailDto key) {
            return key
                    .getItems()
                    .stream()
                    .filter(item -> item.getType() == KeyType.PRIVATE_KEY)
                    .map(KeyItemDetailDto::getUuid)
                    .map(UUID::fromString)
                    .findFirst()
                    .orElseThrow();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private Signer signerFor(UUID tokenUuid, UUID tokenProfileUuid, UUID keyUuid, UUID privateKeyItemUuid) {
        return new CryptographicOperationServiceSigner(cryptographicOperationService,
                SecuredParentUUID.fromUUID(tokenUuid), SecuredUUID.fromUUID(tokenProfileUuid), keyUuid,
                privateKeyItemUuid, SignatureAlgorithmMapping.toAttributes(SIGNATURE_ALGORITHM), SIGNATURE_ALGORITHM);
    }

    private static void assertEachSignatureVerifiesOverItsItem(List<byte[]> signatures, PublicKey publicKey)
            throws Exception {
        assertThat(signatures).hasSameSizeAs(BATCH);
        for (int index = 0; index < BATCH.size(); index++) {
            Signature verifier = Signature.getInstance(SIGNATURE_ALGORITHM.getCode());
            verifier.initVerify(publicKey);
            verifier.update(BATCH.get(index));
            assertThat(verifier.verify(signatures.get(index)))
                    .as("signature %d verifies over item %d", index, index)
                    .isTrue();
        }
    }

    private static void assertSignerFault(ThrowingCallable signBatch, String reason) {
        assertThatThrownBy(signBatch).isInstanceOfSatisfying(SigningEngineException.class, failure -> {
            assertThat(failure.failure()).isEqualTo(SigningEngineFailure.SIGNER_FAULT);
            assertThat(failure.operatorMessage()).contains(reason);
        });
    }
}
