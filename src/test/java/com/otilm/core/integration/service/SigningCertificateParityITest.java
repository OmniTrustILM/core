package com.otilm.core.integration.service;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.oid.SystemOid;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.PqcKeyFixtures;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.otilm.core.util.seeders.CryptographicKeySeeder;
import com.otilm.core.util.seeders.TokenProfileSeeder;
import java.security.PublicKey;
import java.util.Base64;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.filter.annotation.TypeExcludeFilters;
import org.springframework.context.annotation.Import;

import static com.otilm.core.util.PqcKeyFixtures.ML_DSA_PARAMETER_SET;
import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec.signingPrivateKey;
import static com.otilm.core.util.seeders.CryptographicKeySeeder.KeyItemSpec.verifyingPublicKey;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Parity: the cached {@link SigningCertificate} and the per-item {@link CryptographicKeyItemOperationModel} carry the
 * signer inputs stored on the certificate, its key and the key's items.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class SigningCertificateParityITest extends BaseSpringBootTest {

    @Autowired
    private CertificateInternalService certificateService;
    @Autowired
    private CryptographicKeyInternalService cryptographicKeyService;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private TokenProfileSeeder tokenProfileSeeder;
    @Autowired
    private CryptographicKeySeeder cryptographicKeySeeder;

    private TokenProfile tokenProfile;
    private CryptographicKey key;

    @BeforeEach
    void seedMlDsaSigningKey() throws Exception {
        tokenProfile = tokenProfileSeeder.seedTokenProfile();
        String publicKeyBase64 = base64(PqcKeyFixtures.keyPair().getPublic());
        key = cryptographicKeySeeder
                .seedKey("signing-key", tokenProfile, tokenProfile.getTokenInstanceReference(),
                        signingPrivateKey(KeyAlgorithm.MLDSA),
                        verifyingPublicKey(KeyAlgorithm.MLDSA).withMaterial(KeyFormat.SPKI, publicKeyBase64));
    }

    // ── GetSigningCertificate ─────────────────────────────────────────────────

    @Nested
    class GetSigningCertificate {

        @Test
        void returnsEveryStoredColumn_whenEachHoldsANonDefaultValue() throws Exception {
            // given
            String timestampingOid = SystemOid.TIME_STAMPING.getOid();
            var certificate = certificateRepository
                    .saveAndFlush(aCertificate()
                            .withCommonName("parity-test")
                            .withArchived(true)
                            .withState(CertificateState.ISSUED)
                            .withValidationStatus(CertificateValidationStatus.VALID)
                            .withExtendedKeyUsage(timestampingOid)
                            .withExtendedKeyUsageCritical(true)
                            .withQcCompliance(true)
                            .build());

            // when
            SigningCertificate signingCertificate = certificateService.getSigningCertificate(certificate.getUuid());

            // then
            assertThat(signingCertificate)
                    .usingRecursiveComparison()
                    .comparingOnlyFields("uuid", "commonName", "archived", "state", "validationStatus",
                            "extendedKeyUsageCritical", "qcCompliance")
                    .isEqualTo(certificate);
            assertThat(signingCertificate.extendedKeyUsageOids()).containsExactly(timestampingOid);
        }

        @Test
        void referencesKeyTokenAndItems_whenCertificateHasKey() throws Exception {
            // given
            var certificate = certificateRepository.saveAndFlush(aCertificate().withKey(key).build());

            // when
            SigningCertificate signingCertificate = certificateService.getSigningCertificate(certificate.getUuid());

            // then
            assertThat(signingCertificate)
                    .extracting(SigningCertificate::keyUuid, SigningCertificate::tokenInstanceReferenceUuid,
                            SigningCertificate::tokenProfileUuid)
                    .containsExactly(key.getUuid(), tokenProfile.getTokenInstanceReference().getUuid(),
                            tokenProfile.getUuid());
            assertThat(signingCertificate.keyItemUuids())
                    .containsExactlyInAnyOrder(itemOfType(KeyType.PRIVATE_KEY).getUuid(),
                            itemOfType(KeyType.PUBLIC_KEY).getUuid());
        }
    }

    // ── GetKeyItemModel ───────────────────────────────────────────────────────

    @Nested
    class GetKeyItemModel {

        @Test
        void returnsModelWithoutParameterSpec_whenItemIsPrivateKey() throws Exception {
            // given
            CryptographicKeyItem privateItem = itemOfType(KeyType.PRIVATE_KEY);

            // when
            CryptographicKeyItemOperationModel model = cryptographicKeyService.getKeyItemModel(privateItem.getUuid());

            // then
            assertThat(model.keyType()).isEqualTo(KeyType.PRIVATE_KEY);
            assertThat(model.keyAlgorithm()).isEqualTo(KeyAlgorithm.MLDSA);
            assertThat(model.keyState()).isEqualTo(KeyState.ACTIVE);
            assertThat(model.keyUsage()).containsExactly(KeyUsage.SIGN);
            assertThat(model.pqcParameterSpecName()).isNull();
        }

        @Test
        void returnsParameterSpecOfTheKeyData_whenItemIsMlDsaPublicKey() throws Exception {
            // given
            CryptographicKeyItem publicItem = itemOfType(KeyType.PUBLIC_KEY);

            // when
            CryptographicKeyItemOperationModel model = cryptographicKeyService.getKeyItemModel(publicItem.getUuid());

            // then
            assertThat(model.keyType()).isEqualTo(KeyType.PUBLIC_KEY);
            assertThat(model.keyAlgorithm()).isEqualTo(KeyAlgorithm.MLDSA);
            assertThat(model.keyState()).isEqualTo(KeyState.ACTIVE);
            assertThat(model.keyUsage()).containsExactly(KeyUsage.VERIFY);
            assertThat(model.pqcParameterSpecName()).isEqualTo(ML_DSA_PARAMETER_SET);
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private CryptographicKeyItem itemOfType(KeyType type) {
        return key.getItems().stream().filter(item -> item.getType() == type).findFirst().orElseThrow();
    }

    private static String base64(PublicKey publicKey) {
        return Base64.getEncoder().encodeToString(publicKey.getEncoded());
    }
}
