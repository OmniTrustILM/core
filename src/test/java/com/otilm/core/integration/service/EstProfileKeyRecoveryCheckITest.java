package com.otilm.core.integration.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.attribute.RequestAttributeV3;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.est.EstProfileDetailDto;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.dao.repository.est.EstProfileRepository;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.service.EstProfileExternalService;
import com.otilm.core.service.writer.est.EstProfileWriter;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mocks.ConnectorMockFactory;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import com.otilm.core.util.seeders.TokenProfileSeeder;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import static com.otilm.core.util.builders.EstProfileRequestDtoBuilder.anEstProfileRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * What saving an EST Profile with key recovery checks of its token profile: the connector exports a key pair, the key
 * can sign, and the stored create-key attributes are the ones the connector's definitions accept and no secret.
 */
class EstProfileKeyRecoveryCheckITest extends BaseSpringBootTest {

    private static final String ORIGIN = "https://ilm.example.com";
    private static final String CONNECTOR_TEXT = "refused by the connector";
    private static final String KEY_ATTRIBUTE_NAME = "keyAlgorithm";
    private static final UUID KEY_ATTRIBUTE_UUID = UUID.fromString("5e3f0f7e-3d56-4a41-9a1b-6f0d7c2a8b11");
    private static final String REQUIRED_KEY_ATTRIBUTE = "[{\"uuid\":\"" + KEY_ATTRIBUTE_UUID + "\",\"name\":\""
            + KEY_ATTRIBUTE_NAME + "\",\"type\":\"data\",\"contentType\":\"string\",\"version\":3,"
            + "\"properties\":{\"label\":\"Key algorithm\",\"visible\":true,\"required\":true,\"readOnly\":false,"
            + "\"list\":false,\"multiSelect\":false}}]";

    @Autowired
    private EstProfileWriter estProfileWriter;

    @Autowired
    private EstProfileExternalService estProfileService;

    @Autowired
    private EstProfileRepository estProfileRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    @Autowired
    private TokenProfileSeeder tokenProfiles;

    @Autowired
    private ConnectorMockFactory connectorMockFactory;

    private CryptographyProviderV2ConnectorMock token;

    @BeforeEach
    void startTokenThatCreatesKeysWithAnAlgorithm() {
        token = connectorMockFactory.startCryptographyProviderV2();
        token.stubCreateKeyAttributes(REQUIRED_KEY_ATTRIBUTE);
    }

    @AfterEach
    void stopToken() {
        token.stop();
    }

    @Test
    void savesTheProfile_whenTheTokenProfileExportsKeyPairsAndTheAttributesFit() throws Exception {
        // given
        TokenProfile tokenProfile = tokenProfiles.seedKeyExportingTokenProfile(token.getUrl(), KeyAlgorithm.ECDSA);
        var request = anEstProfileRequest()
                .withKeyRecovery(tokenProfile.getUuid(), List.of(keyAlgorithm("ECDSA")))
                .build();

        // when
        EstProfileDetailDto created = estProfileService.createEstProfile(request, ORIGIN);

        // then
        assertThat(created.getKeyRecoveryTokenProfile().getUuid()).isEqualTo(tokenProfile.getUuid().toString());
        assertThat(estProfileRepository.count()).isEqualTo(1);
    }

    @Test
    void throwsValidation_whenTheConnectorDoesNotSupportKeyExport() {
        // given
        TokenProfile tokenProfile = tokenProfiles.seedTokenProfile();
        var request = anEstProfileRequest().withKeyRecovery(tokenProfile.getUuid(), List.of()).build();

        // when
        ThrowingCallable create = () -> estProfileService.createEstProfile(request, ORIGIN);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("does not support key export");
        assertThat(estProfileRepository.count()).isZero();
    }

    @Test
    void throwsValidation_whenTheTokenProfileDoesNotExportKeyPairs() {
        // given
        TokenProfile tokenProfile = tokenProfiles.seedKeyExportingTokenProfile(token.getUrl(), KeyAlgorithm.ECDSA);
        tokenProfile
                .setExportableKeyTypes(
                        List.of(new TransferableKeyType(KeyRequestType.SECRET, Set.of(KeyAlgorithm.AES))));
        tokenProfileRepository.saveAndFlush(tokenProfile);
        var request = anEstProfileRequest()
                .withKeyRecovery(tokenProfile.getUuid(), List.of(keyAlgorithm("ECDSA")))
                .build();

        // when
        ThrowingCallable create = () -> estProfileService.createEstProfile(request, ORIGIN);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("does not support exporting a key pair");
        assertThat(estProfileRepository.count()).isZero();
    }

    @Test
    void throwsValidation_whenAttributesFailTheConnectorsDefinitions() {
        // given — the definitions require the key algorithm
        TokenProfile tokenProfile = tokenProfiles.seedKeyExportingTokenProfile(token.getUrl(), KeyAlgorithm.ECDSA);
        var request = anEstProfileRequest().withKeyRecovery(tokenProfile.getUuid(), List.of()).build();

        // when
        ThrowingCallable create = () -> estProfileService.createEstProfile(request, ORIGIN);

        // then
        assertThatThrownBy(create).isInstanceOf(ValidationException.class).hasMessageContaining(KEY_ATTRIBUTE_NAME);
        assertThat(estProfileRepository.count()).isZero();
    }

    @Test
    void throwsValidation_whenAnAttributeHoldsSecretContent() {
        // given
        TokenProfile tokenProfile = tokenProfiles.seedKeyExportingTokenProfile(token.getUrl(), KeyAlgorithm.ECDSA);
        var secretName = "keyPin";
        RequestAttribute pin = new RequestAttributeV2(UUID.randomUUID(), secretName, AttributeContentType.SECRET,
                List.of(new SecretAttributeContentV2(null, new SecretAttributeContentData("1234"))));
        var request = anEstProfileRequest()
                .withKeyRecovery(tokenProfile.getUuid(), List.of(keyAlgorithm("ECDSA"), pin))
                .build();

        // when
        ThrowingCallable create = () -> estProfileService.createEstProfile(request, ORIGIN);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("cannot hold secret content: " + secretName);
        assertThat(estProfileRepository.count()).isZero();
    }

    @Test
    void throwsValidation_whenTheTokenProfileDoesNotAllowSigning() {
        // given
        TokenProfile tokenProfile = tokenProfiles.seedKeyExportingTokenProfile(token.getUrl(), KeyAlgorithm.ECDSA);
        tokenProfile.setUsage(List.of(KeyUsage.VERIFY));
        tokenProfileRepository.saveAndFlush(tokenProfile);
        var request = anEstProfileRequest()
                .withKeyRecovery(tokenProfile.getUuid(), List.of(keyAlgorithm("ECDSA")))
                .build();

        // when
        ThrowingCallable create = () -> estProfileService.createEstProfile(request, ORIGIN);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("does not allow the signing usage");
        assertThat(estProfileRepository.count()).isZero();
    }

    @Test
    void throwsValidationWithoutTheConnectorsWords_whenTheConnectorCannotCheckTheAttributes() {
        // given
        TokenProfile tokenProfile = tokenProfiles.seedKeyExportingTokenProfile(token.getUrl(), KeyAlgorithm.ECDSA);
        token.stubCreateKeyAttributesFailing(CONNECTOR_TEXT);
        var request = anEstProfileRequest()
                .withKeyRecovery(tokenProfile.getUuid(), List.of(keyAlgorithm("ECDSA")))
                .build();

        // when
        ThrowingCallable create = () -> estProfileService.createEstProfile(request, ORIGIN);

        // then
        assertThatThrownBy(create)
                .isInstanceOf(ValidationException.class)
                .hasMessageNotContaining(CONNECTOR_TEXT)
                .hasMessageContaining("could not check its export capability and key attributes");
        assertThat(estProfileRepository.count()).isZero();
    }

    @Test
    void throwsValidation_whenTheTokenProfileIsDisabledAfterItWasChecked() {
        // given — the disable committed between the save's check and its transaction
        TokenProfile tokenProfile = tokenProfiles.seedKeyExportingTokenProfile(token.getUrl(), KeyAlgorithm.ECDSA);
        tokenProfile.setEnabled(false);
        tokenProfileRepository.saveAndFlush(tokenProfile);

        // when
        ThrowingCallable lockInSaveTransaction = () -> estProfileWriter
                .requireKeyRecoveryTokenProfileEnabled(tokenProfile.getUuid());

        // then
        assertThatThrownBy(lockInSaveTransaction)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining(tokenProfile.getName() + " is disabled");
    }

    @Test
    void acceptsTheTokenProfile_whenItIsStillEnabledInTheSaveTransaction() {
        // given
        TokenProfile tokenProfile = tokenProfiles.seedKeyExportingTokenProfile(token.getUrl(), KeyAlgorithm.ECDSA);

        // when
        ThrowingCallable lockInSaveTransaction = () -> estProfileWriter
                .requireKeyRecoveryTokenProfileEnabled(tokenProfile.getUuid());

        // then
        assertThatCode(lockInSaveTransaction).doesNotThrowAnyException();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static RequestAttribute keyAlgorithm(String algorithm) {
        return new RequestAttributeV3(KEY_ATTRIBUTE_UUID, KEY_ATTRIBUTE_NAME, AttributeContentType.STRING,
                List.of(new StringAttributeContentV3(algorithm)));
    }
}
