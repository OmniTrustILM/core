package com.otilm.core.service.handler;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class KeystoreAvailabilityTest {

    private static final UUID PROFILE_UUID = UUID.randomUUID();

    private static final UUID TOKEN_UUID = UUID.randomUUID();

    private final KeyTransferCapabilityService capabilityService = mock(KeyTransferCapabilityService.class);

    private final TokenProfileRepository tokenProfileRepository = mock(TokenProfileRepository.class);

    private final KeystoreAvailability availability = new KeystoreAvailability(capabilityService,
            tokenProfileRepository);

    @AfterEach
    void capabilityOfIsNeverCalled() {
        verify(capabilityService, never()).capabilityOf(any());
    }

    @Test
    void of_isAvailableForAnExportableKeyThatItsProfileExports() {
        Certificate certificate = exportableCertificate(KeyAlgorithm.RSA);
        profileExports(Map.of(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)));

        assertThat(availability.of(certificate)).isTrue();
    }

    @Test
    void of_isUnavailableWithoutAKey() {
        assertThat(availability.of(new Certificate())).isFalse();
        verifyNoInteractions(capabilityService, tokenProfileRepository);
    }

    @Test
    void of_isUnavailableForAKeyThatCannotBeExportedNow() {
        Certificate certificate = certificateWithKey(privateItem(false, KeyState.ACTIVE, true), publicItem("fp"), "fp");

        assertThat(availability.of(certificate)).isFalse();
        verifyNoInteractions(capabilityService, tokenProfileRepository);
    }

    @Test
    void of_isUnavailableForAKeyThatDoesNotHoldTheCertificatesPublicKey() {
        Certificate certificate = certificateWithKey(privateItem(true, KeyState.ACTIVE, true), publicItem("fp"),
                "else");

        assertThat(availability.of(certificate)).isFalse();
    }

    @Test
    void of_isUnavailableWhenTheProfileDoesNotExportTheAlgorithm() {
        Certificate certificate = exportableCertificate(KeyAlgorithm.RSA);
        profileExports(Map.of(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.ECDSA)));

        assertThat(availability.of(certificate)).isFalse();
    }

    @Test
    void of_isUnavailableWhenTheConnectorCannotSayWhatItExports() {
        Certificate certificate = exportableCertificate(KeyAlgorithm.RSA);
        profileExports(Map.of());

        assertThat(availability.of(certificate)).isFalse();
    }

    @Test
    void of_isAvailableWhileTheProfilesAnswerIsNotRecorded() {
        Certificate certificate = exportableCertificate(KeyAlgorithm.RSA);
        profileAnswers(Optional.empty());

        assertThat(availability.of(certificate)).isTrue();
    }

    @Test
    void of_isUnavailableWhenTheKeysProfileIsGone() {
        Certificate certificate = exportableCertificate(KeyAlgorithm.RSA);
        when(tokenProfileRepository.findFullModelByUuidAndTokenInstanceReferenceUuid(PROFILE_UUID, TOKEN_UUID))
                .thenReturn(Optional.empty());

        assertThat(availability.of(certificate)).isFalse();
        verifyNoInteractions(capabilityService);
    }

    @Test
    void of_isUnavailableForACertificateNotIssuedYet() {
        Certificate certificate = exportableCertificate(KeyAlgorithm.RSA);
        certificate.setCertificateContent(null);

        assertThat(availability.of(certificate)).isFalse();
        verifyNoInteractions(capabilityService, tokenProfileRepository);
    }

    private void profileExports(Map<KeyRequestType, Set<KeyAlgorithm>> exportableKeyTypes) {
        profileAnswers(Optional.of(exportableKeyTypes));
    }

    private void profileAnswers(Optional<Map<KeyRequestType, Set<KeyAlgorithm>>> recordedExportableKeyTypes) {
        TokenProfileFullModel profile = mock(TokenProfileFullModel.class);
        when(tokenProfileRepository.findFullModelByUuidAndTokenInstanceReferenceUuid(PROFILE_UUID, TOKEN_UUID))
                .thenReturn(Optional.of(profile));
        when(capabilityService.recordedExportableKeyTypes(profile)).thenReturn(recordedExportableKeyTypes);
    }

    private static Certificate exportableCertificate(KeyAlgorithm algorithm) {
        return certificateWithKey(privateItem(true, KeyState.ACTIVE, true, algorithm), publicItem("fp"), "fp");
    }

    private static Certificate certificateWithKey(CryptographicKeyItem privateItem, CryptographicKeyItem publicItem,
            String publicKeyFingerprint) {
        CryptographicKey key = new CryptographicKey();
        key.setUuid(UUID.randomUUID());
        key.setTokenProfileUuid(PROFILE_UUID);
        key.setTokenInstanceReferenceUuid(TOKEN_UUID);
        key.setItems(Set.of(privateItem, publicItem));
        Certificate certificate = new Certificate();
        certificate.setKey(key);
        certificate.setPublicKeyFingerprint(publicKeyFingerprint);
        certificate.setCertificateContent(new CertificateContent());
        return certificate;
    }

    private static CryptographicKeyItem privateItem(boolean exportable, KeyState state, boolean enabled) {
        return privateItem(exportable, state, enabled, KeyAlgorithm.RSA);
    }

    private static CryptographicKeyItem privateItem(boolean exportable, KeyState state, boolean enabled,
            KeyAlgorithm algorithm) {
        CryptographicKeyItem item = item(KeyType.PRIVATE_KEY);
        item.setExportable(exportable);
        item.setState(state);
        item.setEnabled(enabled);
        item.setKeyAlgorithm(algorithm);
        return item;
    }

    private static CryptographicKeyItem publicItem(String fingerprint) {
        CryptographicKeyItem item = item(KeyType.PUBLIC_KEY);
        item.setFingerprint(fingerprint);
        item.setState(KeyState.ACTIVE);
        item.setEnabled(true);
        return item;
    }

    private static CryptographicKeyItem item(KeyType type) {
        CryptographicKeyItem item = new CryptographicKeyItem();
        item.setUuid(UUID.randomUUID());
        item.setType(type);
        return item;
    }
}
