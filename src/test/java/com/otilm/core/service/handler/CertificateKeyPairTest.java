package com.otilm.core.service.handler;

import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class CertificateKeyPairTest {

    private static final String FINGERPRINT = "public-key-fingerprint";

    @Test
    void of_findsThePrivateAndPublicItems() {
        // given
        Certificate certificate = certificateWithKey(FINGERPRINT, privateItem(true, KeyState.ACTIVE, true),
                publicItem(FINGERPRINT));

        // when
        Optional<CertificateKeyPair> pair = CertificateKeyPair.of(certificate);

        // then
        assertThat(pair).hasValueSatisfying(found -> {
            assertThat(found.key()).isSameAs(certificate.getKey());
            assertThat(found.privateItem().getType()).isEqualTo(KeyType.PRIVATE_KEY);
            assertThat(found.publicItem().getType()).isEqualTo(KeyType.PUBLIC_KEY);
        });
    }

    @Test
    void of_findsNothingForACertificateWithoutAKey() {
        assertThat(CertificateKeyPair.of(new Certificate())).isEmpty();
    }

    @Test
    void of_findsNothingForAKeyWithoutAPrivateItem() {
        // given
        Certificate certificate = certificateWithKey(FINGERPRINT, publicItem(FINGERPRINT));

        // when
        Optional<CertificateKeyPair> pair = CertificateKeyPair.of(certificate);

        // then
        assertThat(pair).isEmpty();
    }

    @Test
    void holds_comparesTheCertificatesPublicKeyWithTheKeys() {
        // given
        Certificate matching = certificateWithKey(FINGERPRINT, privateItem(true, KeyState.ACTIVE, true),
                publicItem(FINGERPRINT));
        Certificate other = certificateWithKey("another-fingerprint", privateItem(true, KeyState.ACTIVE, true),
                publicItem(FINGERPRINT));

        // when
        CertificateKeyPair matchingPair = CertificateKeyPair.of(matching).orElseThrow();
        CertificateKeyPair otherPair = CertificateKeyPair.of(other).orElseThrow();

        // then
        assertThat(matchingPair.holds(matching)).isTrue();
        assertThat(otherPair.holds(other)).isFalse();
    }

    @Test
    void holds_needsAPublicItem() {
        // given
        Certificate certificate = certificateWithKey(FINGERPRINT, privateItem(true, KeyState.ACTIVE, true));

        // when
        CertificateKeyPair pair = CertificateKeyPair.of(certificate).orElseThrow();

        // then
        assertThat(pair.holds(certificate)).isFalse();
    }

    @ParameterizedTest
    @CsvSource({
            "true, ACTIVE, true, true",
            "false, ACTIVE, true, false",
            "true, DEACTIVATED, true, false",
            "true, ACTIVE, false, false"})
    void exportableNow_needsAnExportableActiveEnabledPrivateItem(boolean exportable, KeyState state, boolean enabled,
            boolean expected) {
        // given
        Certificate certificate = certificateWithKey(FINGERPRINT, privateItem(exportable, state, enabled),
                publicItem(FINGERPRINT));

        // when
        CertificateKeyPair pair = CertificateKeyPair.of(certificate).orElseThrow();

        // then
        assertThat(pair.exportableNow()).isEqualTo(expected);
    }

    private static Certificate certificateWithKey(String publicKeyFingerprint, CryptographicKeyItem... items) {
        CryptographicKey key = new CryptographicKey();
        key.setUuid(UUID.randomUUID());
        key.setItems(Set.copyOf(Stream.of(items).toList()));
        Certificate certificate = new Certificate();
        certificate.setKey(key);
        certificate.setPublicKeyFingerprint(publicKeyFingerprint);
        return certificate;
    }

    private static CryptographicKeyItem privateItem(boolean exportable, KeyState state, boolean enabled) {
        CryptographicKeyItem item = item(KeyType.PRIVATE_KEY);
        item.setExportable(exportable);
        item.setState(state);
        item.setEnabled(enabled);
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
