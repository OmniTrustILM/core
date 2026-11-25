package com.otilm.core.service.renewal.auto;

import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.certificate.AutoRenewalMode;
import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateLocation;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.Location;
import com.otilm.core.service.renewal.auto.AutoRenewalModeResolver.ModeDecision;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static com.otilm.core.util.builders.CertificateRequestEntityBuilder.aCertificateRequest;
import static com.otilm.core.util.builders.CryptographicKeyBuilder.aCryptographicKey;
import static com.otilm.core.util.builders.CryptographicKeyItemBuilder.aKeyItem;
import static com.otilm.core.util.builders.DataAttributeV3Builder.aDataAttribute;
import static org.assertj.core.api.Assertions.assertThat;

class AutoRenewalModeResolverTest {

    @Test
    void resolvesLocation_whenAKeyGeneratingLocationExistsBesideAHeldKey() {
        // given
        Certificate certificate = heldKeyCertificate(KeyState.ACTIVE, true);
        addLocation(certificate, keyGeneratingLocation(), true, true);

        // when
        ModeDecision decision = AutoRenewalModeResolver.resolve(certificate);

        // then
        assertThat(decision.mode()).isEqualTo(AutoRenewalMode.LOCATION);
        assertThat(decision.blockedReason()).isNull();
    }

    @Test
    void resolvesLocation_whenLocationsRenewedTheCertificateAndItSitsInNone() {
        // given
        Certificate certificate = aCertificate().build();

        // when
        ModeDecision decision = AutoRenewalModeResolver.resolve(certificate, true);

        // then
        assertThat(decision.mode()).isEqualTo(AutoRenewalMode.LOCATION);
        assertThat(decision.blockedReason()).isNull();
    }

    @Test
    void resolvesNoneWithReason_whenTheCertificateTypeDoesNotSupportRenewal() {
        // given
        Certificate certificate = heldKeyCertificate(KeyState.ACTIVE, true);
        var withoutRenew = EnumSet.complementOf(EnumSet.of(CertificateOperation.RENEW));

        // when
        ModeDecision decision = AutoRenewalModeResolver.resolve(certificate, false, withoutRenew);

        // then
        assertThat(decision.mode()).isEqualTo(AutoRenewalMode.NONE);
        assertThat(decision.blockedReason()).isEqualTo(AutoRenewalModeResolver.RENEWAL_NOT_SUPPORTED);
    }

    @Test
    void resolvesIlmKey_whenThePlatformHoldsTheKeyAndTheRequest() {
        // given
        Certificate certificate = heldKeyCertificate(KeyState.ACTIVE, true);

        // when
        ModeDecision decision = AutoRenewalModeResolver.resolve(certificate);

        // then
        assertThat(decision.mode()).isEqualTo(AutoRenewalMode.ILM_KEY);
        assertThat(decision.blockedReason()).isNull();
    }

    @Test
    void resolvesNoneWithReason_whenTheHeldKeyHasNoStoredRequest() {
        // given
        Certificate certificate = heldKeyCertificate(KeyState.ACTIVE, false);

        // when
        ModeDecision decision = AutoRenewalModeResolver.resolve(certificate);

        // then
        assertThat(decision.mode()).isEqualTo(AutoRenewalMode.NONE);
        assertThat(decision.blockedReason()).isEqualTo(AutoRenewalModeResolver.NO_STORED_REQUEST);
    }

    @Test
    void resolvesNoneWithReason_whenThePrivateKeyIsNotActive() {
        // given
        Certificate certificate = heldKeyCertificate(KeyState.DEACTIVATED, true);

        // when
        ModeDecision decision = AutoRenewalModeResolver.resolve(certificate);

        // then
        assertThat(decision.mode()).isEqualTo(AutoRenewalMode.NONE);
        assertThat(decision.blockedReason()).isEqualTo(AutoRenewalModeResolver.NO_KEY);
    }

    @Test
    void resolvesNoneWithReason_whenOnlyPushOnlyLocationsHoldTheCertificate() {
        // given
        Certificate certificate = aCertificate().build();
        addLocation(certificate, keyGeneratingLocation(), true, false);

        // when
        ModeDecision decision = AutoRenewalModeResolver.resolve(certificate);

        // then
        assertThat(decision.mode()).isEqualTo(AutoRenewalMode.NONE);
        assertThat(decision.blockedReason()).isEqualTo(AutoRenewalModeResolver.NO_KEY);
    }

    @Test
    void ignoresALocation_whenItHasNoPushAttributes() {
        // given
        Certificate certificate = aCertificate().build();
        addLocation(certificate, keyGeneratingLocation(), false, true);

        // when
        ModeDecision decision = AutoRenewalModeResolver.resolve(certificate);

        // then
        assertThat(decision.mode()).isEqualTo(AutoRenewalMode.NONE);
    }

    @Test
    void ignoresALocation_whenItDoesNotManageKeys() {
        // given
        Certificate certificate = aCertificate().build();
        Location location = keyGeneratingLocation();
        location.setSupportKeyManagement(false);
        addLocation(certificate, location, true, true);

        // when
        ModeDecision decision = AutoRenewalModeResolver.resolve(certificate);

        // then
        assertThat(decision.mode()).isEqualTo(AutoRenewalMode.NONE);
    }

    @Test
    void ignoresALocation_whenItIsDisabled() {
        // given
        Certificate certificate = aCertificate().build();
        Location location = keyGeneratingLocation();
        location.setEnabled(false);
        addLocation(certificate, location, true, true);

        // when
        ModeDecision decision = AutoRenewalModeResolver.resolve(certificate);

        // then
        assertThat(decision.mode()).isEqualTo(AutoRenewalMode.NONE);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Certificate heldKeyCertificate(KeyState privateKeyState, boolean withRequest) {
        CryptographicKey key = aCryptographicKey().build();
        key.setUuid(UUID.randomUUID());
        key.setItems(Set.of(aKeyItem().withType(KeyType.PRIVATE_KEY).withState(privateKeyState).build()));
        Certificate certificate = aCertificate().withKey(key).withKeyUuid(key.getUuid()).build();
        if (withRequest) {
            certificate.setCertificateRequest(aCertificateRequest().withContent("request").build());
        }
        return certificate;
    }

    private static Location keyGeneratingLocation() {
        Location location = new Location();
        location.setUuid(UUID.randomUUID());
        location.setEnabled(true);
        location.setSupportKeyManagement(true);
        return location;
    }

    private static void addLocation(Certificate certificate, Location location, boolean withPushAttributes,
            boolean withCsrAttributes) {
        CertificateLocation certificateLocation = new CertificateLocation();
        certificateLocation.setLocation(location);
        certificateLocation.setCertificate(certificate);
        if (withPushAttributes) {
            certificateLocation.setPushAttributes(List.of(aDataAttribute().withName("push").build()));
        }
        if (withCsrAttributes) {
            certificateLocation.setCsrAttributes(List.of(aDataAttribute().withName("csr").build()));
        }
        certificate.getLocations().add(certificateLocation);
    }
}
