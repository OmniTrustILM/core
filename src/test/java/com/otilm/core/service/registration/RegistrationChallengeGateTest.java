package com.otilm.core.service.registration;

import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class RegistrationChallengeGateTest {

    private static final UUID CERTIFICATE_UUID = UUID.randomUUID();

    @Mock
    private CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository;

    private RegistrationChallengeGate gate;

    @BeforeEach
    void createGate() {
        gate = new RegistrationChallengeGate();
        gate.setRegistrationAuthorizationRepository(registrationAuthorizationRepository);
    }

    @Test
    void requiresNoChallenge_whenTheCertificateHasNoAuthorization() {
        // given
        when(registrationAuthorizationRepository.findByCertificateUuid(CERTIFICATE_UUID)).thenReturn(Optional.empty());

        // when
        boolean required = gate.requiresChallenge(CERTIFICATE_UUID);

        // then
        assertThat(required).isFalse();
    }

    @Test
    void requiresNoChallenge_whenTheAuthorizationIsClosed() {
        // given
        stubAuthorizationIn(RegistrationState.CLOSED);

        // when
        boolean required = gate.requiresChallenge(CERTIFICATE_UUID);

        // then
        assertThat(required).isFalse();
    }

    @ParameterizedTest
    @EnumSource(value = RegistrationState.class, names = "CLOSED", mode = EnumSource.Mode.EXCLUDE)
    void requiresTheChallenge_whenTheAuthorizationIsNotClosed(RegistrationState liveState) {
        // given
        stubAuthorizationIn(liveState);

        // when
        boolean required = gate.requiresChallenge(CERTIFICATE_UUID);

        // then
        assertThat(required).isTrue();
        verify(registrationAuthorizationRepository).findByCertificateUuid(CERTIFICATE_UUID);
        verifyNoMoreInteractions(registrationAuthorizationRepository);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubAuthorizationIn(RegistrationState state) {
        CertificateRegistrationAuthorization authorization = new CertificateRegistrationAuthorization();
        authorization.setCertificateUuid(CERTIFICATE_UUID);
        authorization.setState(state);
        when(registrationAuthorizationRepository.findByCertificateUuid(CERTIFICATE_UUID))
                .thenReturn(Optional.of(authorization));
    }
}
