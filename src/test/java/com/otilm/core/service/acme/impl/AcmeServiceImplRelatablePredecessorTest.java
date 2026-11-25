package com.otilm.core.service.acme.impl;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateInternalService;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AcmeServiceImplRelatablePredecessorTest {

    private static final UUID PREDECESSOR_UUID = UUID.randomUUID();

    @Mock
    private CertificateInternalService certificateService;

    private AcmeServiceImpl acmeService;

    @BeforeEach
    void createService() {
        acmeService = new AcmeServiceImpl();
        acmeService.setCertificateService(certificateService);
    }

    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = {"ISSUED", "REVOKED"})
    void returnsThePredecessor_whenItCanBeOne(CertificateState relatableState) throws Exception {
        // given
        stubPredecessorIn(relatableState);

        // when
        UUID relatable = acmeService.relatablePredecessor(PREDECESSOR_UUID);

        // then
        assertThat(relatable).isEqualTo(PREDECESSOR_UUID);
    }

    @ParameterizedTest
    @EnumSource(value = CertificateState.class, names = {"PENDING_REVOKE", "PENDING_ISSUE", "FAILED"})
    void returnsNull_whenThePredecessorIsInAnotherState(CertificateState otherState) throws Exception {
        // given
        stubPredecessorIn(otherState);

        // when
        UUID relatable = acmeService.relatablePredecessor(PREDECESSOR_UUID);

        // then
        assertThat(relatable).isNull();
    }

    @Test
    void returnsNull_whenThePredecessorWasDeleted() throws Exception {
        // given
        when(certificateService.getCertificateEntity(any(SecuredUUID.class)))
                .thenThrow(new NotFoundException(Certificate.class, PREDECESSOR_UUID));

        // when
        UUID relatable = acmeService.relatablePredecessor(PREDECESSOR_UUID);

        // then
        assertThat(relatable).isNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubPredecessorIn(CertificateState state) throws Exception {
        Certificate predecessor = aCertificate().withUuid(PREDECESSOR_UUID).withState(state).build();
        when(certificateService.getCertificateEntity(any(SecuredUUID.class))).thenReturn(predecessor);
    }
}
