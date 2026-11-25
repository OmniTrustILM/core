package com.otilm.core.service.renewal.refresh;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.SettingInternalService;
import com.otilm.core.service.writer.RenewalRefreshWriter;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.CertificateBuilder.aCertificate;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class RenewalInfoEnrolmentTest {

    @Mock
    private RenewalRefreshWriter refreshWriter;
    @Mock
    private SettingInternalService settingService;

    private RenewalInfoEnrolment enrolment;

    @BeforeEach
    void createEnrolment() {
        enrolment = new RenewalInfoEnrolment(refreshWriter, settingService);
    }

    @Test
    void reEnrolsTheCertificate_whenItsRaProfileUsesTheAuthorityInformation() {
        // given
        Certificate certificate = createCertificateUnder(createRaProfileUsingAuthorityInfo(true));

        // when
        enrolment.enrol(certificate);

        // then
        verify(refreshWriter).reEnrol(eq(certificate.getUuid()), any(), eq(RenewalInfoEnrolment.ENROL_DELAY_SECONDS));
    }

    @Test
    void writesNothing_whenItsRaProfileDoesNotUseTheAuthorityInformation() {
        // given
        Certificate certificate = createCertificateUnder(createRaProfileUsingAuthorityInfo(false));

        // when
        enrolment.enrol(certificate);

        // then
        verifyNoInteractions(refreshWriter);
    }

    @Test
    void writesNothing_whenTheCertificateHasNoRaProfile() {
        // given
        Certificate withoutRaProfile = createCertificateUnder(null);

        // when
        enrolment.enrol(withoutRaProfile);

        // then
        verifyNoInteractions(refreshWriter);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static RaProfile createRaProfileUsingAuthorityInfo(boolean useAuthorityInfo) {
        RaProfile raProfile = new RaProfile();
        raProfile.setRenewalUseAuthorityInfo(useAuthorityInfo);
        return raProfile;
    }

    private static Certificate createCertificateUnder(RaProfile raProfile) {
        return aCertificate().withUuid(UUID.randomUUID()).withRaProfile(raProfile).build();
    }
}
