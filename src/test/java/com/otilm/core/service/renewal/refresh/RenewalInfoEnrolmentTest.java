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
        Certificate certificate = certificateUnder(raProfileUsingAuthorityInfo(true));

        // when
        enrolment.enrol(certificate);

        // then
        verify(refreshWriter).reEnrol(eq(certificate.getUuid()), any(), eq(RenewalInfoEnrolment.ENROL_DELAY_SECONDS));
    }

    @Test
    void writesNothing_whenItsRaProfileDoesNotUseTheAuthorityInformation() {
        // given
        Certificate certificate = certificateUnder(raProfileUsingAuthorityInfo(false));

        // when
        enrolment.enrol(certificate);

        // then
        verifyNoInteractions(refreshWriter);
    }

    @Test
    void writesNothing_whenTheCertificateHasNoRaProfile() {
        // given
        Certificate withoutRaProfile = certificateUnder(null);

        // when
        enrolment.enrol(withoutRaProfile);

        // then
        verifyNoInteractions(refreshWriter);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static RaProfile raProfileUsingAuthorityInfo(boolean useAuthorityInfo) {
        RaProfile raProfile = new RaProfile();
        raProfile.setRenewalUseAuthorityInfo(useAuthorityInfo);
        return raProfile;
    }

    private static Certificate certificateUnder(RaProfile raProfile) {
        return aCertificate().withUuid(UUID.randomUUID()).withRaProfile(raProfile).build();
    }
}
