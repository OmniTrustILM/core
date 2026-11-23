package com.otilm.core.certificate.type;

import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.core.dao.entity.RaProfile;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthorityCertificateTypesTest {

    private final AuthorityCertificateTypes authorityCertificateTypes = new AuthorityCertificateTypes();

    @Test
    void acceptsX509_whenTheAuthorityReportsNoTypes() {
        // given
        RaProfile raProfile = createRaProfile("profile");

        // when
        ThrowingCallable check = () -> authorityCertificateTypes.requireSupport(CertificateType.X509, raProfile);

        // then
        assertThatCode(check).doesNotThrowAnyException();
    }

    @Test
    void treatsAMissingTypeAsX509_whenCheckingTheAuthority() {
        // given
        RaProfile raProfile = createRaProfile("profile");

        // when
        ThrowingCallable check = () -> authorityCertificateTypes.requireSupport(null, raProfile);

        // then
        assertThatCode(check).doesNotThrowAnyException();
    }

    @Test
    void refusesTheTypeNamingTheRaProfile_whenTheAuthorityDoesNotIssueIt() {
        // given
        String raProfileName = "x509-only-profile";
        CertificateType notIssued = CertificateType.SSH;
        RaProfile raProfile = createRaProfile(raProfileName);

        // when
        ThrowingCallable check = () -> authorityCertificateTypes.requireSupport(notIssued, raProfile);

        // then
        assertThatThrownBy(check)
                .isInstanceOf(UnsupportedCertificateTypeException.class)
                .hasMessageContaining(notIssued.getCode())
                .hasMessageContaining(raProfileName);
    }

    // ── Helpers ──────────────────────────────────────────────────────────────

    private static RaProfile createRaProfile(String name) {
        var raProfile = new RaProfile();
        raProfile.setName(name);
        return raProfile;
    }
}
