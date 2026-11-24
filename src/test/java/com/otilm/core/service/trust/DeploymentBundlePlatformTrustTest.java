package com.otilm.core.service.trust;

import com.otilm.api.model.client.trustedcertificate.PlatformBundleCertificateDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformSource;
import com.otilm.core.config.TrustedCertificatesConfig;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.provisioning.ProvisioningApplyStatusDTO;
import com.otilm.core.util.CertificateUtil;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;
import java.util.function.Consumer;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeploymentBundlePlatformTrustTest {

    @Mock
    private TrustedCertificatesConfig config;

    private DeploymentBundlePlatformTrust manager;

    @BeforeEach
    void createManager() {
        manager = new DeploymentBundlePlatformTrust(config);
    }

    @Test
    void isNotManaged_whenTrustIsSetInTheDeployment() {
        // given — the bundle manager never changes platform trust

        // when
        boolean managed = manager.isManaged();

        // then
        assertThat(managed).isFalse();
    }

    @Test
    void reportsTheDeploymentAsTheSource_whenTheDeploymentProvidesABundle() throws Exception {
        // given
        when(config.getTrustedCertificates()).thenReturn(List.of(testRootCa()));

        // when
        TrustedCertificatePlatformSource source = manager.source();

        // then
        assertThat(source).isEqualTo(TrustedCertificatePlatformSource.DEPLOYMENT);
    }

    @Test
    void reportsNoSource_whenTheDeploymentProvidesNoBundle() {
        // given
        when(config.getTrustedCertificates()).thenReturn(List.of());

        // when
        TrustedCertificatePlatformSource source = manager.source();

        // then
        assertThat(source).isEqualTo(TrustedCertificatePlatformSource.NONE);
    }

    @Test
    void listsTheParsedBundle_whenTheDeploymentProvidesOne() throws Exception {
        // given
        X509Certificate root = testRootCa();
        when(config.getTrustedCertificates()).thenReturn(List.of(root));

        // when
        List<PlatformBundleCertificateDto> bundle = manager.bundle();

        // then
        assertThat(bundle).singleElement().satisfies(certificate -> {
            assertThat(certificate.getSubject()).isEqualTo("CN=Test Root CA");
            assertThat(certificate.getIssuer()).isEqualTo("CN=Test Root CA");
            assertThat(certificate.getSerialNumber()).isEqualTo(root.getSerialNumber().toString(16));
            assertThat(certificate.getFingerprint()).isEqualTo(CertificateUtil.getThumbprint(root));
            assertThat(certificate.getNotAfter()).isNotNull();
        });
    }

    @Test
    void listsNoBundle_whenTheDeploymentProvidesNone() {
        // given
        when(config.getTrustedCertificates()).thenReturn(List.of());

        // when
        List<PlatformBundleCertificateDto> bundle = manager.bundle();

        // then
        assertThat(bundle).isEmpty();
    }

    @ParameterizedTest
    @MethodSource("changesToPlatformTrust")
    void refusesTheChange_whenTrustIsSetInTheDeployment(Consumer<DeploymentBundlePlatformTrust> change) {
        // given — the bundle comes from the deployment configuration

        // when
        ThrowingCallable changePlatformTrust = () -> change.accept(manager);

        // then
        assertThatThrownBy(changePlatformTrust)
                .isInstanceOf(PlatformTrustNotManagedException.class)
                .hasMessageContaining("Platform trust is set in the deployment configuration");
    }

    @Test
    void listsNoPlatformRecords_whenTrustIsSetInTheDeployment() {
        // given — the bundle manager keeps no platform records

        // when
        List<PlatformRecord> records = manager.list();

        // then
        assertThat(records).isEmpty();
    }

    @Test
    void reportsNoApplyStatus_whenTrustIsSetInTheDeployment() {
        // given — the bundle manager never applies

        // when
        Optional<ProvisioningApplyStatusDTO> status = manager.applyStatus();

        // then
        assertThat(status).isEmpty();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Named<Consumer<DeploymentBundlePlatformTrust>>> changesToPlatformTrust() {
        return Stream
                .of(named("create", platformTrust -> platformTrust.create("pem")),
                        named("delete", platformTrust -> platformTrust.delete("p1")),
                        named("apply", DeploymentBundlePlatformTrust::apply));
    }

    private static X509Certificate testRootCa() throws Exception {
        return CertificateGeneratorHelper.generateCACertificate(null, "CN=Test Root CA");
    }
}
