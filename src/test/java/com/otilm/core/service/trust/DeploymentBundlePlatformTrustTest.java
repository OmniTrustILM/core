package com.otilm.core.service.trust;

import com.otilm.api.model.client.trustedcertificate.PlatformBundleCertificateDto;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformSource;
import com.otilm.core.config.TrustedCertificatesConfig;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.util.CertificateUtil;
import java.security.cert.X509Certificate;
import java.util.List;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class DeploymentBundlePlatformTrustTest {

    @Mock
    private TrustedCertificatesConfig config;

    @Test
    void listsTheParsedBundleReadOnly_whenTheDeploymentProvidesOne() throws Exception {
        // given
        X509Certificate root = CertificateGeneratorHelper.generateCACertificate(null, "CN=Test Root CA");
        when(config.getTrustedCertificates()).thenReturn(List.of(root));
        var manager = new DeploymentBundlePlatformTrust(config);

        // when
        List<PlatformBundleCertificateDto> bundle = manager.bundle();

        // then
        assertThat(manager.isManaged()).isFalse();
        assertThat(manager.source()).isEqualTo(TrustedCertificatePlatformSource.DEPLOYMENT);
        assertThat(bundle).singleElement().satisfies(certificate -> {
            assertThat(certificate.getSubject()).isEqualTo("CN=Test Root CA");
            assertThat(certificate.getIssuer()).isEqualTo("CN=Test Root CA");
            assertThat(certificate.getSerialNumber()).isEqualTo(root.getSerialNumber().toString(16));
            assertThat(certificate.getFingerprint()).isEqualTo(CertificateUtil.getThumbprint(root));
            assertThat(certificate.getNotAfter()).isNotNull();
        });
    }

    @Test
    void reportsNoSource_whenTheDeploymentProvidesNoBundle() {
        // given
        when(config.getTrustedCertificates()).thenReturn(List.of());
        var manager = new DeploymentBundlePlatformTrust(config);

        // when
        TrustedCertificatePlatformSource source = manager.source();

        // then
        assertThat(source).isEqualTo(TrustedCertificatePlatformSource.NONE);
        assertThat(manager.bundle()).isEmpty();
    }

    @Test
    void refusesToChangePlatformTrust_whenItIsSetInTheDeployment() {
        // given
        var manager = new DeploymentBundlePlatformTrust(config);

        // when
        ThrowingCallable create = () -> manager.create("pem");

        // then
        assertThatThrownBy(create)
                .isInstanceOf(PlatformTrustNotManagedException.class)
                .hasMessageContaining("Platform trust is set in the deployment configuration");
        assertThatThrownBy(() -> manager.delete("p1")).isInstanceOf(PlatformTrustNotManagedException.class);
        assertThatThrownBy(manager::apply).isInstanceOf(PlatformTrustNotManagedException.class);
        assertThat(manager.list()).isEmpty();
        assertThat(manager.applyStatus()).isEmpty();
    }
}
