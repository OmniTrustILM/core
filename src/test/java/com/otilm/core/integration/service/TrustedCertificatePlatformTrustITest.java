package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformSource;
import com.otilm.api.model.client.trustedcertificate.TrustedCertificatePlatformState;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.provisioning.ProvisioningApplyResponseDTO;
import com.otilm.core.provisioning.ProvisioningException;
import com.otilm.core.service.trust.PlatformRecord;
import com.otilm.core.service.trust.PlatformTrustManager;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.WireMockPorts;
import com.otilm.core.util.X509ObjectToString;
import java.nio.charset.StandardCharsets;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TrustedCertificatePlatformTrustITest extends BaseSpringBootTest {

    private static final String BASE_PATH = "/api/v1/trusted-certificates";

    @RegisterExtension
    static WireMockExtension wireMockServer = WireMockExtension
            .newInstance()
            .options(wireMockConfig().port(WireMockPorts.PROVISIONING_API))
            .build();

    @Autowired
    private PlatformTrustManager manager;

    private X509Certificate certificate;
    private String pem;
    private String contentBase64;

    @BeforeEach
    void generateCertificate() throws Exception {
        certificate = CertificateGeneratorHelper.generateCACertificate(null, "CN=Platform Trust CA");
        pem = X509ObjectToString.toPem(certificate);
        contentBase64 = Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.US_ASCII));
    }

    @Test
    void isManagedFromProvisioning_whenTheSwitchIsOn() {
        // given — the test configuration sets provisioning.trusted-certificates.enabled

        // when
        boolean managed = manager.isManaged();

        // then
        assertThat(managed).isTrue();
        assertThat(manager.source()).isEqualTo(TrustedCertificatePlatformSource.PROVISIONING);
        assertThat(manager.bundle()).isEmpty();
    }

    @Test
    void returnsTheStoredRecord_whenCreating() throws Exception {
        // given
        wireMockServer
                .stubFor(post(urlPathEqualTo(BASE_PATH)).willReturn(okJson(item("p1", "pending")).withStatus(201)));

        // when
        PlatformRecord created = manager.create(pem);

        // then
        assertThat(created.uuid()).isEqualTo("p1");
        assertThat(created.fingerprintSha256()).isEqualTo(CertificateUtil.getThumbprint(certificate));
        assertThat(created.state()).isEqualTo(TrustedCertificatePlatformState.PENDING);
    }

    @Test
    void adoptsTheExistingRecordByFingerprint_whenCreateConflicts() {
        // given
        wireMockServer
                .stubFor(post(urlPathEqualTo(BASE_PATH))
                        .willReturn(aResponse()
                                .withStatus(409)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"Certificate already exists\",\"uuid\":\"p1\"}")));
        wireMockServer.stubFor(get(urlPathEqualTo(BASE_PATH)).willReturn(okJson("[" + item("p1", "applied") + "]")));

        // when
        PlatformRecord adopted = manager.create(pem);

        // then
        assertThat(adopted.uuid()).isEqualTo("p1");
        assertThat(adopted.state()).isEqualTo(TrustedCertificatePlatformState.APPLIED);
    }

    @Test
    void returnsNoDeployment_whenOlderProvisioningHasNoApply() {
        // given
        wireMockServer.stubFor(post(urlPathEqualTo(BASE_PATH + "/apply")).willReturn(aResponse().withStatus(404)));

        // when
        Optional<ProvisioningApplyResponseDTO> deployment = manager.apply();

        // then
        assertThat(deployment).isEmpty();
    }

    @Test
    void returnsNoStatus_whenOlderProvisioningHasNoApply() {
        // given
        wireMockServer.stubFor(get(urlPathEqualTo(BASE_PATH + "/apply")).willReturn(aResponse().withStatus(404)));

        // when
        var status = manager.applyStatus();

        // then
        assertThat(status).isEmpty();
    }

    @Test
    void mapsAMissingStateToUnknownWithAReason_whenListing() {
        // given
        wireMockServer
                .stubFor(get(urlPathEqualTo(BASE_PATH))
                        .willReturn(okJson("[{\"uuid\":\"p1\",\"certificateContent\":\"" + contentBase64 + "\"}]")));

        // when
        List<PlatformRecord> listed = manager.list();

        // then
        assertThat(listed).singleElement().satisfies(record -> {
            assertThat(record.state()).isEqualTo(TrustedCertificatePlatformState.UNKNOWN);
            assertThat(record.message()).isEqualTo("Platform reports no state");
        });
    }

    @Test
    void mapsRemovalFailed_whenListing() {
        // given
        wireMockServer
                .stubFor(get(urlPathEqualTo(BASE_PATH)).willReturn(okJson("[" + item("p1", "removalFailed") + "]")));

        // when
        List<PlatformRecord> listed = manager.list();

        // then
        assertThat(listed).singleElement().satisfies(record -> {
            assertThat(record.state()).isEqualTo(TrustedCertificatePlatformState.REMOVAL_FAILED);
            assertThat(record.message()).isNull();
        });
    }

    @Test
    void treatsNotFoundAsDone_whenDeleting() {
        // given
        wireMockServer.stubFor(delete(urlPathEqualTo(BASE_PATH + "/p1")).willReturn(aResponse().withStatus(404)));

        // when
        ThrowingCallable deleteGone = () -> manager.delete("p1");

        // then
        assertThatNoException().isThrownBy(deleteGone);
    }

    @Test
    void throwsProvisioningException_whenListingFails() {
        // given
        wireMockServer.stubFor(get(urlPathEqualTo(BASE_PATH)).willReturn(aResponse().withStatus(500)));

        // when
        ThrowingCallable list = () -> manager.list();

        // then
        assertThatThrownBy(list).isInstanceOf(ProvisioningException.class);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private String item(String uuid, String state) {
        return "{\"uuid\":\"%s\",\"certificateContent\":\"%s\",\"state\":\"%s\"}".formatted(uuid, contentBase64, state);
    }
}
