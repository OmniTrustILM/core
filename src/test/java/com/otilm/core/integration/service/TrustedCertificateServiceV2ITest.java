package com.otilm.core.integration.service;

import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.NotSupportedException;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateAddRequestDto;
import com.otilm.api.model.client.trustedcertificate.v2.TrustedCertificateDto;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.v2.TrustedCertificateExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.WireMockPorts;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.List;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TrustedCertificateServiceV2ITest extends BaseSpringBootTest {

    private static final String PROVISIONING_UUID = "abfbc322-29e1-11ed-a261-0242ac120002";
    private static final String PROVISIONING_RECORD_JSON = """
            {
                "uuid": "%s",
                "certificateContent": "dGVzdC1jZXJ0aWZpY2F0ZS1jb250ZW50",
                "issuer": "CN=Test CA",
                "san": "DNS:example.com",
                "serialNumber": "1234567890",
                "subject": "CN=example.com",
                "thumbprint": "AB:CD:EF:12:34:56",
                "notBefore": "2024-01-01T00:00:00",
                "notAfter": "2025-12-31T23:59:59"
            }
            """.formatted(PROVISIONING_UUID);

    @RegisterExtension
    static WireMockExtension wireMockServer = WireMockExtension
            .newInstance()
            .options(wireMockConfig().port(WireMockPorts.PROVISIONING_API))
            .build();

    @Autowired
    private TrustedCertificateExternalService trustedCertificateService;

    @Test
    void listsTheProvisioningRecords_whileCoreDoesNotOwnTheTrustList() {
        // given
        wireMockServer
                .stubFor(get(urlPathEqualTo("/api/v1/trusted-certificates"))
                        .willReturn(okJson("[" + PROVISIONING_RECORD_JSON + "]")));

        // when
        List<TrustedCertificateDto> listed = trustedCertificateService.listTrustedCertificates();

        // then
        assertThat(listed).singleElement().satisfies(item -> {
            assertThat(item.getUuid()).isEqualTo(PROVISIONING_UUID);
            assertThat(item.getSubject()).isEqualTo("CN=example.com");
        });
    }

    @Test
    void returnsTheProvisioningRecord_whileCoreDoesNotOwnTheTrustList() throws Exception {
        // given
        wireMockServer
                .stubFor(get(urlPathEqualTo("/api/v1/trusted-certificates/" + PROVISIONING_UUID))
                        .willReturn(okJson(PROVISIONING_RECORD_JSON)));

        // when
        TrustedCertificateDto detail = trustedCertificateService
                .getTrustedCertificate(SecuredUUID.fromString(PROVISIONING_UUID));

        // then
        assertThat(detail.getIssuer()).isEqualTo("CN=Test CA");
        assertThat(detail.getNotAfter()).isEqualTo(OffsetDateTime.of(2025, 12, 31, 23, 59, 59, 0, ZoneOffset.UTC));
        assertThat(detail.getThumbprint()).isNull();
    }

    @Test
    void throwsNotFound_whenProvisioningHasNoSuchRecord() {
        // given
        wireMockServer
                .stubFor(get(urlPathEqualTo("/api/v1/trusted-certificates/" + PROVISIONING_UUID))
                        .willReturn(aResponse().withStatus(404)));

        // when
        ThrowingCallable getMissing = () -> trustedCertificateService
                .getTrustedCertificate(SecuredUUID.fromString(PROVISIONING_UUID));

        // then
        assertThatThrownBy(getMissing).isInstanceOf(NotFoundException.class);
    }

    @Test
    void throwsNotSupported_whenAddingBeforeCoreOwnsTheTrustList() {
        // given — no trust list in Core yet
        var request = new TrustedCertificateAddRequestDto();

        // when
        ThrowingCallable add = () -> trustedCertificateService.addTrustedCertificates(request);

        // then
        assertThatThrownBy(add).isInstanceOf(NotSupportedException.class).hasMessageContaining("Not implemented yet");
    }
}
