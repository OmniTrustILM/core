package com.otilm.core.integration.provisioning;

import com.github.tomakehurst.wiremock.http.Fault;
import com.github.tomakehurst.wiremock.junit5.WireMockExtension;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.otilm.core.provisioning.ProvisioningApplyResponseDTO;
import com.otilm.core.provisioning.ProvisioningApplyStatusDTO;
import com.otilm.core.provisioning.TrustedCertificateProvisioningApiClient;
import com.otilm.core.provisioning.TrustedCertificateProvisioningDTO;
import com.otilm.core.provisioning.TrustedCertificateProvisioningRequestDTO;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.WireMockPorts;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.delete;
import static com.github.tomakehurst.wiremock.client.WireMock.deleteRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TrustedCertificateProvisioningClientITest extends BaseSpringBootTest {

    private static final String BASE_PATH = "/api/v1/trusted-certificates";
    private static final byte[] PEM_BYTES = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
            .getBytes(StandardCharsets.US_ASCII);
    private static final String PEM_B64 = Base64.getEncoder().encodeToString(PEM_BYTES);

    @RegisterExtension
    static WireMockExtension wireMockServer = WireMockExtension
            .newInstance()
            .options(wireMockConfig().port(WireMockPorts.PROVISIONING_API))
            .build();

    @Autowired
    private TrustedCertificateProvisioningApiClient client;

    @Test
    void sendsDeferApply_whenCreating() {
        // given
        wireMockServer.stubFor(post(urlPathEqualTo(BASE_PATH)).willReturn(okJson("{\"uuid\":\"p1\"}").withStatus(201)));

        // when
        client.createTrustedCertificate(new TrustedCertificateProvisioningRequestDTO(PEM_BYTES), true);

        // then
        wireMockServer
                .verify(1, postRequestedFor(urlPathEqualTo(BASE_PATH)).withQueryParam("deferApply", equalTo("true")));
    }

    @Test
    void doesNotRetry_whenCreateConflicts() {
        // given
        wireMockServer
                .stubFor(post(urlPathEqualTo(BASE_PATH))
                        .willReturn(aResponse()
                                .withStatus(409)
                                .withHeader("Content-Type", "application/json")
                                .withBody("{\"error\":\"Certificate already exists\",\"uuid\":\"p1\"}")));
        var request = new TrustedCertificateProvisioningRequestDTO(PEM_BYTES);

        // when
        ThrowingCallable create = () -> client.createTrustedCertificate(request, true);

        // then
        assertThatThrownBy(create).isInstanceOf(HttpClientErrorException.Conflict.class);
        wireMockServer.verify(1, postRequestedFor(urlPathEqualTo(BASE_PATH)));
    }

    @Test
    void sendsDeferApply_whenDeleting() {
        // given
        wireMockServer.stubFor(delete(urlPathEqualTo(BASE_PATH + "/p1")).willReturn(aResponse().withStatus(204)));

        // when
        client.deleteTrustedCertificate("p1", true);

        // then
        wireMockServer
                .verify(1, deleteRequestedFor(urlPathEqualTo(BASE_PATH + "/p1"))
                        .withQueryParam("deferApply", equalTo("true")));
    }

    @Test
    void retriesApplyOnce_whenTheConnectionClosesWithoutAnAnswer() {
        // given — a pooled connection provisioning closed while idle answers nothing. An idempotent read first replaces
        // any connection an earlier test class left stale, so the injected fault is the only failure the retry meets.
        wireMockServer.stubFor(get(urlPathEqualTo(BASE_PATH + "/apply")).willReturn(okJson("{\"deploymentId\":1}")));
        client.getApplyStatus();
        wireMockServer
                .stubFor(post(urlPathEqualTo(BASE_PATH + "/apply"))
                        .inScenario("stale connection")
                        .whenScenarioStateIs(Scenario.STARTED)
                        .willReturn(aResponse().withFault(Fault.EMPTY_RESPONSE))
                        .willSetStateTo("fresh connection"));
        wireMockServer
                .stubFor(post(urlPathEqualTo(BASE_PATH + "/apply"))
                        .inScenario("stale connection")
                        .whenScenarioStateIs("fresh connection")
                        .willReturn(okJson("{\"deploymentId\":42,\"configurationVersion\":\"v7\"}").withStatus(202)));

        // when
        ResponseEntity<ProvisioningApplyResponseDTO> response = client.apply();

        // then
        assertThat(response.getBody()).isEqualTo(new ProvisioningApplyResponseDTO(42, "v7"));
        wireMockServer.verify(2, postRequestedFor(urlPathEqualTo(BASE_PATH + "/apply")));
    }

    @Test
    void doesNotRetryApply_whenTheAnswerTimesOut() {
        // given — provisioning may have queued the deployment before the read timeout of the test configuration
        wireMockServer
                .stubFor(post(urlPathEqualTo(BASE_PATH + "/apply"))
                        .willReturn(okJson("{\"deploymentId\":42}").withStatus(202).withFixedDelay(2_000)));

        // when
        ThrowingCallable apply = () -> client.apply();

        // then
        assertThatThrownBy(apply).isInstanceOf(ResourceAccessException.class);
        wireMockServer.verify(1, postRequestedFor(urlPathEqualTo(BASE_PATH + "/apply")));
    }

    @Test
    void doesNotRetryApply_whenProvisioningFails() {
        // given
        wireMockServer.stubFor(post(urlPathEqualTo(BASE_PATH + "/apply")).willReturn(aResponse().withStatus(503)));

        // when
        ThrowingCallable apply = () -> client.apply();

        // then
        assertThatThrownBy(apply).isInstanceOf(HttpServerErrorException.class);
        wireMockServer.verify(1, postRequestedFor(urlPathEqualTo(BASE_PATH + "/apply")));
    }

    @Test
    void returnsNoBody_whenApplyAnswersNoContent() {
        // given
        wireMockServer.stubFor(post(urlPathEqualTo(BASE_PATH + "/apply")).willReturn(aResponse().withStatus(204)));

        // when
        ResponseEntity<ProvisioningApplyResponseDTO> response = client.apply();

        // then
        assertThat(response.getBody()).isNull();
    }

    @Test
    void returnsTheDeployment_whenApplyStartsOne() {
        // given
        wireMockServer
                .stubFor(post(urlPathEqualTo(BASE_PATH + "/apply"))
                        .willReturn(okJson("{\"deploymentId\":42,\"configurationVersion\":\"v7\"}")));

        // when
        ResponseEntity<ProvisioningApplyResponseDTO> response = client.apply();

        // then
        assertThat(response.getBody()).isEqualTo(new ProvisioningApplyResponseDTO(42, "v7"));
    }

    @Test
    void throwsNotFoundWithoutRetry_whenApplyStatusIsUnknownToOlderProvisioning() {
        // given
        wireMockServer.stubFor(get(urlPathEqualTo(BASE_PATH + "/apply")).willReturn(aResponse().withStatus(404)));

        // when
        ThrowingCallable status = () -> client.getApplyStatus();

        // then
        assertThatThrownBy(status).isInstanceOf(HttpClientErrorException.NotFound.class);
        wireMockServer.verify(1, getRequestedFor(urlPathEqualTo(BASE_PATH + "/apply")));
    }

    @Test
    void readsTheDeploymentState_whenAskingApplyStatus() {
        // given
        wireMockServer
                .stubFor(get(urlPathEqualTo(BASE_PATH + "/apply"))
                        .willReturn(okJson("{\"deploymentId\":42,\"state\":\"failed\",\"error\":\"helm timeout\"}")));

        // when
        ProvisioningApplyStatusDTO status = client.getApplyStatus();

        // then
        assertThat(status.deploymentId()).isEqualTo(42);
        assertThat(status.state()).isEqualTo("failed");
        assertThat(status.error()).isEqualTo("helm timeout");
    }

    @Test
    void carriesTheState_whenListing() {
        // given
        wireMockServer
                .stubFor(get(urlPathEqualTo(BASE_PATH))
                        .willReturn(okJson("[{\"uuid\":\"p1\",\"certificateContent\":\"" + PEM_B64
                                + "\",\"state\":\"applying\",\"stateMessage\":\"rolling out\"}]")));

        // when
        List<TrustedCertificateProvisioningDTO> listed = client.listTrustedCertificates();

        // then
        assertThat(listed).singleElement().satisfies(item -> {
            assertThat(item.state()).isEqualTo("applying");
            assertThat(item.stateMessage()).isEqualTo("rolling out");
        });
    }
}
