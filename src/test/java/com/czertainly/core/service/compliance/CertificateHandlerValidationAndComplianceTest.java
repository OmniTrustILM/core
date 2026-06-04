package com.czertainly.core.service.compliance;

import com.czertainly.api.model.client.certificate.UploadCertificateRequestDto;
import com.czertainly.api.model.common.enums.cryptography.KeyAlgorithm;
import com.czertainly.api.model.core.certificate.CertificateEvent;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.compliance.ComplianceStatus;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CertificateEventHistory;
import com.czertainly.core.dao.repository.CertificateEventHistoryRepository;
import com.czertainly.core.helpers.CertificateGeneratorHelper;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.handler.CertificateHandler;
import com.czertainly.core.util.RabbitMQContainerFactory;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.RabbitMQContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.awaitility.Awaitility.await;

/**
 * End-to-end tests for the certificate validation and compliance flow through {@link CertificateHandler}.
 *
 * <p>A real RabbitMQ container is required ({@code messaging-int-test} profile with
 * {@code inheritProfiles = false}) so that JMS endpoint configs annotated
 * {@code @Profile("!test")} are loaded and the {@code CERTIFICATE_STATUS_CHANGED} event
 * is actually delivered end-to-end and recorded in certificate event history.
 */
@Testcontainers
@ActiveProfiles(value = {"messaging-int-test"}, inheritProfiles = false)
class CertificateHandlerValidationAndComplianceTest extends BaseComplianceTest {

    @Container
    private static final RabbitMQContainer rabbitMQContainer = RabbitMQContainerFactory.create();

    @DynamicPropertySource
    static void rabbitMQProperties(DynamicPropertyRegistry registry) throws IOException, InterruptedException {
        RabbitMQContainerFactory.importDefinitions(rabbitMQContainer);
        registry.add("spring.messaging.broker-url",
                () -> "amqp://%s:%d".formatted(rabbitMQContainer.getHost(), rabbitMQContainer.getAmqpPort()));
        registry.add("spring.messaging.broker-type", () -> "RABBITMQ");
        registry.add("spring.messaging.username", rabbitMQContainer::getAdminUsername);
        registry.add("spring.messaging.password", rabbitMQContainer::getAdminPassword);
        // Disable the per-instance and shared proxy queue listeners — the test-instance queue
        // does not exist in the test RabbitMQ definitions and would cause an infinite retry loop.
        registry.add("proxy.enabled", () -> "false");
    }

    @Autowired
    private CertificateHandler certificateHandler;

    @Autowired
    private CertificateService certificateService;

    @Autowired
    private CertificateEventHistoryRepository certificateEventHistoryRepository;

    @BeforeEach
    void setUpAsync() {
        // JMS listener threads must inherit the security context set up by BaseSpringBootTest.setupAuth().
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_INHERITABLETHREADLOCAL);
        SecurityContextHolder.getContext().setAuthentication(getAuthentication());

        // Remove internal compliance rules from the profile added by the base class.
        complianceProfileRuleRepository.deleteAll(
                complianceProfileRuleRepository.findAll().stream()
                        .filter(r -> r.getInternalRuleUuid() != null)
                        .toList()
        );
    }

    @AfterEach
    void tearDownAsync() {
        SecurityContextHolder.clearContext();
        SecurityContextHolder.setStrategyName(SecurityContextHolder.MODE_THREADLOCAL);
    }

    static Stream<Arguments> providerScenarios() {
        return Stream.of(
                Arguments.of(
                        "successfulProvider",
                        200,
                        """
                                {
                                  "rules": [
                                    {
                                      "uuid": "%s",
                                      "name": "Rule1",
                                      "status": "ok"
                                    }
                                  ]
                                }
                                """,
                        "Test",
                        ComplianceStatus.OK,
                        CertificateValidationStatus.INVALID
                ),
                Arguments.of(
                        "unavailableProvider",
                        500,
                        "{}",
                        "Test-1455",
                        ComplianceStatus.FAILED,
                        CertificateValidationStatus.INVALID
                )
        );
    }

    /**
     * Verifies the full validate → compliance-check → event-history flow for a certificate.
     *
     * @param providerHttpStatus       HTTP status the compliance provider WireMock stub returns
     * @param providerBody             response body template (may contain a {@code %s} placeholder for the rule UUID)
     * @param cnSuffix                 distinguishing suffix appended to issuer/subject CNs so parallel runs don't collide
     * @param expectedComplianceStatus compliance status expected on the certificate after {@code validate()}
     * @param expectedValidationStatus exact validation status expected
     */
    @ParameterizedTest(name = "{0}")
    @MethodSource("providerScenarios")
    void validateAndCheckCompliance(
            String displayName,
            int providerHttpStatus,
            String providerBody,
            String cnSuffix,
            ComplianceStatus expectedComplianceStatus,
            CertificateValidationStatus expectedValidationStatus
    ) throws Exception {
        WireMock.stubFor(WireMock.post(WireMock.urlPathEqualTo(
                        "/v2/complianceProvider/%s/compliance".formatted(KIND_V2)))
                .willReturn(WireMock.aResponse()
                        .withStatus(providerHttpStatus)
                        .withHeader("Content-Type", "application/json")
                        .withBody(providerBody.formatted(complianceV2RuleUuid))));

        var certInfo = CertificateGeneratorHelper.generateCertificateWithIssuer(
                KeyAlgorithm.RSA, "CN=Test-Issuer-%s".formatted(cnSuffix),
                "CN=Test-Subject-%s".formatted(cnSuffix), null);
        UploadCertificateRequestDto uploadDto = new UploadCertificateRequestDto();
        uploadDto.setCertificate(certInfo.getCaCertificateBase64Encoded());
        certificateService.uploadAsync(uploadDto);
        uploadDto.setCertificate(certInfo.getEndEntityCertificateBase64Encoded());
        String fingerprint = certificateService.uploadAsync(uploadDto).getFingerprint();

        // Wait for the initial async X.509 validation triggered by upload to complete before associating the RA profile.
        await().atMost(10, TimeUnit.SECONDS).until(() ->
                certificateRepository.findByFingerprint(fingerprint)
                        .map(c -> c.getValidationStatus() != CertificateValidationStatus.NOT_CHECKED)
                        .orElse(false)
        );

        // Associate certificate with the RA profile that has a compliance profile.
        Certificate cert = certificateRepository.findByFingerprint(fingerprint).orElseThrow();
        cert.setRaProfileUuid(associatedRaProfileUuid);
        certificateRepository.save(cert);

        // Load with associations exactly as ValidationListener.processMessage() does.
        Certificate certWithAssociations = certificateRepository
                .findAllWithAssociationsByUuidIn(List.of(cert.getUuid()))
                .getFirst();

        certificateHandler.validate(certWithAssociations);

        Certificate reloaded = certificateRepository.findByUuid(cert.getUuid()).orElseThrow();

        Assertions.assertEquals(expectedComplianceStatus, reloaded.getComplianceStatus(),
                "Unexpected complianceStatus for scenario: " + displayName);
        Assertions.assertEquals(expectedValidationStatus, reloaded.getValidationStatus(),
                "Unexpected validationStatus for scenario: " + displayName);

        // Wait for the CERTIFICATE_STATUS_CHANGED JMS event to be delivered end-to-end
        // (producer → RabbitMQ → EventListener → history writer).
        await().atMost(10, TimeUnit.SECONDS).untilAsserted(() -> {
            List<CertificateEventHistory> history = certificateEventHistoryRepository
                    .findByCertificateOrderByCreatedDesc(reloaded);
            long validationStatusEntries = history.stream()
                    .filter(h -> h.getEvent() == CertificateEvent.UPDATE_VALIDATION_STATUS)
                    .count();
            Assertions.assertEquals(1L, validationStatusEntries,
                    "Expected exactly one UPDATE_VALIDATION_STATUS event for scenario '%s'; found %d"
                            .formatted(displayName, validationStatusEntries));
        });
    }
}
