package com.otilm.core.service.v3.integration;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.v2.AvailableOperationsDto;
import com.otilm.api.model.core.v2.CertificateOperationKind;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRegistrationDto;
import com.otilm.api.model.core.v2.OperationSupport;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.builders.AuthorityFixtures;
import com.otilm.core.util.builders.V3ConnectorStubs;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.test.context.bean.override.mockito.MockitoSpyBean;

import java.util.UUID;

/**
 * Integration tests verifying capability gating for the v3 authority register operation and the
 * {@code listAvailableOperations} flag advertisement.
 *
 * <p>Scenarios:
 * <ol>
 *   <li>Register against a v2 authority → {@link ValidationException}, no placeholder cert left behind.</li>
 *   <li>Register against a v3 authority without {@code CERTIFICATE_REGISTRATION} flag → same rejection,
 *       no placeholder.</li>
 *   <li>Register against a v3 authority with {@code CERTIFICATE_REGISTRATION} + sync stub → {@code REGISTERED}.</li>
 *   <li>{@code listAvailableOperations} correctly reflects boolean flags for three fixture variants:
 *       v2, v3 + both flags, v3 + only {@code CERTIFICATE_REGISTRATION}.</li>
 * </ol>
 */
public class V3CapabilityGatingITest extends BaseSpringBootTest {

    // ── Spring beans ──────────────────────────────────────────────────────────

    @Autowired
    private ClientOperationExternalService clientOperationService;

    @MockitoSpyBean
    @SuppressWarnings("unused") // Spied for parity with the issue-driving suites; this suite stubs/verifies no interactions on it.
    private ActionProducer actionProducer;

    @Autowired
    private CertificateRepository certificateRepository;

    // Fixture builder repos
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private FunctionGroupRepository functionGroupRepository;
    @Autowired
    private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    // ── Per-test state ────────────────────────────────────────────────────────

    private WireMockServer wireMockServer;

    // ── Lifecycle ─────────────────────────────────────────────────────────────

    @BeforeEach
    public void setUpWireMock() {
        wireMockServer = new WireMockServer(0);
        wireMockServer.start();
        WireMock.configureFor("localhost", wireMockServer.port());
    }

    @AfterEach
    public void tearDownWireMock() {
        wireMockServer.stop();
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    /**
     * Register on a v2 authority must be rejected with {@link ValidationException}.
     *
     * <p>The v2 adapter does not implement {@code RegisterCapability}, so the gate in
     * {@code ClientOperationServiceImpl.registerCertificate} must reject the call before creating a
     * placeholder certificate. No connector HTTP call is made, so a synthetic URL is sufficient.</p>
     */
    @Test
    public void register_v2Authority_rejected() {
        AuthorityFixtures.Fixture fixture = AuthorityFixtures.v2Authority(repos(), "MOCK_V2");

        long certsBefore = certificateRepository.count();

        Assertions.assertThrows(ValidationException.class,
                () -> registerCertificate(fixture, "CN=gating-v2,O=Test"),
                "Register on a v2 authority must throw ValidationException");

        long certsAfter = certificateRepository.count();
        Assertions.assertEquals(certsBefore, certsAfter,
                "No placeholder certificate must be created when register is rejected for a v2 authority");
    }

    /**
     * Register on a v3 authority that does NOT advertise {@code CERTIFICATE_REGISTRATION} must be
     * rejected with {@link ValidationException}.
     *
     * <p>The v3 adapter implements {@code RegisterCapability} at the protocol level, but the capability
     * service gate requires the {@code CERTIFICATE_REGISTRATION} feature flag to also be present in the
     * connector interface. Without it the call must fail before creating a placeholder. No connector HTTP
     * call is made, so a synthetic URL is sufficient.</p>
     */
    @Test
    public void register_v3WithoutFlag_rejected() {
        // v3Authority with zero feature flags; no HTTP call is made so no WireMock server is needed
        AuthorityFixtures.Fixture fixture = AuthorityFixtures.v3Authority(repos());

        long certsBefore = certificateRepository.count();

        Assertions.assertThrows(ValidationException.class,
                () -> registerCertificate(fixture, "CN=gating-noflag,O=Test"),
                "Register on a v3 authority without CERTIFICATE_REGISTRATION flag must throw ValidationException");

        long certsAfter = certificateRepository.count();
        Assertions.assertEquals(certsBefore, certsAfter,
                "No placeholder certificate must be created when register is rejected for a v3 authority missing the flag");
    }

    /**
     * Register on a v3 authority that advertises {@code CERTIFICATE_REGISTRATION} with a sync connector
     * stub (HTTP 200) must succeed and transition the certificate to {@code REGISTERED}.
     */
    @Test
    public void register_v3WithFlag_succeeds() throws Exception {
        AuthorityFixtures.Fixture fixture = AuthorityFixtures.v3Authority(
                repos(), wireMockServer, FeatureFlag.CERTIFICATE_REGISTRATION);

        V3ConnectorStubs.stubRegisterSync(wireMockServer, null);

        ClientCertificateDataResponseDto response = registerCertificate(fixture, "CN=gating-ok,O=Test");

        Certificate cert =
                certificateRepository.findByUuid(UUID.fromString(response.getUuid()))
                        .orElseThrow(() -> new AssertionError("Certificate not found: " + response.getUuid()));

        Assertions.assertEquals(
                CertificateState.REGISTERED,
                cert.getState(),
                "v3 authority with CERTIFICATE_REGISTRATION flag + sync stub must transition cert to REGISTERED");
    }

    /**
     * {@code listAvailableOperations} must reflect the correct boolean flags across three fixture variants.
     *
     * <p>None of the variants make connector HTTP calls — capability inspection is purely local —
     * so all three connectors use synthetic URLs via the no-WireMock overloads. This avoids spinning
     * up extra WireMock servers purely for URL uniqueness.
     *
     * <p>Assertions:
     * <ul>
     *   <li><b>v2 authority:</b> {@code REGISTER.supported=false}; {@code ISSUE.asyncSupported=false}
     *       (no async capability).</li>
     *   <li><b>v3 + both flags:</b> {@code REGISTER.supported=true}, {@code REGISTER.asyncSupported=true};
     *       {@code ISSUE.asyncSupported=true}.</li>
     *   <li><b>v3 + only {@code CERTIFICATE_REGISTRATION}:</b> {@code REGISTER.supported=true},
     *       {@code REGISTER.asyncSupported=false} (no polling flag),
     *       {@code REGISTER.cancelSupported=false} (hardcoded false for all variants, never flag-gated);
     *       {@code ISSUE.asyncSupported=false}.</li>
     * </ul>
     * </p>
     */
    @Test
    public void listAvailableOperations_reflectsFlags() throws Exception {
        // No connector HTTP calls are made; synthetic URLs keep each connector URL unique.

        // --- variant 1: v2 authority ---
        AuthorityFixtures.Fixture v2Fixture = AuthorityFixtures.v2Authority(repos(), "MOCK_V2");
        AvailableOperationsDto v2Ops = clientOperationService.listAvailableOperations(
                SecuredParentUUID.fromUUID(v2Fixture.authority().getUuid()),
                v2Fixture.raProfile().getSecuredUuid());

        OperationSupport v2Register = getOperation(v2Ops, CertificateOperationKind.REGISTER);
        OperationSupport v2Issue    = getOperation(v2Ops, CertificateOperationKind.ISSUE);

        Assertions.assertFalse(v2Register.isSupported(),
                "v2 authority: REGISTER must not be supported");
        Assertions.assertFalse(v2Issue.isAsyncSupported(),
                "v2 authority: ISSUE asyncSupported must be false");

        // --- variant 2: v3 + both flags ---
        AuthorityFixtures.Fixture v3BothFixture = AuthorityFixtures.v3Authority(
                repos(),
                FeatureFlag.CERTIFICATE_REGISTRATION,
                FeatureFlag.CERTIFICATE_STATUS_POLLING);
        AvailableOperationsDto v3BothOps = clientOperationService.listAvailableOperations(
                SecuredParentUUID.fromUUID(v3BothFixture.authority().getUuid()),
                v3BothFixture.raProfile().getSecuredUuid());

        OperationSupport v3BothRegister = getOperation(v3BothOps, CertificateOperationKind.REGISTER);
        OperationSupport v3BothIssue    = getOperation(v3BothOps, CertificateOperationKind.ISSUE);

        Assertions.assertTrue(v3BothRegister.isSupported(),
                "v3 + both flags: REGISTER must be supported");
        Assertions.assertTrue(v3BothRegister.isAsyncSupported(),
                "v3 + both flags: REGISTER asyncSupported must be true");
        Assertions.assertFalse(v3BothRegister.isCancelSupported(),
                "v3 + both flags: REGISTER cancelSupported must be false (hardcoded, never advertised regardless of flags)");
        Assertions.assertTrue(v3BothIssue.isAsyncSupported(),
                "v3 + both flags: ISSUE asyncSupported must be true");

        // --- variant 3: v3 + only CERTIFICATE_REGISTRATION (no polling flag) ---
        AuthorityFixtures.Fixture v3RegOnlyFixture = AuthorityFixtures.v3Authority(
                repos(), FeatureFlag.CERTIFICATE_REGISTRATION);
        AvailableOperationsDto v3RegOnlyOps = clientOperationService.listAvailableOperations(
                SecuredParentUUID.fromUUID(v3RegOnlyFixture.authority().getUuid()),
                v3RegOnlyFixture.raProfile().getSecuredUuid());

        OperationSupport v3RegOnlyRegister = getOperation(v3RegOnlyOps, CertificateOperationKind.REGISTER);
        OperationSupport v3RegOnlyIssue    = getOperation(v3RegOnlyOps, CertificateOperationKind.ISSUE);

        Assertions.assertTrue(v3RegOnlyRegister.isSupported(),
                "v3 + CERTIFICATE_REGISTRATION only: REGISTER must be supported");
        Assertions.assertFalse(v3RegOnlyRegister.isAsyncSupported(),
                "v3 + CERTIFICATE_REGISTRATION only: REGISTER asyncSupported must be false (no polling flag)");
        Assertions.assertFalse(v3RegOnlyRegister.isCancelSupported(),
                "v3 + CERTIFICATE_REGISTRATION only: REGISTER cancelSupported must be false");
        Assertions.assertFalse(v3RegOnlyIssue.isAsyncSupported(),
                "v3 + CERTIFICATE_REGISTRATION only: ISSUE asyncSupported must be false (no polling flag)");
    }

    // ── Private helpers ───────────────────────────────────────────────────────

    private AuthorityFixtures.Repos repos() {
        return new AuthorityFixtures.Repos(
                connectorRepository,
                functionGroupRepository,
                connector2FunctionGroupRepository,
                authorityInstanceReferenceRepository,
                raProfileRepository,
                connectorInterfaceRepository);
    }

    private ClientCertificateDataResponseDto registerCertificate(AuthorityFixtures.Fixture fixture, String subjectDn)
            throws Exception {
        ClientCertificateRegistrationDto request = new ClientCertificateRegistrationDto();
        request.setSubjectDn(subjectDn);

        return clientOperationService.registerCertificate(
                SecuredParentUUID.fromUUID(fixture.authority().getUuid()),
                fixture.raProfile().getSecuredUuid(),
                request);
    }

    /**
     * Retrieves the {@link OperationSupport} entry for the given kind from the DTO, failing the test
     * if no such entry is present.
     */
    private OperationSupport getOperation(AvailableOperationsDto dto, CertificateOperationKind kind) {
        return dto.getOperations().stream()
                .filter(op -> op.getOperation() == kind)
                .findFirst()
                .orElseThrow(() -> new AssertionError(
                        "AvailableOperationsDto did not contain an entry for " + kind));
    }
}
