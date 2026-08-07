package com.otilm.core.integration.service.cmp.message.handler;

import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.cmp.CmpProfileVariant;
import com.otilm.api.model.core.cmp.ProtectionMethod;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.protocol.ProtocolChallengeSource;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.Connector2FunctionGroupRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.cmp.CmpProfileRepository;
import com.otilm.core.service.cmp.CmpEntityUtil;
import com.otilm.core.service.cmp.CmpTestUtil;
import com.otilm.core.service.cmp.message.handler.PollFeature;
import com.otilm.core.service.cmp.message.handler.PollResult;
import com.otilm.core.service.cmp.CmpExternalService;
import com.otilm.core.service.cmp.registration.CmpRegistrationResolver;
import com.otilm.core.service.registration.RegistrationChallengeStore;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.MetaDefinitions;
import com.otilm.core.util.mockbeans.PollMocks;
import com.github.tomakehurst.wiremock.WireMockServer;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * End-to-end CMP registration-mode enrolment through {@link CmpExternalService#handlePost}: a real
 * MAC-protected PKIMessage whose senderKID references a pre-registration and whose MAC key is the
 * registration challenge. Drives the full path (header/body/protection validation, where the registration
 * gate lives, then the ir/cr and kur handlers) rather than a handler in isolation.
 */
// Deliberately NOT @Transactional: the completion runs issueExistingCertificate with NOT_SUPPORTED, which
// would suspend a spanning test transaction still holding the protection-layer gate's row lock and
// self-deadlock on the completion's re-gate. Seeds commit directly; BaseSpringBootTest truncates per test.
@Import(PollMocks.class)
class CmpRegistrationEnrolmentITest extends BaseSpringBootTest {

    private static final String PROFILE_NAME = "cmpRegistrationProfile";
    private static final String SUBJECT_DN = "CN=device-1";
    private static final String CHALLENGE = "cmp-registration-challenge";

    @Autowired private CmpExternalService cmpService;
    @Autowired private CmpProfileRepository cmpProfileRepository;
    @Autowired private RaProfileRepository raProfileRepository;
    @Autowired private CertificateRepository certificateRepository;
    @Autowired private CertificateContentRepository certificateContentRepository;
    @Autowired private ConnectorRepository connectorRepository;
    @Autowired private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired private FunctionGroupRepository functionGroupRepository;
    @Autowired private Connector2FunctionGroupRepository connector2FunctionGroupRepository;
    @Autowired private CertificateRegistrationAuthorizationRepository authorizationRepository;
    @Autowired private CertificateEventHistoryRepository eventHistoryRepository;
    @Autowired private RegistrationChallengeStore registrationChallengeStore;
    @Autowired private PollFeature pollFeature;
    @Autowired private PlatformTransactionManager transactionManager;

    private WireMockServer mockServer;
    private RaProfile raProfile;
    private CmpProfile cmpProfile;

    @BeforeEach
    void setUp() {
        mockServer = CmpTestUtil.createIssuingPlatform();

        Connector connector = new Connector();
        connector.setName("cmpRegistrationConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        FunctionGroup functionGroup = new FunctionGroup();
        functionGroup.setCode(FunctionGroupCode.AUTHORITY_PROVIDER);
        functionGroup.setName(FunctionGroupCode.AUTHORITY_PROVIDER.getCode());
        functionGroupRepository.save(functionGroup);

        Connector2FunctionGroup c2fg = new Connector2FunctionGroup();
        c2fg.setConnector(connector);
        c2fg.setConnectorUuid(connector.getUuid());
        c2fg.setFunctionGroup(functionGroup);
        c2fg.setFunctionGroupUuid(functionGroup.getUuid());
        c2fg.setKinds(MetaDefinitions.serializeArrayString(List.of("ApiKey")));
        connector2FunctionGroupRepository.save(c2fg);
        connector.getFunctionGroups().add(c2fg);
        connector.setVersion(ConnectorVersion.V2);
        connectorRepository.save(connector);

        AuthorityInstanceReference authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setUuid(UUID.randomUUID());
        authorityInstance.setName("cmpRegistrationAuthority");
        authorityInstance.setConnector(connector);
        authorityInstance.setConnectorUuid(connector.getUuid());
        authorityInstance.setKind("sample");
        authorityInstance.setAuthorityInstanceUuid("1l");
        authorityInstance = authorityInstanceReferenceRepository.save(authorityInstance);

        raProfile = raProfileRepository.saveAndFlush(CmpEntityUtil.createRaProfile(authorityInstance));

        cmpProfile = new CmpProfile();
        cmpProfile.setName(PROFILE_NAME);
        cmpProfile.setEnabled(true);
        cmpProfile.setVariant(CmpProfileVariant.V2);
        cmpProfile.setRequestProtectionMethod(ProtectionMethod.SHARED_SECRET);
        cmpProfile.setResponseProtectionMethod(ProtectionMethod.SHARED_SECRET);
        cmpProfile.setChallengeSource(ProtocolChallengeSource.CERTIFICATE_REGISTRATION);
        cmpProfile.setRaProfile(raProfile);
        cmpProfile = cmpProfileRepository.saveAndFlush(cmpProfile);
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
        // Committed rows are cleaned by BaseSpringBootTest's per-test truncation; a manual certificate
        // deleteAll here would violate the cmp_transaction -> certificate foreign key.
    }

    private Certificate seedRegistration(String subjectDn, Map<String, List<String>> sans, CertificateState state) {
        Certificate certificate = new Certificate();
        certificate.setUuid(UUID.randomUUID());
        certificate.setSubjectDn(subjectDn);
        if (sans != null) {
            certificate.setSubjectAlternativeNames(CertificateUtil.serializeSans(sans));
        }
        certificate.setState(state);
        certificate.setRaProfile(raProfile);
        certificate.setRaProfileUuid(raProfile.getUuid());
        certificate = certificateRepository.saveAndFlush(certificate);

        CertificateRegistrationAuthorization authorization = new CertificateRegistrationAuthorization();
        authorization.setCertificateUuid(certificate.getUuid());
        authorization.setState(RegistrationState.ACTIVE);
        authorization.setFailedAttempts(0);
        authorization.setExpiresAt(OffsetDateTime.now().plusDays(7));
        registrationChallengeStore.store(authorization, CHALLENGE);
        authorizationRepository.saveAndFlush(authorization);
        return certificate;
    }

    private ResponseEntity<byte[]> post(PKIMessage message) throws Exception {
        MockHttpServletRequest servletRequest = new MockHttpServletRequest("POST", "/v1/protocols/cmp/" + PROFILE_NAME);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(servletRequest));
        return cmpService.handlePost(PROFILE_NAME, message.getEncoded());
    }

    private PKIMessage irMessage(String subjectDn, List<String> dnsSans, String challenge, UUID senderKid) throws Exception {
        KeyPair keyPair = CmpTestUtil.generateKeyPairEC();
        PKIBody body = CmpTestUtil.createRegistrationCrmfBody(keyPair, 0L, PKIBody.TYPE_INIT_REQ, subjectDn, dnsSans, null);
        return CmpTestUtil.createMacBasedMessageWithSenderKid(
                "0102030405060708", challenge, body,
                senderKid.toString().getBytes(StandardCharsets.UTF_8)).toASN1Structure();
    }

    private String failText(byte[] responseBytes) {
        PKIMessage response = PKIMessage.getInstance(responseBytes);
        return ((org.bouncycastle.asn1.cmp.ErrorMsgContent) response.getBody().getContent())
                .getPKIStatusInfo().getStatusString().getStringAtUTF8(0).getString();
    }

    private int failInfo(byte[] responseBytes) {
        PKIMessage response = PKIMessage.getInstance(responseBytes);
        return ((org.bouncycastle.asn1.cmp.ErrorMsgContent) response.getBody().getContent())
                .getPKIStatusInfo().getFailInfo().intValue();
    }

    /**
     * The issued certificate the poll returns once issuance finishes. Persists a backing row so the
     * dispatcher's by-UUID chain lookup resolves, but returns a detached twin carrying a plain (non-proxy)
     * CertificateContent, so response-building can read the content without the seeding session (the test is
     * not transactional).
     */
    private Certificate seedIssuedCertificate() throws Exception {
        KeyPair keyPair = CmpTestUtil.generateKeyPairEC();
        var holder = CmpTestUtil.makeV3Certificate(BigInteger.valueOf(System.nanoTime()), keyPair, "CN=issued", keyPair, "CN=issued");
        String content = java.util.Base64.getEncoder().encodeToString(holder.getEncoded());
        CertificateContent certificateContent = certificateContentRepository.saveAndFlush(
                CmpEntityUtil.createCertContent(CertificateUtil.getThumbprint(content.getBytes()), content));
        Certificate persisted = CmpEntityUtil.createCertificate(holder.getSerialNumber(), CertificateState.ISSUED, certificateContent);
        persisted.setRaProfile(raProfile);
        persisted.setRaProfileUuid(raProfile.getUuid());
        persisted = certificateRepository.saveAndFlush(persisted);

        CertificateContent plainContent = new CertificateContent();
        plainContent.setContent(content);
        plainContent.setFingerprint(certificateContent.getFingerprint());
        Certificate pollResult = new Certificate();
        pollResult.setUuid(persisted.getUuid());
        pollResult.setSerialNumber(persisted.getSerialNumber());
        pollResult.setState(CertificateState.ISSUED);
        pollResult.setCertificateContent(plainContent);
        return pollResult;
    }

    @Test
    void matchingEnrolmentCompletesTheRegistration() throws Exception {
        Certificate registration = seedRegistration(SUBJECT_DN, Map.of("dNSName", List.of("device-1.example")), CertificateState.REGISTERED);
        given(pollFeature.pollCertificate(any(), any(), any(), any()))
                .willReturn(new PollResult.Reached(seedIssuedCertificate()));

        ResponseEntity<byte[]> response = post(irMessage(SUBJECT_DN, List.of("device-1.example"), CHALLENGE, registration.getUuid()));

        assertNotNull(response.getBody());
        // A read transaction so the lazy protocolAssociation can load (the test is not transactional).
        new TransactionTemplate(transactionManager).executeWithoutResult(status -> {
            Certificate completed = certificateRepository.findByUuid(registration.getUuid()).orElseThrow();
            assertNotNull(completed.getCertificateRequestUuid(), "the CRMF is attached to the registration");
            assertNotNull(completed.getProtocolAssociation(), "the completion is attributed to CMP");
            assertEquals(CertificateProtocol.CMP, completed.getProtocolAssociation().getProtocol());
        });
    }

    @Test
    void macRevocationIsRejectedNotAuthenticatedByAnEmptySecret() throws Exception {
        // Registration mode stores no shared secret; a MAC-protected revocation must not authenticate against
        // an empty key. It is rejected at protection validation, never reaching the revocation handler.
        seedRegistration(SUBJECT_DN, null, CertificateState.REGISTERED);
        PKIBody revocation = CmpTestUtil.createRevocationBody(BigInteger.valueOf(0xC0FFEEL));
        PKIMessage message = CmpTestUtil.createMacBasedMessageWithSenderKid(
                "0102030405060708", "anything", revocation,
                UUID.randomUUID().toString().getBytes(StandardCharsets.UTF_8)).toASN1Structure();

        ResponseEntity<byte[]> response = post(message);

        assertEquals(PKIFailureInfo.badMessageCheck, failInfo(response.getBody()));
    }

    @Test
    void wrongMacIsRejectedGenericallyAndCounted() throws Exception {
        Certificate registration = seedRegistration(SUBJECT_DN, null, CertificateState.REGISTERED);

        ResponseEntity<byte[]> response = post(irMessage(SUBJECT_DN, null, "wrong-challenge", registration.getUuid()));

        assertEquals(PKIFailureInfo.badMessageCheck, failInfo(response.getBody()));
        assertEquals(CmpRegistrationResolver.REGISTRATION_REJECTION, failText(response.getBody()));
        CertificateRegistrationAuthorization authorization =
                authorizationRepository.findByCertificateUuid(registration.getUuid()).orElseThrow();
        assertEquals(1, authorization.getFailedAttempts(), "the failed attempt survives the rejection");
    }

    @Test
    void unknownSenderKidIsIndistinguishableFromWrongMac() throws Exception {
        Certificate registration = seedRegistration(SUBJECT_DN, null, CertificateState.REGISTERED);

        byte[] wrongMac = post(irMessage(SUBJECT_DN, null, "wrong-challenge", registration.getUuid())).getBody();
        byte[] unknownKid = post(irMessage(SUBJECT_DN, null, CHALLENGE, UUID.randomUUID())).getBody();

        assertEquals(failText(wrongMac), failText(unknownKid),
                "a prober must not distinguish a wrong MAC from an unknown registration");
        assertEquals(failInfo(wrongMac), failInfo(unknownKid));
    }

    @Test
    void sanMismatchIsRejectedAndRecordedOnTheRegistration() throws Exception {
        Certificate registration = seedRegistration(SUBJECT_DN, Map.of("dNSName", List.of("registered.example")), CertificateState.REGISTERED);

        ResponseEntity<byte[]> response = post(irMessage(SUBJECT_DN, List.of("other.example"), CHALLENGE, registration.getUuid()));

        assertEquals(CmpRegistrationResolver.REGISTRATION_REJECTION, failText(response.getBody()));
        List<CertificateEventHistory> history = eventHistoryRepository.findByCertificateOrderByCreatedDesc(
                certificateRepository.findByUuid(registration.getUuid()).orElseThrow());
        assertTrue(history.stream().anyMatch(e -> e.getStatus() == CertificateEventStatus.FAILED
                        && e.getMessage().contains("subject alternative names")),
                "the SAN mismatch is recorded on the matched registration");
    }

    @Test
    void subjectMismatchIsRejectedAndRecordedOnTheRegistration() throws Exception {
        Certificate registration = seedRegistration(SUBJECT_DN, null, CertificateState.REGISTERED);

        ResponseEntity<byte[]> response = post(irMessage("CN=someone-else", null, CHALLENGE, registration.getUuid()));

        assertEquals(CmpRegistrationResolver.REGISTRATION_REJECTION, failText(response.getBody()));
        List<CertificateEventHistory> history = eventHistoryRepository.findByCertificateOrderByCreatedDesc(
                certificateRepository.findByUuid(registration.getUuid()).orElseThrow());
        assertTrue(history.stream().anyMatch(e -> e.getStatus() == CertificateEventStatus.FAILED
                        && e.getMessage().contains("subject does not match")),
                "the subject mismatch is recorded on the matched registration");
    }
}
