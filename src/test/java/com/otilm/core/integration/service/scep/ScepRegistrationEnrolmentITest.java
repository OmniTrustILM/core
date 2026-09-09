package com.otilm.core.integration.service.scep;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.enums.CertificateProtocol;
import com.otilm.api.model.core.protocol.ProtocolChallengeSource;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.api.model.core.scep.PkiStatus;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CertificateContent;
import com.otilm.core.dao.entity.CertificateEventHistory;
import com.otilm.core.dao.entity.CertificateProtocolAssociation;
import com.otilm.core.dao.entity.CertificateRegistrationAuthorization;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.RegistrationState;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.entity.scep.ScepTransaction;
import com.otilm.core.dao.repository.AuthorityInstanceReferenceRepository;
import com.otilm.core.dao.repository.CertificateContentRepository;
import com.otilm.core.dao.repository.CertificateEventHistoryRepository;
import com.otilm.core.dao.repository.CertificateProtocolAssociationRepository;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.scep.ScepProfileRepository;
import com.otilm.core.dao.repository.scep.ScepTransactionRepository;
import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.service.registration.CertificateRegistrationDefaults;
import com.otilm.core.service.registration.RegistrationChallengeStore;
import com.otilm.core.service.scep.ScepExternalService;
import com.otilm.core.service.scep.ScepMessageTestData;
import com.otilm.core.service.scep.impl.ScepServiceImpl;
import com.otilm.core.service.scep.message.ScepConstants;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.mockbeans.ProducerMocks;
import com.otilm.core.util.seeders.CryptographicKeySeeder;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.OffsetDateTime;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import javax.crypto.Cipher;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.cms.EnvelopedData;
import org.bouncycastle.asn1.cms.KeyTransRecipientInfo;
import org.bouncycastle.asn1.cms.RecipientInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.filter.TypeExcludeFilters;
import org.springframework.context.annotation.Import;
import org.springframework.http.ResponseEntity;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * End-to-end SCEP enrolment against pre-registrations: a real signed CMS PKCSReq goes into a CERTIFICATE_REGISTRATION
 * profile and the assertions cover both what the client receives and what the platform recorded. The CA key is RSA, so
 * requests are enveloped via key transport and the connector decrypt is stubbed per message: the test extracts the
 * encrypted content-encryption key from the message it just built, decrypts it locally with the test-held CA private
 * key, and stubs the decrypt endpoint to return exactly that key. Response signing is stubbed as in
 * {@link ScepPkiOperationITest}; issuance stays unstubbed — completion is asynchronous and the client sees PENDING.
 */
@Import(ProducerMocks.class)
@TypeExcludeFilters(ProducerMocks.MockedProducersTypeExcludeFilter.class)
class ScepRegistrationEnrolmentITest extends BaseSpringBootTest {

    private static final String SCEP_PROFILE_NAME = "registrationEnrolmentProfile";
    private static final String CA_DN = "CN=Test SCEP Registration CA";
    private static final String CHALLENGE = "registration-challenge-1";
    private static final String SUBJECT_DN = "CN=device-1";
    /** Pinned copy of the wire contract: changing the production message must consciously change this test. */
    private static final String REGISTRATION_REJECTION = "The request does not match an active certificate registration.";

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Autowired
    private ScepExternalService scepService;
    @Autowired
    private ScepProfileRepository scepProfileRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CertificateContentRepository certificateContentRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private ScepTransactionRepository scepTransactionRepository;
    @Autowired
    private CertificateRegistrationAuthorizationRepository authorizationRepository;
    @Autowired
    private CertificateEventHistoryRepository eventHistoryRepository;
    @Autowired
    private CertificateProtocolAssociationRepository certificateProtocolAssociationRepository;
    @Autowired
    private RegistrationChallengeStore registrationChallengeStore;
    @Autowired
    private CryptographicKeySeeder cryptographicKeySeeder;
    @Autowired
    private ActionProducer actionProducer;

    private WireMockServer mockServer;
    private RaProfile raProfile;
    private ScepProfile scepProfile;
    private KeyPair caKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        mockServer = new WireMockServer(0);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        Connector connector = new Connector();
        connector.setName("scepRegistrationTestConnector");
        connector.setUrl("http://localhost:" + mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        AuthorityInstanceReference authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setName("scepRegistrationTestAuthority");
        authorityInstance.setConnector(connector);
        authorityInstance.setConnectorUuid(connector.getUuid());
        authorityInstance.setKind("sample");
        authorityInstance.setAuthorityInstanceUuid("1l");
        authorityInstance = authorityInstanceReferenceRepository.save(authorityInstance);

        raProfile = new RaProfile();
        raProfile.setName("scepRegistrationTestRaProfile");
        raProfile.setEnabled(true);
        raProfile.setAuthorityInstanceReference(authorityInstance);
        raProfile = raProfileRepository.save(raProfile);

        TokenInstanceReference tokenInstance = new TokenInstanceReference();
        tokenInstance.setStatus(TokenInstanceStatus.CONNECTED);
        tokenInstance.setName("scepRegistrationTestTokenInstance");
        tokenInstance.setConnector(connector);
        tokenInstance.setConnectorUuid(connector.getUuid());
        tokenInstance.setKind("sample");
        tokenInstance.setTokenInstanceUuid("33333333-3333-3333-3333-333333333333");
        tokenInstance = tokenInstanceReferenceRepository.save(tokenInstance);

        caKeyPair = KeyPairGenerator.getInstance("RSA").generateKeyPair();
        // An RSA SCEP CA key must carry the full usage sets (DECRYPT+SIGN / ENCRYPT+VERIFY) —
        // isCertificateScepCaCertAcceptable rejects the profile otherwise.
        CryptographicKey caKey = cryptographicKeySeeder
                .seedKey("scepRegistrationCaKey", null, tokenInstance,
                        new CryptographicKeySeeder.KeyItemSpec(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA,
                                List.of(KeyUsage.DECRYPT, KeyUsage.SIGN), KeyFormat.PRKI, "placeholder"),
                        new CryptographicKeySeeder.KeyItemSpec(KeyType.PUBLIC_KEY, KeyAlgorithm.RSA,
                                List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY), KeyFormat.SPKI,
                                Base64.getEncoder().encodeToString(caKeyPair.getPublic().getEncoded())));

        Certificate caCertificate = storeCertificate(selfSignedRsaCertificate(caKeyPair), caKey, null);

        scepProfile = new ScepProfile();
        scepProfile.setName(SCEP_PROFILE_NAME);
        scepProfile.setDescription("registration enrolment end-to-end profile");
        scepProfile.setEnabled(true);
        scepProfile.setRequireManualApproval(false);
        scepProfile.setIncludeCaCertificate(true);
        scepProfile.setChallengeSource(ProtocolChallengeSource.CERTIFICATE_REGISTRATION);
        scepProfile.setCaCertificate(caCertificate);
        scepProfile.setRaProfile(raProfile);
        scepProfile = scepProfileRepository.save(scepProfile);

        stubTokenSigning();
    }

    @AfterEach
    void tearDown() {
        mockServer.stop();
    }

    @Test
    void matchingEnrolmentCompletesTheRegistrationAsPending() throws Exception {
        Certificate placeholder = registeredPlaceholder(SUBJECT_DN, Map.of("dNSName", List.of("device-1.example")),
                CHALLENGE);

        ResponseEntity<Object> response = postPkiOperation(
                enrolment(SUBJECT_DN, List.of("device-1.example"), CHALLENGE));

        assertScepFormatted(response);
        assertEquals(String.valueOf(PkiStatus.PENDING.getValue()), attribute(response, ScepConstants.id_pkiStatus));
        Certificate completed = certificateRepository.findWithAssociationsByUuid(placeholder.getUuid()).orElseThrow();
        assertEquals(CertificateState.REGISTERED, completed.getState(),
                "the placeholder stays REGISTERED until the async ISSUE action completes");
        assertNotNull(completed.getCertificateRequestUuid(), "the enrolment CSR is attached");
        List<CertificateProtocolAssociation> certificateProtocolAssociation = certificateProtocolAssociationRepository
                .findAll();
        Optional<CertificateProtocolAssociation> association = certificateProtocolAssociation
                .stream()
                .filter(pa -> pa.getCertificateUuid().equals(completed.getUuid())
                        && pa.getProtocol() == CertificateProtocol.SCEP)
                .findFirst();
        assertTrue(association.isPresent(), "the completion is attributed to SCEP");
        assertTrue(scepTransactionRepository.findByTransactionId(ScepMessageTestData.TRANSACTION_ID).isPresent(),
                "the poll transaction is stored");
        verify(actionProducer).produceMessage(Mockito.argThat(m -> m.getResourceAction() == ResourceAction.ISSUE));
    }

    @Test
    void enrolmentSubjectDifferingOnlyInRdnOrderStillMatches() throws Exception {
        // The SQL prefilter compares the stored normalized subject, so a CSR presenting the same identity
        // with reordered RDNs must still reach the identity match and complete.
        registeredPlaceholder("O=Acme, CN=device-rdn", Map.of("dNSName", List.of("device-rdn.example")), CHALLENGE);

        ResponseEntity<Object> response = postPkiOperation(
                enrolment("CN=device-rdn, O=Acme", List.of("device-rdn.example"), CHALLENGE));

        assertScepFormatted(response);
        assertEquals(String.valueOf(PkiStatus.PENDING.getValue()), attribute(response, ScepConstants.id_pkiStatus));
    }

    @Test
    void differentKeyReplayCannotReplaceTheAttachedCsr() throws Exception {
        // A fresh-key second completion must not overwrite the first CSR. The certificate row lock serializes
        // concurrent completions into this same second attach, so a sequential replay deterministically covers
        // the race, and a fresh transaction id stops the SCEP dedup from folding the replay into a poll.
        Certificate placeholder = registeredPlaceholder(SUBJECT_DN, Map.of("dNSName", List.of("device-1.example")),
                CHALLENGE);

        ResponseEntity<Object> first = postPkiOperation(enrolment(SUBJECT_DN, List.of("device-1.example"), CHALLENGE));
        assertEquals(String.valueOf(PkiStatus.PENDING.getValue()), attribute(first, ScepConstants.id_pkiStatus));
        UUID boundRequest = certificateRepository
                .findByUuid(placeholder.getUuid())
                .orElseThrow()
                .getCertificateRequestUuid();
        assertNotNull(boundRequest, "the first enrolment binds its CSR");

        String replayTransactionId = "aa1ba25258bfc72fe6cf8aa70f75e21facd8fc3d";
        ResponseEntity<Object> second = postPkiOperation(ScepMessageTestData
                .keyTransportEnvelopedPkcsReq(caCertificateX509(), SUBJECT_DN, List.of("device-1.example"), CHALLENGE,
                        replayTransactionId));

        assertRegistrationRejection(second);
        assertEquals(boundRequest,
                certificateRepository.findByUuid(placeholder.getUuid()).orElseThrow().getCertificateRequestUuid(),
                "the first enrolment's CSR must not be replaced by the different-key replay");
        assertTrue(
                scepTransactionRepository.findByTransactionIdAndScepProfile(replayTransactionId, scepProfile).isEmpty(),
                "the rejected replay's staged poll mapping is discarded");
    }

    @Test
    void aCompletionThatFailsBeforeTheIssueIsEnqueuedDiscardsTheStagedPollMapping() throws Exception {
        // The poll mapping is staged before the ISSUE is published. A failure before the enqueue (here a failed
        // publish, standing in for a row-lock timeout or infrastructure error) must not leave the mapping behind,
        // or a retry with the same key-derived transaction id would be short-circuited to a poll that never completes.
        registeredPlaceholder(SUBJECT_DN, Map.of("dNSName", List.of("device-1.example")), CHALLENGE);
        doThrow(new IllegalStateException("action broker unavailable"))
                .when(actionProducer)
                .produceMessage(Mockito.any());

        postPkiOperation(enrolment(SUBJECT_DN, List.of("device-1.example"), CHALLENGE));

        assertTrue(scepTransactionRepository.findByTransactionId(ScepMessageTestData.TRANSACTION_ID).isEmpty(),
                "a completion that fails before the ISSUE is enqueued leaves no poll mapping");
    }

    @Test
    void subjectlessRegistrationCompletesBySanOnly() throws Exception {
        // A SAN-only pre-registration carries no subject; a subjectless enrolment must still match it on SANs.
        Certificate placeholder = registeredPlaceholder(null, Map.of("dNSName", List.of("device-1.example")),
                CHALLENGE);

        ResponseEntity<Object> response = postPkiOperation(enrolment("", List.of("device-1.example"), CHALLENGE));

        assertScepFormatted(response);
        assertEquals(String.valueOf(PkiStatus.PENDING.getValue()), attribute(response, ScepConstants.id_pkiStatus));
        Certificate completed = certificateRepository.findByUuid(placeholder.getUuid()).orElseThrow();
        assertEquals(CertificateState.REGISTERED, completed.getState());
        assertNotNull(completed.getCertificateRequestUuid(), "the subjectless enrolment CSR is attached");
    }

    @Test
    void transactionLookupIsScopedByScepProfile() {
        // Transaction ids are client-chosen and can collide across profiles, so a poll's fetch must resolve only
        // the polling profile's transaction — never another profile's registration behind the same id (which in
        // registration mode would recover the wrong challenge for the response envelope).
        ScepProfile otherProfile = new ScepProfile();
        otherProfile.setName("otherRegistrationProfile");
        otherProfile.setEnabled(true);
        otherProfile.setRequireManualApproval(false);
        otherProfile.setIncludeCaCertificate(true);
        otherProfile.setChallengeSource(ProtocolChallengeSource.CERTIFICATE_REGISTRATION);
        otherProfile.setCaCertificate(scepProfile.getCaCertificate());
        otherProfile.setRaProfile(scepProfile.getRaProfile());
        otherProfile = scepProfileRepository.save(otherProfile);

        UUID certUnderThisProfile = savedCertificate();
        UUID certUnderOtherProfile = savedCertificate();
        String sharedTransactionId = "shared-across-profiles";
        storeTransaction(sharedTransactionId, certUnderThisProfile, scepProfile);
        storeTransaction(sharedTransactionId, certUnderOtherProfile, otherProfile);

        assertEquals(certUnderThisProfile,
                scepTransactionRepository
                        .findByTransactionIdAndScepProfile(sharedTransactionId, scepProfile)
                        .orElseThrow()
                        .getCertificateUuid(),
                "the fetch must return this profile's transaction, not the colliding one");
        assertEquals(certUnderOtherProfile,
                scepTransactionRepository
                        .findByTransactionIdAndScepProfile(sharedTransactionId, otherProfile)
                        .orElseThrow()
                        .getCertificateUuid());
    }

    private UUID savedCertificate() {
        Certificate certificate = new Certificate();
        certificate.setState(CertificateState.REGISTERED);
        certificate.setRaProfile(raProfile);
        return certificateRepository.save(certificate).getUuid();
    }

    private void storeTransaction(String transactionId, UUID certificateUuid, ScepProfile profile) {
        ScepTransaction transaction = new ScepTransaction();
        transaction.setTransactionId(transactionId);
        transaction.setCertificateUuid(certificateUuid);
        transaction.setScepProfile(profile);
        scepTransactionRepository.save(transaction);
    }

    @Test
    void wrongChallengeIsRejectedGenericallyAndCounted() throws Exception {
        Certificate placeholder = registeredPlaceholder(SUBJECT_DN, null, CHALLENGE);

        ResponseEntity<Object> response = postPkiOperation(enrolment(SUBJECT_DN, null, "wrong-challenge"));

        assertRegistrationRejection(response);
        CertificateRegistrationAuthorization authorization = authorizationRepository
                .findByCertificateUuid(placeholder.getUuid())
                .orElseThrow();
        assertEquals(1, authorization.getFailedAttempts(), "the failed attempt survives the rejection");
        Certificate untouched = certificateRepository.findByUuid(placeholder.getUuid()).orElseThrow();
        assertEquals(CertificateState.REGISTERED, untouched.getState());
        assertNull(untouched.getCertificateRequestUuid(), "no CSR is attached on a rejected challenge");
    }

    @Test
    void lockoutBlocksEvenTheCorrectChallenge() throws Exception {
        Certificate placeholder = registeredPlaceholder(SUBJECT_DN, null, CHALLENGE);

        for (int attempt = 0; attempt < CertificateRegistrationDefaults.MAX_FAILED_ATTEMPTS; attempt++) {
            assertRegistrationRejection(postPkiOperation(enrolment(SUBJECT_DN, null, "wrong-challenge")));
        }
        CertificateRegistrationAuthorization authorization = authorizationRepository
                .findByCertificateUuid(placeholder.getUuid())
                .orElseThrow();
        assertEquals(RegistrationState.LOCKED, authorization.getState(), "lockout after the configured attempts");

        ResponseEntity<Object> lockedResponse = postPkiOperation(enrolment(SUBJECT_DN, null, CHALLENGE));

        // A LOCKED authorization drops out of the ACTIVE-scoped finder, so even the correct challenge is
        // indistinguishable from any other miss.
        assertRegistrationRejection(lockedResponse);
        assertNull(certificateRepository.findByUuid(placeholder.getUuid()).orElseThrow().getCertificateRequestUuid());
    }

    @Test
    void expiredIssuanceWindowRejectsAndExpiresTheAuthorization() throws Exception {
        Certificate placeholder = registeredPlaceholder(SUBJECT_DN, null, CHALLENGE);
        CertificateRegistrationAuthorization authorization = authorizationRepository
                .findByCertificateUuid(placeholder.getUuid())
                .orElseThrow();
        authorization.setExpiresAt(OffsetDateTime.now().minusMinutes(1));
        authorizationRepository.save(authorization);

        ResponseEntity<Object> response = postPkiOperation(enrolment(SUBJECT_DN, null, CHALLENGE));

        assertRegistrationRejection(response);
        assertEquals(RegistrationState.EXPIRED,
                authorizationRepository.findByCertificateUuid(placeholder.getUuid()).orElseThrow().getState());
    }

    @Test
    void unknownSubjectIsIndistinguishableFromWrongChallenge() throws Exception {
        registeredPlaceholder(SUBJECT_DN, null, CHALLENGE);

        ResponseEntity<Object> wrongChallenge = postPkiOperation(enrolment(SUBJECT_DN, null, "wrong-challenge"));
        ResponseEntity<Object> unknownSubject = postPkiOperation(enrolment("CN=unregistered-device", null, CHALLENGE));

        assertRegistrationRejection(wrongChallenge);
        assertRegistrationRejection(unknownSubject);
        assertEquals(attribute(wrongChallenge, ScepConstants.id_scep_failInfoText),
                attribute(unknownSubject, ScepConstants.id_scep_failInfoText),
                "a prober must not distinguish a wrong challenge from an unknown registration");
    }

    @Test
    void ambiguousRegistrationsAreRejected() throws Exception {
        registeredPlaceholder("CN=fleet", Map.of("dNSName", List.of("a.example")), CHALLENGE);
        registeredPlaceholder("CN=fleet", Map.of("dNSName", List.of("a.example")), CHALLENGE);

        ResponseEntity<Object> response = postPkiOperation(enrolment("CN=fleet", List.of("a.example"), CHALLENGE));

        assertRegistrationRejection(response);
    }

    @Test
    void sanMismatchRejectsAndRecordsEventHistory() throws Exception {
        Certificate placeholder = registeredPlaceholder(SUBJECT_DN, Map.of("dNSName", List.of("registered.example")),
                CHALLENGE);

        ResponseEntity<Object> response = postPkiOperation(enrolment(SUBJECT_DN, List.of("other.example"), CHALLENGE));

        assertRegistrationRejection(response);
        List<CertificateEventHistory> history = eventHistoryRepository.findByCertificateOrderByCreatedDesc(placeholder);
        assertTrue(
                history
                        .stream()
                        .anyMatch(event -> event.getStatus() == CertificateEventStatus.FAILED
                                && event.getMessage().contains("subject alternative names")),
                "the SAN mismatch is recorded on the matched registration");
    }

    @Test
    void passwordRecipientRequestCannotBeDecrypted() throws Exception {
        Certificate placeholder = registeredPlaceholder(ScepMessageTestData.SUBJECT_DN, null, CHALLENGE);

        // No decrypt stub: the profile has no shared password, so a password-recipient request is
        // undecryptable by construction and must be answered as a SCEP failure.
        ResponseEntity<Object> response = scepService
                .handlePost(SCEP_PROFILE_NAME, ScepServiceImpl.SCEP_OPERATION_PKI_OPERATION,
                        ScepMessageTestData.passwordEnvelopedPkcsReq(CHALLENGE));

        assertScepFormatted(response);
        assertEquals(String.valueOf(PkiStatus.FAILURE.getValue()), attribute(response, ScepConstants.id_pkiStatus));
        assertEquals(String.valueOf(FailInfo.BAD_REQUEST.getValue()), attribute(response, ScepConstants.id_failInfo));
        // Rejected before any completion: the placeholder is untouched and no issuance is enqueued, so the test
        // cannot pass on an unrelated setup, connector, or response-building failure that also ends in FAILURE.
        Certificate untouched = certificateRepository.findByUuid(placeholder.getUuid()).orElseThrow();
        assertEquals(CertificateState.REGISTERED, untouched.getState());
        assertNull(untouched.getCertificateRequestUuid());
        verify(actionProducer, never()).produceMessage(Mockito.any());
    }

    @Test
    void authenticatedRenewalBypassesTheGateButAnEcClientCannotBeAnswered() throws Exception {
        registerSignerCertificate();

        ResponseEntity<Object> response = postPkiOperation(ScepMessageTestData
                .keyTransportEnvelopedPkcsReq(caCertificateX509(), ScepMessageTestData.SUBJECT_DN, null, null));

        assertScepFormatted(response);
        // The renewal gets past the registration gate (which rejects with badMessageCheck) and is then
        // rejected by the envelope preflight: the EC signer cannot take a key-transport envelope and a
        // renewal presents no challenge to envelope with — the documented registration-mode limitation
        // for non-RSA client keys.
        assertEquals(String.valueOf(FailInfo.BAD_ALG.getValue()), attribute(response, ScepConstants.id_failInfo),
                "an authenticated renewal must get past the registration gate to the envelope preflight");
    }

    private byte[] enrolment(String subjectDn, List<String> dnsSans, String challengePassword) throws Exception {
        return ScepMessageTestData
                .keyTransportEnvelopedPkcsReq(caCertificateX509(), subjectDn, dnsSans, challengePassword);
    }

    private X509Certificate caCertificateX509() throws Exception {
        return CertificateUtil.parseCertificate(scepProfile.getCaCertificate().getCertificateContent().getContent());
    }

    private ResponseEntity<Object> postPkiOperation(byte[] message) throws Exception {
        stubConnectorDecrypt(message);
        return scepService.handlePost(SCEP_PROFILE_NAME, ScepServiceImpl.SCEP_OPERATION_PKI_OPERATION, message);
    }

    /**
     * The connector decrypt must return the real content-encryption key or the CSR can never be read: the key is
     * extracted from the message's KeyTransRecipientInfo and decrypted locally with the test-held CA private key, and
     * the stub returns exactly that value. Later stubs override earlier ones, so each message gets its own.
     */
    private void stubConnectorDecrypt(byte[] scepMessage) throws Exception {
        byte[] encryptedKey = extractEncryptedContentEncryptionKey(scepMessage);
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, caKeyPair.getPrivate());
        byte[] contentEncryptionKey = cipher.doFinal(encryptedKey);

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/decrypt"))
                        .willReturn(WireMock.okJson("""
                                {"decryptedData": [{"data": "%s"}]}
                                """.formatted(Base64.getEncoder().encodeToString(contentEncryptionKey)))));
    }

    private static byte[] extractEncryptedContentEncryptionKey(byte[] scepMessage) throws Exception {
        CMSSignedData signedData = new CMSSignedData(scepMessage);
        ContentInfo envelopedContentInfo = ContentInfo.getInstance((byte[]) signedData.getSignedContent().getContent());
        EnvelopedData envelopedData = EnvelopedData.getInstance(envelopedContentInfo.getContent());
        RecipientInfo recipientInfo = RecipientInfo.getInstance(envelopedData.getRecipientInfos().getObjectAt(0));
        KeyTransRecipientInfo keyTransRecipientInfo = KeyTransRecipientInfo.getInstance(recipientInfo.getInfo());
        return keyTransRecipientInfo.getEncryptedKey().getOctets();
    }

    private Certificate registeredPlaceholder(String subjectDn, Map<String, List<String>> sans, String challenge) {
        Certificate placeholder = new Certificate();
        placeholder.setSubjectDn(subjectDn);
        placeholder.setSubjectDnNormalized(CertificateUtil.normalizeStoredSubjectDn(subjectDn));
        if (sans != null) {
            placeholder.setSubjectAlternativeNames(CertificateUtil.serializeSans(sans));
        }
        placeholder.setState(CertificateState.REGISTERED);
        placeholder.setRaProfile(raProfile);
        placeholder = certificateRepository.save(placeholder);

        CertificateRegistrationAuthorization authorization = new CertificateRegistrationAuthorization();
        authorization.setCertificateUuid(placeholder.getUuid());
        authorization.setState(RegistrationState.ACTIVE);
        authorization.setFailedAttempts(0);
        authorization.setExpiresAt(OffsetDateTime.now().plusDays(7));
        registrationChallengeStore.store(authorization, challenge);
        authorizationRepository.save(authorization);
        return placeholder;
    }

    private void assertRegistrationRejection(ResponseEntity<Object> response) throws Exception {
        assertScepFormatted(response);
        assertEquals(String.valueOf(PkiStatus.FAILURE.getValue()), attribute(response, ScepConstants.id_pkiStatus));
        assertEquals(String.valueOf(FailInfo.BAD_MESSAGE_CHECK.getValue()),
                attribute(response, ScepConstants.id_failInfo));
        assertEquals(REGISTRATION_REJECTION, attribute(response, ScepConstants.id_scep_failInfoText));
    }

    private void assertScepFormatted(ResponseEntity<Object> response) throws Exception {
        assertEquals("application/x-pki-message", response.getHeaders().getFirst("Content-Type"),
                "a SCEP client can only parse application/x-pki-message");
        assertNotNull(response.getBody());
        assertNotNull(new CMSSignedData((byte[]) response.getBody()).getSignerInfos().getSigners());
    }

    private String attribute(ResponseEntity<Object> response, String oid) throws Exception {
        CMSSignedData signedData = new CMSSignedData((byte[]) response.getBody());
        SignerInformation signer = signedData.getSignerInfos().getSigners().iterator().next();
        ASN1Primitive value = signer
                .getSignedAttributes()
                .get(new ASN1ObjectIdentifier(oid))
                .getAttrValues()
                .getObjectAt(0)
                .toASN1Primitive();
        return ((ASN1String) value).getString();
    }

    /**
     * Registers the request's signer certificate as an issued certificate of this RA profile, with the subject the
     * request asks for and a validity inside the default half-life renewal window.
     */
    private void registerSignerCertificate() throws Exception {
        X509Certificate signerCertificate = ScepMessageTestData.signerCertificate();
        Certificate certificate = storeCertificate(signerCertificate, null, raProfile);
        certificate.setSubjectDn(new X500Name(ScepMessageTestData.SUBJECT_DN).toString());
        certificate.setNotBefore(new Date(System.currentTimeMillis() - 30L * 24 * 3600 * 1000));
        certificate.setNotAfter(new Date(System.currentTimeMillis() + 10L * 24 * 3600 * 1000));
        certificateRepository.save(certificate);
    }

    private Certificate storeCertificate(X509Certificate x509Certificate, CryptographicKey key, RaProfile owner)
            throws Exception {
        String encoded = Base64.getEncoder().encodeToString(x509Certificate.getEncoded());
        String fingerprint = CertificateUtil.getThumbprint(x509Certificate);

        CertificateContent content = new CertificateContent();
        content.setContent(encoded);
        content.setFingerprint(fingerprint);
        content = certificateContentRepository.save(content);

        Certificate certificate = new Certificate();
        certificate.setCertificateContent(content);
        certificate.setCertificateContentId(content.getId());
        certificate.setFingerprint(fingerprint);
        certificate.setSubjectDn(x509Certificate.getSubjectX500Principal().getName());
        certificate.setIssuerDn(x509Certificate.getIssuerX500Principal().getName());
        certificate.setSerialNumber(x509Certificate.getSerialNumber().toString(16));
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setNotBefore(x509Certificate.getNotBefore());
        certificate.setNotAfter(x509Certificate.getNotAfter());
        if (key != null) {
            certificate.setKey(key);
        }
        if (owner != null) {
            certificate.setRaProfile(owner);
        }
        return certificateRepository.save(certificate);
    }

    private static X509Certificate selfSignedRsaCertificate(KeyPair keyPair) throws Exception {
        X500Name dn = new X500Name(CA_DN);
        Date notBefore = new Date(System.currentTimeMillis() - 3_600_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(dn,
                BigInteger.valueOf(System.currentTimeMillis()), notBefore, notAfter, dn, keyPair.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA")
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .build(keyPair.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    /**
     * The token connector signs the response. The value is passed through without verification here, so a fixed
     * well-formed signature is enough to exercise the real response-building path.
     */
    private void stubTokenSigning() throws Exception {
        KeyPair throwaway = KeyPairGenerator.getInstance("EC").generateKeyPair();
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(throwaway.getPrivate());
        signature.update("scep".getBytes());
        String signed = Base64.getEncoder().encodeToString(signature.sign());

        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/sign"))
                        .willReturn(WireMock.okJson("""
                                {"signatures": [{"data": "%s"}]}
                                """.formatted(signed))));
        mockServer
                .stubFor(WireMock
                        .post(WireMock.urlPathMatching("/v1/cryptographyProvider/tokens/[^/]+/keys/[^/]+/verify"))
                        .willReturn(WireMock.okJson("""
                                {"verifications": [{"result": true}]}
                                """)));
    }
}
