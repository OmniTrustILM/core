package com.otilm.core.service.scep.impl;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ScepException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.v2.DataAttributeV2;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.certificate.CertificateDetailDto;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.logging.enums.Operation;
import com.otilm.api.model.core.protocol.ProtocolChallengeSource;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.api.model.core.scep.MessageType;
import com.otilm.api.model.core.scep.PkiStatus;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.api.model.core.v2.ClientCertificateRequestDto;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeOperation;
import com.otilm.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.client.ConnectorApiFactory;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import com.otilm.core.dao.entity.CryptographicKeyItem;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.dao.entity.scep.ScepTransaction;
import com.otilm.core.dao.repository.CertificateRegistrationAuthorizationRepository;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.scep.ScepProfileRepository;
import com.otilm.core.dao.repository.scep.ScepTransactionRepository;
import com.otilm.core.intune.scepvalidation.IntuneConfigProperties;
import com.otilm.core.intune.scepvalidation.IntuneScepServiceClient;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.model.request.Pkcs10CertificateRequest;
import com.otilm.core.provider.PlatformProvider;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.security.authz.ProtocolEndpoint;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.service.handler.CertificateValidationStatusPoller;
import com.otilm.core.service.registration.RegistrationChallengeStore;
import com.otilm.core.service.registration.RegistrationIdentityMatcher;
import com.otilm.core.service.scep.ScepExternalService;
import com.otilm.core.service.scep.message.ScepRequest;
import com.otilm.core.service.scep.message.ScepResponse;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.AttributeDefinitionUtils;
import com.otilm.core.util.CertificateEligibilityUtil;
import com.otilm.core.util.CertificateRequestUtils;
import com.otilm.core.util.CertificateUtil;
import com.otilm.core.util.RandomUtil;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaCertStore;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCSException;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.NoTransactionException;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.interceptor.TransactionAspectSupport;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

@Service
// noRollbackFor keeps Spring's default (no rollback on checked exceptions): SCEP surfaces
// these as protocol error responses rather than treating them as transaction failures.
@Transactional(noRollbackFor = {ScepException.class, NotFoundException.class})
public class ScepServiceImpl implements ScepExternalService {

    public static final String SCEP_URL_PREFIX = "/v1/protocols/scep";
    public static final String SCEP_OPERATION_GET_CA_CERT = "GetCACert";
    public static final String SCEP_OPERATION_GET_CA_CAPS = "GetCACaps";
    public static final String SCEP_OPERATION_PKI_OPERATION = "PKIOperation";

    private static final Logger logger = LoggerFactory.getLogger(ScepServiceImpl.class);
    private static final List<String> SCEP_CA_CAPABILITIES = List
            .of("POSTPKIOperation", "SHA-1", "SHA-256", "SHA-512", "DES3", "AES", "Renewal", "SCEPStandard");
    // The principle: reject only on evidence that the certificate itself is unusable. EnumSet is used
    // deliberately here and below: unlike Set.of it tolerates a null argument to contains().
    private static final Set<CertificateValidationStatus> NON_RENEWABLE_VALIDATION_STATUSES = EnumSet
            .of(CertificateValidationStatus.REVOKED, CertificateValidationStatus.EXPIRED,
                    CertificateValidationStatus.INVALID);
    // FAILED means the platform could not complete validation (an unreachable CRL or OCSP responder), which
    // is not evidence against the certificate — so it does not reject the renewal. It is not evidence for the
    // certificate either, so it withholds the challenge password waiver and the shared secret is required.
    private static final Set<CertificateValidationStatus> INCONCLUSIVE_VALIDATION_STATUSES = EnumSet
            .of(CertificateValidationStatus.FAILED);

    private IntuneConfigProperties intuneConfigProperties;

    private List<X509Certificate> caCertificateChain = new ArrayList<>();
    private X509Certificate recipient;
    private boolean raProfileBased;
    private RaProfile raProfile;
    private List<RequestAttribute> issueAttributes;
    private ScepProfile scepProfile;
    private RaProfileRepository raProfileRepository;
    private ScepProfileRepository scepProfileRepository;
    private ScepTransactionRepository scepTransactionRepository;
    private ScepRegistrationTrackingWriter scepRegistrationTrackingWriter;
    private CertificateRepository certificateRepository;
    private CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository;
    private RegistrationChallengeStore registrationChallengeStore;
    private CertificateEventHistoryInternalService certificateEventHistoryService;
    private ClientOperationInternalService clientOperationService;
    private ClientOperationExternalService clientOperationExternalService;
    private CertificateInternalService certificateService;
    private CertificateValidationStatusPoller validationStatusPoller;
    private CryptographicKeyInternalService cryptographicKeyService;
    private ConnectorApiFactory connectorApiFactory;
    private AttributeEngine attributeEngine;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    @Autowired
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    @Autowired
    public void setIntuneConfigProperties(IntuneConfigProperties intuneConfigProperties) {
        this.intuneConfigProperties = intuneConfigProperties;
    }

    @Autowired
    public void setScepProfileRepository(ScepProfileRepository scepProfileRepository) {
        this.scepProfileRepository = scepProfileRepository;
    }

    @Autowired
    public void setScepTransactionRepository(ScepTransactionRepository scepTransactionRepository) {
        this.scepTransactionRepository = scepTransactionRepository;
    }

    @Autowired
    public void setScepRegistrationTrackingWriter(ScepRegistrationTrackingWriter scepRegistrationTrackingWriter) {
        this.scepRegistrationTrackingWriter = scepRegistrationTrackingWriter;
    }

    @Autowired
    public void setClientOperationService(ClientOperationInternalService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Autowired
    public void setClientOperationExternalService(ClientOperationExternalService clientOperationExternalService) {
        this.clientOperationExternalService = clientOperationExternalService;
    }

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    @Autowired
    public void setRegistrationAuthorizationRepository(
            CertificateRegistrationAuthorizationRepository registrationAuthorizationRepository) {
        this.registrationAuthorizationRepository = registrationAuthorizationRepository;
    }

    @Autowired
    public void setRegistrationChallengeStore(RegistrationChallengeStore registrationChallengeStore) {
        this.registrationChallengeStore = registrationChallengeStore;
    }

    @Autowired
    public void setCertificateEventHistoryService(
            CertificateEventHistoryInternalService certificateEventHistoryService) {
        this.certificateEventHistoryService = certificateEventHistoryService;
    }

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setValidationStatusPoller(CertificateValidationStatusPoller validationStatusPoller) {
        this.validationStatusPoller = validationStatusPoller;
    }

    @Autowired
    public void setCryptographicKeyInternalService(CryptographicKeyInternalService cryptographicKeyService) {
        this.cryptographicKeyService = cryptographicKeyService;
    }

    @Autowired
    public void setConnectorApiFactory(ConnectorApiFactory connectorApiFactory) {
        this.connectorApiFactory = connectorApiFactory;
    }

    public void setRecipient(String certificateContent) {
        try {
            this.recipient = CertificateUtil.parseCertificate(certificateContent);
        } catch (CertificateException e) {
            // This should not occur
            throw new IllegalArgumentException("Error converting the certificate to x509 object");
        }
    }

    @Override
    @ProtocolEndpoint
    public ResponseEntity<Object> handleGet(String profileName, String operation, String message) throws ScepException {
        logger
                .debug("SCEP GET request received for profile: {}, operation: {}, message: {}", profileName, operation,
                        message);
        byte[] encoded = new byte[0];
        if (message != null) {
            encoded = message.getBytes();
        }
        return service(profileName, operation, encoded);
    }

    @Override
    @ProtocolEndpoint
    public ResponseEntity<Object> handlePost(String profileName, String operation, byte[] message)
            throws ScepException {
        if (logger.isDebugEnabled()) {
            logger
                    .debug("SCEP POST request received for profile: {}, operation: {}, message: {}", profileName,
                            operation, Base64.getEncoder().encodeToString(message));
        }
        return service(profileName, operation, message);
    }

    private ResponseEntity<Object> service(String profileName, String operation, byte[] message) throws ScepException {
        init(profileName);
        validateProfile();
        logger.info("SCEP request received for profile: {}, operation: {}", profileName, operation);
        return switch (operation) {
            case SCEP_OPERATION_GET_CA_CERT -> {
                LoggingHelper.putAuditLogOperation(Operation.LIST_PROTOCOL_CERTIFICATES);
                yield getCaCerts();
            }
            case SCEP_OPERATION_GET_CA_CAPS -> {
                LoggingHelper.putAuditLogOperation(Operation.SCEP_CA_CAPABILITIES);
                yield getCaCaps();
            }
            case SCEP_OPERATION_PKI_OPERATION -> pkiOperation(message);
            default -> buildResponse(null,
                    buildFailedResponse(new ScepException("Unsupported Operation", FailInfo.BAD_REQUEST), null));
        };
    }

    private void init(String profileName) throws ScepException {
        this.raProfileBased = ServletUriComponentsBuilder
                .fromCurrentRequestUri()
                .build()
                .toUriString()
                .contains("/raProfile/");
        if (raProfileBased) {
            raProfile = raProfileRepository.findByName(profileName).orElse(null);
            if (raProfile == null) {
                return;
            }
            scepProfile = raProfile.getScepProfile();
            String attributesJson = raProfile.getProtocolAttribute() != null
                    ? raProfile.getProtocolAttribute().getScepIssueCertificateAttributes()
                    : null;
            issueAttributes = AttributeDefinitionUtils
                    .getClientAttributes(AttributeDefinitionUtils.deserialize(attributesJson, DataAttributeV2.class));
        } else {
            scepProfile = scepProfileRepository.findByName(profileName).orElse(null);
            if (scepProfile == null) {
                return;
            }
            raProfile = scepProfile.getRaProfile();
            if (raProfile == null) {
                return;
            }

            issueAttributes = attributeEngine
                    .getRequestObjectDataAttributesContent(ObjectAttributeContentInfo
                            .builder(Resource.SCEP_PROFILE, scepProfile.getUuid())
                            .connector(scepProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid())
                            .operation(AttributeOperation.CERTIFICATE_ISSUE)
                            .build());
        }
        LoggingHelper
                .putLogResourceInfo(Resource.SCEP_PROFILE, true, scepProfile.getUuid().toString(),
                        scepProfile.getName());

        Certificate scepCaCertificate = scepProfile.getCaCertificate();
        if (scepCaCertificate == null) {
            throw new ScepException("SCEP Profile does not have any associated CA certificate", FailInfo.BAD_REQUEST);
        }

        setRecipient(scepCaCertificate.getCertificateContent().getContent());
        try {
            this.caCertificateChain = loadCertificateChain(scepCaCertificate, false);
        } catch (NotFoundException e) {
            throw new ScepException("Failed to load certificate chain of SCEP profile CA certificate");
        }

        logger
                .debug("SCEP service initialized: isRaProfileBased: {}, raProfile: {}, scepProfile: {}", raProfileBased,
                        raProfile, scepProfile);
    }

    private void validateProfile() throws ScepException {
        validateScepProfile();
        validateRaProfile();
    }

    private void validateScepProfile() throws ScepException {
        if (scepProfile == null) {
            throw new ScepException("Requested SCEP Profile not found", FailInfo.BAD_REQUEST);
        }
        if (scepProfile.isEnabled() == null || Boolean.FALSE.equals(scepProfile.isEnabled())) {
            throw new ScepException("SCEP Profile is not enabled", FailInfo.BAD_REQUEST);
        }
        if (scepProfile.getCaCertificate() == null) {
            throw new ScepException("SCEP Profile does not have any associated CA certificate", FailInfo.BAD_REQUEST);
        }
        if (!CertificateEligibilityUtil
                .isCertificateScepCaCertAcceptable(scepProfile.getCaCertificate(), scepProfile.isIntuneEnabled())) {
            throw new ScepException("SCEP Profile does not have associated acceptable CA certificate",
                    FailInfo.BAD_REQUEST);
        }
        if (!raProfileBased && scepProfile.getRaProfile() == null) {
            throw new ScepException("SCEP Profile does not contain associated RA Profile", FailInfo.BAD_REQUEST);
        }
    }

    private void validateRaProfile() throws ScepException {
        if (raProfile == null) {
            throw new ScepException("Requested RA Profile not found", FailInfo.BAD_REQUEST);
        }
        if (raProfile.getEnabled() == null || Boolean.FALSE.equals(raProfile.getEnabled())) {
            throw new ScepException("RA Profile is not enabled", FailInfo.BAD_REQUEST);
        }
        if (raProfileBased && raProfile.getScepProfile() == null) {
            throw new ScepException("RA Profile does not contain associated SCEP Profile", FailInfo.BAD_REQUEST);
        }
    }

    private ResponseEntity<Object> getCaCerts() {
        byte[] encoded;
        try {
            if (caCertificateChain.size() > 1) {
                logger.debug("Certificate chain is more than one, returning CA-RA certificate");
                CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
                generator.addCertificates(new JcaCertStore(caCertificateChain));
                encoded = generator.generate(new CMSProcessableByteArray(new byte[0])).getEncoded();
                return getResponseEntity(encoded, "application/x-x509-ca-ra-cert", encoded.length);
            } else {
                logger.debug("Certificate chain is one, returning CA certificate");
                encoded = recipient.getEncoded();
                return getResponseEntity(encoded, "application/x-x509-ca-cert", encoded.length);
            }
        } catch (CertificateException | CMSException | IOException e) {
            // This should not happen
            throw new IllegalArgumentException("Error converting the certificate to x509 object");
        }
    }

    private ResponseEntity<Object> getCaCaps() {
        logger.debug("Returning CA capabilities");
        return getResponseEntity(String.join(System.lineSeparator(), SCEP_CA_CAPABILITIES), "text/plain", null);
    }

    private ResponseEntity<Object> getResponseEntity(Object body, String contentType, Integer contentLength) {
        HttpHeaders responseHeaders = new HttpHeaders();
        responseHeaders.set("Content-Type", contentType);
        if (contentLength != null) {
            responseHeaders.set("Content-Length", String.valueOf(contentLength));
        }
        return new ResponseEntity<>(body, responseHeaders, HttpStatus.OK);
    }

    private ResponseEntity<Object> pkiOperation(byte[] body) throws ScepException {
        ScepRequest scepRequest = null;
        try {
            // Parsing the request belongs inside the guard: the body is attacker-supplied DER and
            // BouncyCastle reports malformed structures with unchecked exceptions.
            scepRequest = new ScepRequest(body);
            return processPkiOperation(scepRequest);
        } catch (Exception e) {
            // Any failure here would otherwise escape to the generic error handler and leave the client with a
            // JSON body it cannot parse — including the checked ScepException that response building raises
            // when signing fails. Answer with a SCEP FAILURE instead, so the endpoint responds in
            // application/x-pki-message. The failInfoText is generic on purpose: internal exception messages
            // are not shaped for the wire.
            if (scepRequest == null) {
                // The message did not parse, so there is no transaction id or nonce to echo and no SCEP
                // response can be formed. Surface it as a protocol-level error instead.
                logger.error("Failed to parse the SCEP PKIOperation request", e);
                throw e instanceof ScepException scepException
                        ? scepException
                        : new ScepException("Failed to parse the SCEP request", FailInfo.BAD_REQUEST);
            }
            String transactionId = scepRequest.getTransactionId();
            logger.error("Unexpected failure while processing SCEP PKIOperation: transactionId={}", transactionId, e);
            // Discard whatever the failed attempt wrote before answering.
            markCurrentTransactionRollbackOnly();
            try {
                return buildResponse(scepRequest, buildFailedResponse(
                        new ScepException("SCEP request processing failed", FailInfo.BAD_REQUEST), transactionId));
            } catch (Exception failureResponseError) { // NOSONAR - the fallback must not itself escape
                // Building the failure needs the profile's CA key through the token connector; when that is
                // what broke, no SCEP message can be produced at all. Answer with a bare status rather than
                // a JSON body the client cannot parse.
                logger.error("Failed to build the SCEP failure response", failureResponseError);
                return new ResponseEntity<>(HttpStatus.INTERNAL_SERVER_ERROR);
            }
        }
    }

    /**
     * Rolls back the work of a failed PKIOperation without discarding the failure response: a locally set rollback-only
     * flag makes Spring roll the transaction back at the boundary and still return this method's value. A flag already
     * set by a nested transactional collaborator is global, and that commit fails with
     * {@code UnexpectedRollbackException} regardless — guaranteeing the protocol format for a failure raised inside a
     * nested transaction needs the boundary to sit outside the transaction.
     */
    private void markCurrentTransactionRollbackOnly() {
        try {
            TransactionAspectSupport.currentTransactionStatus().setRollbackOnly();
        } catch (NoTransactionException e) {
            // No active transaction (e.g. a unit test driving the service directly) — nothing to roll back.
            logger.debug("No active transaction to roll back for the failed SCEP request");
        }
    }

    private ResponseEntity<Object> processPkiOperation(ScepRequest scepRequest) throws ScepException {
        logger.debug("Processing SCEP request: transactionId={}", scepRequest.getTransactionId());

        try {
            decryptRequestData(scepRequest);
        } catch (ScepException | CMSException e) {
            // ScepException covers the undecryptable cases decryptData rejects itself (e.g. a password
            // recipient with no challenge password configured); answering here keeps the response in the
            // SCEP format instead of letting it reach the generic JSON error handler.
            ScepException failure;
            if (e instanceof ScepException scepException) {
                failure = scepException;
            } else {
                // The CMS detail stays in the log: failInfoText is read by an unauthenticated client and
                // parsing internals are not shaped for the wire.
                logger.error("Failed to decrypt the SCEP request: transactionId={}", scepRequest.getTransactionId(), e);
                failure = new ScepException("Unable to decrypt the request data", FailInfo.BAD_REQUEST);
            }
            return buildResponse(scepRequest, buildFailedResponse(failure, scepRequest.getTransactionId()));
        }

        IntuneScepServiceClient intuneClient = scepProfile.isIntuneEnabled()
                ? buildIntuneClient(getIntuneConfiguration())
                : null;

        Certificate matchedRegistration = null;
        if (scepRequest.getMessageType().equals(MessageType.PKCS_REQ)
                || scepRequest.getMessageType().equals(MessageType.RENEWAL_REQ)) {
            try {
                // Classify first: both challenge regimes need the renewal verdict.
                boolean authenticatedRenewal = authenticateRenewal(scepRequest);
                if (registrationMode()) {
                    // An authenticated renewal proved possession of the replaced certificate's key — the
                    // RFC-blessed equivalent of a challenge — so only initial enrolments must match a
                    // pre-registration. The match travels as a parameter: it is per-request state and must
                    // not live on this singleton.
                    if (!authenticatedRenewal) {
                        matchedRegistration = matchRegistration(scepRequest);
                    }
                } else {
                    validateChallengePassword(scepRequest.getChallengePassword(), authenticatedRenewal);
                }
                verifyProofOfPossession(scepRequest);
            } catch (ScepException e) {
                return buildResponse(scepRequest, buildFailedResponse(e, scepRequest.getTransactionId()));
            }
        }

        return buildResponse(scepRequest, resolveResponse(scepRequest, intuneClient, matchedRegistration));
    }

    /** Decrypts the enveloped PKCS#10 request with the private key of the SCEP profile's CA certificate. */
    private void decryptRequestData(ScepRequest scepRequest) throws ScepException, CMSException {
        CryptographicKey key = scepProfile.getCaCertificate().getKey();
        CryptographicKeyItem item = cryptographicKeyService.getKeyItemFromKey(key, KeyType.PRIVATE_KEY);
        var connectorDto = key.getTokenInstanceReference().getConnector().mapToDto();
        // Get the private key from the configuration of SCEP Profile
        PlatformPrivateKey privateKey = new PlatformPrivateKey(key.getTokenInstanceReference().getTokenInstanceUuid(),
                item.getKeyReferenceUuid().toString(), connectorDto, item.getKeyAlgorithm().getLabel());

        CryptographicOperationsSyncApiClient cryptoApiClient = connectorApiFactory
                .getCryptographicOperationsApiClient(connectorDto);
        PlatformProvider provider = PlatformProvider.getInstance(scepProfile.getName(), true, cryptoApiClient);

        scepRequest.decryptData(privateKey, provider, item.getKeyAlgorithm(), scepProfile.getChallengePassword());
    }

    /** Produces the response body for a request that has been decrypted and, where applicable, authenticated. */
    private ScepResponse resolveResponse(ScepRequest scepRequest, IntuneScepServiceClient intuneClient,
            Certificate matchedRegistration) {
        if (scepTransactionRepository
                .existsByTransactionIdAndScepProfile(scepRequest.getTransactionId(), scepProfile)) {
            LoggingHelper.putAuditLogOperation(Operation.SCEP_TRANSACTION_CHECK);
            return existingTransactionResponse(scepRequest);
        }
        if (scepRequest.getMessageType().equals(MessageType.PKCS_REQ)) {
            return enrollmentResponse(scepRequest, intuneClient, matchedRegistration);
        }
        if (scepRequest.getMessageType().equals(MessageType.CERT_POLL)) {
            LoggingHelper.putAuditLogOperation(Operation.SCEP_CERTIFICATE_POLL);
            return pollCertificate(scepRequest, intuneClient);
        }
        return buildFailedResponse(new ScepException("Unsupported Operation. The requested operation is not supported",
                FailInfo.BAD_REQUEST), scepRequest.getTransactionId());
    }

    private ScepResponse existingTransactionResponse(ScepRequest scepRequest) {
        try {
            return getExistingTransaction(scepRequest.getTransactionId());
        } catch (ScepException e) {
            return buildFailedResponse(new ScepException("Error while formatting certificate", FailInfo.BAD_REQUEST),
                    scepRequest.getTransactionId());
        } catch (NotFoundException e) {
            return buildFailedResponse(new ScepException("Transaction certificate not found", FailInfo.BAD_REQUEST),
                    scepRequest.getTransactionId());
        }
    }

    private ScepResponse enrollmentResponse(ScepRequest scepRequest, IntuneScepServiceClient intuneClient,
            Certificate matchedRegistration) {
        try {
            // Reject before issuing when the response could never be delivered, so the platform
            // does not commit a certificate the client can never retrieve (RFC 8894 §3.2.2).
            verifyResponseEnvelopable(scepRequest);
            if (matchedRegistration != null) {
                LoggingHelper.putAuditLogOperation(Operation.ISSUE);
                return completeRegistration(scepRequest, matchedRegistration);
            }
            // Manual approval for the SCEP clients are configured in the SCEP Profile.
            // If the SCEP Profile has the manual approval set to true, only the CSR will be generated
            if (scepProfile.getRequireManualApproval() != null && !scepProfile.getRequireManualApproval()) {
                LoggingHelper.putAuditLogOperation(Operation.ISSUE);
                return issueCertificate(scepRequest, intuneClient);
            }
            LoggingHelper.putAuditLogOperation(Operation.REQUEST);
            return generateCsr(scepRequest, intuneClient);
        } catch (ScepException e) {
            ScepResponse failureResponse = buildFailedResponse(e, scepRequest.getTransactionId());
            if (scepProfile.isIntuneEnabled()) {
                // 32-bit error code formulated using the instructions specified in
                // https://msdn.microsoft.com/en-us/library/cc231198.aspx
                // this is a vendor specific error code
                FailInfo failInfo = e.getFailInfo() != null ? e.getFailInfo() : FailInfo.BAD_REQUEST;
                String detail = e.getMessage() != null ? e.getMessage() : e.getClass().getSimpleName();
                sendIntuneFailureMessage(intuneClient, scepRequest, 0x20000000L + failInfo.getValue(),
                        detail.substring(0, Math.min(detail.length(), 255)));
            }
            return failureResponse;
        }
    }

    private ScepResponse buildFailedResponse(ScepException scepException, String transactionId) {
        ScepResponse scepResponse = new ScepResponse();
        scepResponse.setPkiStatus(PkiStatus.FAILURE);
        // Not every ScepException constructor sets a failInfo, and the response attributes require one.
        scepResponse
                .setFailInfo(scepException.getFailInfo() != null ? scepException.getFailInfo() : FailInfo.BAD_REQUEST);
        scepResponse.setFailInfoText(scepException.getMessage());
        if (transactionId != null) {
            scepResponse.setTransactionId(transactionId);
        }

        logger
                .debug("SCEP request failed: {}, failInfo={}, cause={}, transactionId={}, scepProfile={}, raProfile={}",
                        scepException.getMessage(), scepException.getFailInfo(),
                        scepException.getCause() != null ? scepException.getCause().getMessage() : null, transactionId,
                        this.scepProfile.getName(), this.raProfileBased ? this.raProfile.getName() : null);

        return scepResponse;
    }

    private ResponseEntity<Object> buildResponse(ScepRequest scepRequest, ScepResponse scepResponse)
            throws ScepException {
        prepareMessage(scepRequest, scepResponse);
        CryptographicKey key = scepProfile.getCaCertificate().getKey();
        var connectorDto = key.getTokenInstanceReference().getConnector().mapToDto();
        CryptographicOperationsSyncApiClient cryptoApiClient = connectorApiFactory
                .getCryptographicOperationsApiClient(connectorDto);
        PlatformProvider provider = PlatformProvider.getInstance(scepProfile.getName(), true, cryptoApiClient);
        CryptographicKeyItem item = cryptographicKeyService.getKeyItemFromKey(key, KeyType.PRIVATE_KEY);
        // Get the private key from the configuration of SCEP Profile
        PlatformPrivateKey privateKey = new PlatformPrivateKey(key.getTokenInstanceReference().getTokenInstanceUuid(),
                item.getKeyReferenceUuid().toString(), connectorDto, item.getKeyAlgorithm().getLabel());
        try {
            scepResponse
                    .setSigningAttributes(CertificateUtil
                            .getX509Certificate(scepProfile.getCaCertificate().getCertificateContent().getContent()),
                            privateKey, provider

                    );
        } catch (CertificateException e) {
            throw new ScepException("Unable to set certificate for signing SCEP response", e, FailInfo.BAD_REQUEST);
        }
        scepResponse.generate();
        byte[] responseBody;
        try {
            responseBody = scepResponse.getSignedResponseData().getEncoded();
        } catch (IOException e) {
            throw new ScepException("Error generating SCEP response", e, FailInfo.BAD_REQUEST);
        }
        return getResponseEntity(responseBody, "application/x-pki-message", responseBody.length);
    }

    private ScepResponse issueCertificate(ScepRequest scepRequest, IntuneScepServiceClient intuneClient)
            throws ScepException {
        if (scepProfile.isIntuneEnabled()) {
            validateIntuneRequest(intuneClient, scepRequest);
        }
        ClientCertificateIssueRequestDto requestDto = new ClientCertificateIssueRequestDto();
        try {
            requestDto.setRequest(new String(Base64.getEncoder().encode(scepRequest.getPkcs10Request().getEncoded())));
            requestDto.setFormat(CertificateRequestFormat.PKCS10);
            requestDto.setAttributes(issueAttributes);
        } catch (IOException e) {
            throw new ScepException("Unable to decode PKCS#10 request", e, FailInfo.BAD_REQUEST);
        }
        ClientCertificateDataResponseDto response;
        try {
            response = clientOperationService
                    .issueCertificate(raProfile.getAuthorityInstanceReference().getSecuredParentUuid(),
                            raProfile.getSecuredUuid(), requestDto,
                            CertificateProtocolInfo.Scep(scepProfile.getUuid()));
        } catch (RequestAttributePolicyViolationException e) {
            throw new ScepException(e.getMessage(), e, FailInfo.BAD_REQUEST); // platform-authored, safe
        } catch (CertificateException | NotFoundException | CertificateOperationException e) {
            throw new ScepException("Unable to issue certificate", e, FailInfo.BAD_REQUEST);
        } catch (NoSuchAlgorithmException e) {
            throw new ScepException("Wrong algorithm to issue certificate", e, FailInfo.BAD_ALG);
        } catch (IOException | CertificateRequestException e) {
            throw new ScepException("Unable to issue certificate. Error parsing CSR.", e, FailInfo.BAD_REQUEST);
        } catch (InvalidKeyException e) {
            throw new ScepException("Unable to issue certificate. Invalid key", e, FailInfo.BAD_REQUEST);
        }

        ScepResponse scepResponse = new ScepResponse();
        if (response.getCertificateData() == null || response.getCertificateData().isEmpty()) {
            // certificate is not yet issued
            addTransactionEntity(scepRequest.getTransactionId(), response.getUuid());
            scepResponse.setPkiStatus(PkiStatus.PENDING);
            return scepResponse;
        }

        X509Certificate certificate;
        try {
            certificate = CertificateUtil.parseCertificate(response.getCertificateData());
        } catch (CertificateException e) {
            throw new ScepException("Unable to parse certificate", e, FailInfo.BAD_REQUEST);
        }

        Certificate certificateEntity;
        try {
            certificateEntity = certificateService.getCertificateEntity(SecuredUUID.fromString(response.getUuid()));
            scepResponse.setCertificateChain(getIssuedCertificateChain(certificateEntity));
        } catch (NotFoundException e) {
            throw new ScepException(
                    String.format("Issued certificate not found in inventory: uuid=%s", response.getUuid()),
                    FailInfo.BAD_REQUEST);
        }

        addTransactionEntity(scepRequest.getTransactionId(), response.getUuid());

        scepResponse.setPkiStatus(PkiStatus.SUCCESS);
        if (scepProfile.isIntuneEnabled()) {
            sendIntuneSuccessNotification(intuneClient, scepRequest, certificate);
        }
        return scepResponse;
    }

    private ScepResponse generateCsr(ScepRequest scepRequest, IntuneScepServiceClient intuneClient)
            throws ScepException {
        if (scepProfile.isIntuneEnabled()) {
            validateIntuneRequest(intuneClient, scepRequest);
        }
        ScepResponse scepResponse = new ScepResponse();
        ClientCertificateRequestDto requestDto = new ClientCertificateRequestDto();
        if (raProfile != null) {
            requestDto.setRaProfileUuid(raProfile.getUuid());
        }
        try {
            requestDto.setRequest(new String(Base64.getEncoder().encode(scepRequest.getPkcs10Request().getEncoded())));
            requestDto.setFormat(CertificateRequestFormat.PKCS10);
        } catch (IOException e) {
            throw new ScepException("Unable to decode PKCS#10 request", e, FailInfo.BAD_REQUEST);
        }
        CertificateDetailDto response;
        try {
            response = clientOperationService
                    .submitCertificateRequest(requestDto, CertificateProtocolInfo.Scep(scepProfile.getUuid()));
        } catch (RequestAttributePolicyViolationException e) {
            throw new ScepException(e.getMessage(), e, FailInfo.BAD_REQUEST); // platform-authored, safe
        } catch (CertificateException | NotFoundException | NoSuchAlgorithmException | AttributeException
                | ConnectorException | CertificateRequestException e) {
            throw new ScepException("Unable to submit certificate request", e, FailInfo.BAD_REQUEST);
        }

        addTransactionEntity(scepRequest.getTransactionId(), response.getUuid());
        scepResponse.setPkiStatus(PkiStatus.PENDING);

        return scepResponse;
    }

    /**
     * Maps a {@link CertificateState} to the {@link PkiStatus} that SCEP should report per RFC 8894 §3.3.2.
     *
     * @return {@code SUCCESS} for the only positive terminal state (ISSUED); {@code FAILURE} for negative terminal
     * states (REJECTED, FAILED, REVOKED); {@code PENDING} for in-progress states (REQUESTED, PENDING_APPROVAL,
     * PENDING_ISSUE, PENDING_REVOKE).
     */
    static PkiStatus pkiStatusForCertState(CertificateState state) {
        return switch (state) {
            case ISSUED -> PkiStatus.SUCCESS;
            case REJECTED, FAILED, REVOKED -> PkiStatus.FAILURE;
            default -> PkiStatus.PENDING;
        };
    }

    private ScepResponse getExistingTransaction(String transactionId) throws ScepException, NotFoundException {
        ScepTransaction scepTransaction = scepTransactionRepository
                .findByTransactionIdAndScepProfile(transactionId, scepProfile)
                .orElse(null);
        assert scepTransaction != null;
        Certificate certificate = scepTransaction.getCertificate();

        PkiStatus pkiStatus = pkiStatusForCertState(certificate.getState());
        if (pkiStatus == PkiStatus.FAILURE) {
            String reason = certificate.getState() == CertificateState.REJECTED
                    ? "Certificate issuance was rejected"
                    : "Certificate issuance failed";
            return buildFailedResponse(new ScepException(reason, FailInfo.BAD_REQUEST), transactionId);
        }

        ScepResponse scepResponse = new ScepResponse();
        scepResponse.setPkiStatus(pkiStatus);
        if (pkiStatus == PkiStatus.SUCCESS) {
            scepResponse.setCertificateChain(getIssuedCertificateChain(certificate));
        } else if (pkiStatus == PkiStatus.PENDING) {
            logger
                    .debug("SCEP transactionId={} returning PENDING (cert {} state={})", transactionId,
                            certificate.getUuid(), certificate.getState());
        }
        return scepResponse;
    }

    private void addTransactionEntity(String transactionId, String certificateUuid) {
        ScepTransaction scepTransaction = new ScepTransaction();
        scepTransaction.setTransactionId(transactionId);
        scepTransaction.setCertificateUuid(UUID.fromString(certificateUuid));
        scepTransaction.setScepProfile(scepProfile);
        scepTransactionRepository.save(scepTransaction);
    }

    private ScepResponse pollCertificate(ScepRequest scepRequest, IntuneScepServiceClient intuneClient) {
        ScepResponse scepResponse = new ScepResponse();
        try {
            ScepTransaction transaction = getTransaction(scepRequest.getTransactionId());
            if (transaction == null) {
                // No tracked transaction — keep the client polling (the originating request
                // may still be in the queue).
                scepResponse.setPkiStatus(PkiStatus.PENDING);
                prepareMessage(scepRequest, scepResponse);
                return scepResponse;
            }

            Certificate certificate = transaction.getCertificate();
            PkiStatus pkiStatus = pkiStatusForCertState(certificate.getState());

            if (pkiStatus == PkiStatus.FAILURE) {
                String reason = certificate.getState() == CertificateState.REJECTED
                        ? "Certificate issuance was rejected"
                        : "Certificate issuance failed";
                return buildFailedResponse(new ScepException(reason, FailInfo.BAD_REQUEST),
                        scepRequest.getTransactionId());
            }

            scepResponse.setPkiStatus(pkiStatus);
            if (pkiStatus == PkiStatus.SUCCESS) {
                X509Certificate x509Certificate = CertificateUtil
                        .parseCertificate(certificate.getCertificateContent().getContent());
                scepResponse.setCertificateChain(getIssuedCertificateChain(certificate));
                sendIntuneSuccessNotification(intuneClient, scepRequest, x509Certificate);
            } else if (pkiStatus == PkiStatus.PENDING) {
                logger
                        .debug("SCEP poll on transactionId={} returning PENDING (cert {} state={})",
                                scepRequest.getTransactionId(), certificate.getUuid(), certificate.getState());
            }
            prepareMessage(scepRequest, scepResponse);
        } catch (Exception e) {
            logger
                    .error("SCEP poll failed for transactionId={}: {}", scepRequest.getTransactionId(), e.getMessage(),
                            e);
            // Keep the client polling rather than returning a half-initialised (possibly
            // null-status) response that would fail response generation with an HTTP error.
            scepResponse.setPkiStatus(PkiStatus.PENDING);
        }
        return scepResponse;
    }

    private List<X509Certificate> loadCertificateChain(Certificate leafCertificate, boolean tolerateLeafNotChecked)
            throws ScepException, NotFoundException {
        ArrayList<X509Certificate> certificateChain = new ArrayList<>();
        String leafUuid = leafCertificate.getUuid().toString();
        for (CertificateDetailDto certificate : certificateService
                .getCertificateChain(leafCertificate.getSecuredUuid(), true)
                .getCertificates()) {
            // Only the freshly-issued leaf may be transiently NOT_CHECKED; CA / issuer certs
            // must already be validated (see checkCertificateValidity).
            boolean isFreshlyIssuedLeaf = tolerateLeafNotChecked && certificate.getUuid().equals(leafUuid);
            checkCertificateValidity(certificate, isFreshlyIssuedLeaf);
            try {
                certificateChain.add(CertificateUtil.parseCertificate(certificate.getCertificateContent()));
            } catch (CertificateException e) {
                // This should not happen
                throw new IllegalArgumentException(
                        "Failed to parse certificate content: " + certificate.getCertificateContent());
            }
        }

        return certificateChain;
    }

    private List<X509Certificate> getIssuedCertificateChain(Certificate certificate)
            throws ScepException, NotFoundException {
        if (!this.scepProfile.isIncludeCaCertificateChain() && !this.scepProfile.isIncludeCaCertificate()) {
            try {
                // The freshly-issued end-entity certificate: tolerate a transient NOT_CHECKED.
                checkCertificateValidity(certificate.mapToDto(), true);

                return List.of(CertificateUtil.parseCertificate(certificate.getCertificateContent().getContent()));
            } catch (CertificateException e) {
                // This should not happen
                throw new IllegalArgumentException(
                        "Failed to parse certificate content: " + certificate.getCertificateContent().getContent());
            }
        }

        logger.debug("Building the certificate chain for the response message");
        // certificate is the freshly-issued end-entity cert (leaf); tolerate its transient
        // NOT_CHECKED but require the CA / issuer entries to be already validated.
        var certificateChain = loadCertificateChain(certificate, true);
        if (this.scepProfile.isIncludeCaCertificateChain()) {
            return certificateChain;
        } else {
            return certificateChain.subList(0, Math.min(2, certificateChain.size()));
        }
    }

    /**
     * A SUCCESS CertRep is enveloped to the client's own key: RSA keys via key transport, every other key type (e.g.
     * EC) via the RFC 8894 password recipient, which needs a challenge password — the profile's shared one, or in
     * registration mode the matched registration's challenge. When the client key cannot do key transport and no
     * envelope password is available, the issued certificate could never be delivered — reject the request before
     * issuing rather than committing an unretrievable certificate.
     */
    void verifyResponseEnvelopable(ScepRequest scepRequest) throws ScepException {
        X509Certificate signerCertificate = scepRequest.getSignerCertificate();
        if (signerCertificate == null) {
            return;
        }
        boolean keyTransportCapable = "RSA".equalsIgnoreCase(signerCertificate.getPublicKey().getAlgorithm());
        if (!keyTransportCapable && resolveEnvelopePassword(scepRequest) == null) {
            throw new ScepException(
                    "A challenge password must be configured on the SCEP profile, or the enrolment must complete a certificate registration, to issue certificates to non-RSA client keys",
                    FailInfo.BAD_ALG);
        }
    }

    private byte[] resolveRecipientKeyInfo(ScepRequest scepRequest) {
        // Envelope the response to the resolved signer certificate (the entity that holds the private
        // key to decrypt it), not the first element of the request's certificate SET, which is not
        // guaranteed to be the signer.
        X509Certificate signerCertificate = scepRequest.getSignerCertificate();
        if (signerCertificate == null) {
            return scepRequest.getRequestKeyInfo();
        }
        try {
            return signerCertificate.getEncoded();
        } catch (CertificateException e) {
            return scepRequest.getRequestKeyInfo();
        }
    }

    private void prepareMessage(ScepRequest scepRequest, ScepResponse scepResponse) {
        if (scepRequest == null) {
            return;
        }
        // As per the SCEP RFC the fields are not to be null. EVen if they are null, these
        // are handled when generating the attributes for the CMS signed data for the response
        scepResponse.setRecipientNonce(scepRequest.getSenderNonce());
        scepResponse.setTransactionId(scepRequest.getTransactionId());
        scepResponse.setCaCertificate(recipient);
        scepResponse.setRecipientKeyInfo(resolveRecipientKeyInfo(scepRequest));
        scepResponse.setDigestAlgorithmOid(scepRequest.getDigestAlgorithmOid());
        scepResponse.setSenderNonce(RandomUtil.generateRandomNonceBase64(16));
        scepResponse.setContentEncryptionAlgorithm(scepRequest.getContentEncryptionAlgorithm());
        // Enveloping a SUCCESS response to a recipient key that cannot do key transport (e.g. EC)
        // requires a password recipient (RFC 8894 §3.2.2).
        scepResponse.setChallengePassword(resolveEnvelopePassword(scepRequest));
    }

    /**
     * The RFC 8894 password-recipient secret for enveloping a response to a non-key-transport client key. In the
     * profile-password regime it is the shared challenge password. In registration mode it is the per-registration
     * challenge: the one presented in the enrolment CSR, or — on a poll, where no CSR rides the request — the one
     * recovered from the durable authorization behind the poll's transaction. {@code null} when no password is
     * available (the enveloper then raises its delivery error).
     */
    private String resolveEnvelopePassword(ScepRequest scepRequest) {
        if (!registrationMode()) {
            String profilePassword = scepProfile.getChallengePassword();
            return profilePassword == null || profilePassword.isEmpty() ? null : profilePassword;
        }
        if (scepRequest == null) {
            return null;
        }
        if (scepRequest.getPkcs10Request() != null) {
            String presented = scepRequest.getChallengePassword();
            if (presented != null && !presented.isEmpty()) {
                return presented;
            }
        }
        return resolvePollEnvelopePassword(scepRequest);
    }

    private String resolvePollEnvelopePassword(ScepRequest scepRequest) {
        ScepTransaction transaction = getTransaction(scepRequest.getTransactionId());
        if (transaction == null) {
            return null;
        }
        return registrationAuthorizationRepository
                .findByCertificateUuid(transaction.getCertificateUuid())
                .map(registrationChallengeStore::resolvePlaintext)
                .orElse(null);
    }

    private ScepTransaction getTransaction(String transactionId) {
        // Transaction ids are client-chosen and can collide across SCEP profiles, so the fetch is scoped to the
        // current profile — matching the exists-check in resolveResponse, so a poll never resolves another
        // profile's transaction (and, in registration mode, never recovers another registration's challenge).
        return scepTransactionRepository.findByTransactionIdAndScepProfile(transactionId, scepProfile).orElse(null);
    }

    /** The single wire message for every registration-mode rejection, so a prober cannot enumerate registrations. */
    private static final String REGISTRATION_REJECTION = "The request does not match an active certificate registration.";

    private boolean registrationMode() {
        return scepProfile.getChallengeSource() == ProtocolChallengeSource.CERTIFICATE_REGISTRATION;
    }

    /**
     * Binds a registration-mode initial enrolment to its pre-registered certificate: the CSR identity is matched
     * against the RA profile's REGISTERED placeholders holding an ACTIVE authorization, and only the single matched
     * registration later has its challenge verified (inside the completion, so each wrong challenge is counted exactly
     * once against exactly one authorization). Every rejection carries {@link #REGISTRATION_REJECTION}; the reason
     * stays in the log and, when the failed candidate is known, in its certificate event history.
     */
    private Certificate matchRegistration(ScepRequest scepRequest) throws ScepException {
        String presented = scepRequest.getChallengePassword();
        if (presented == null || presented.isEmpty()) {
            logger.info("SCEP registration enrolment rejected: no challenge password presented");
            throw new ScepException(REGISTRATION_REJECTION, FailInfo.BAD_MESSAGE_CHECK);
        }
        Map<String, List<String>> csrSans;
        try {
            csrSans = CertificateUtil.getSAN(new Pkcs10CertificateRequest(scepRequest.getPkcs10Request().getEncoded()));
        } catch (IOException | CertificateRequestException e) {
            logger.info("SCEP registration enrolment rejected: unable to read the CSR identity", e);
            throw new ScepException(REGISTRATION_REJECTION, FailInfo.BAD_MESSAGE_CHECK);
        }
        List<Certificate> candidates = certificateRepository
                .findRegisteredWithActiveRegistrationAuthorizationByRaProfileUuidAndSubjectDnNormalized(
                        raProfile.getUuid(),
                        CertificateUtil.normalizeSubjectDn(scepRequest.getPkcs10Request().getSubject()));
        RegistrationIdentityMatcher.MatchResult result = RegistrationIdentityMatcher
                .match(scepRequest.getPkcs10Request().getSubject(), csrSans,
                        candidates
                                .stream()
                                .map(c -> new RegistrationIdentityMatcher.Candidate(c.getUuid(), c.getSubjectDn(),
                                        c.getSubjectAlternativeNames()))
                                .toList());
        // The wire carries only the generic rejection, so these lines are the operator's whole diagnostic
        // surface: they must name the identity the matcher actually compared. A SAN-only enrolment has no
        // subject, rendered as the empty string rather than dereferenced.
        X500Name csrSubjectDn = scepRequest.getPkcs10Request().getSubject();
        String csrSubject = csrSubjectDn == null ? "" : csrSubjectDn.toString();
        switch (result.outcome()) {
            case MATCHED -> {
                return candidates
                        .stream()
                        .filter(c -> c.getUuid().equals(result.certificateUuid()))
                        .findFirst()
                        .orElseThrow();
            }
            case SAN_MISMATCH -> {
                certificateEventHistoryService
                        .addEventHistory(result.certificateUuid(), CertificateEvent.ISSUE,
                                CertificateEventStatus.FAILED,
                                "SCEP enrolment subject alternative names do not match the registered ones", "");
                logger
                        .info("SCEP registration enrolment rejected: SAN mismatch with registration {} (CSR subject={}, CSR SANs={})",
                                result.certificateUuid(), csrSubject, csrSans);
            }
            case AMBIGUOUS -> logger
                    .info("SCEP registration enrolment rejected: several registrations match the CSR identity (CSR subject={}, CSR SANs={})",
                            csrSubject, csrSans);
            case NO_MATCH -> logger
                    .info("SCEP registration enrolment rejected: no registration matches the CSR identity (CSR subject={}, CSR SANs={}, {} subject-matching REGISTERED candidate(s) with an active authorization under RA profile {})",
                            csrSubject, csrSans, candidates.size(), raProfile.getName());
        }
        throw new ScepException(REGISTRATION_REJECTION, FailInfo.BAD_MESSAGE_CHECK);
    }

    /**
     * Completes the matched pre-registration through the standard completion operation, presenting the CSR's challenge
     * as the authorization secret — the challenge gate, CSR attach and ISSUE enqueue are the same as for an operator
     * completion. Registration completion is always asynchronous: the client receives PENDING and polls the
     * transaction.
     */
    private ScepResponse completeRegistration(ScepRequest scepRequest, Certificate matchedRegistration)
            throws ScepException {
        ClientCertificateIssueRequestDto requestDto = new ClientCertificateIssueRequestDto();
        try {
            requestDto.setRequest(Base64.getEncoder().encodeToString(scepRequest.getPkcs10Request().getEncoded()));
        } catch (IOException e) {
            throw new ScepException("Unable to decode PKCS#10 request", e, FailInfo.BAD_REQUEST);
        }
        requestDto.setFormat(CertificateRequestFormat.PKCS10);
        requestDto.setAttributes(issueAttributes);
        requestDto.setAuthorizationSecret(scepRequest.getChallengePassword());

        // Record the poll mapping in its own committed transaction before issueExistingCertificate publishes the
        // ISSUE message: the publish is a non-transactional JMS send, so a mapping durable only with this request's
        // outer transaction could be rolled back after the message is on the broker — the certificate would issue
        // while the client's transactionId resolves to nothing. Nothing throws after the enqueue, so any failure
        // below means no ISSUE was published; discard the staged mapping on every failure path.
        scepRegistrationTrackingWriter
                .recordPollMapping(scepRequest.getTransactionId(), matchedRegistration.getUuid(),
                        scepProfile.getUuid());
        try {
            clientOperationExternalService
                    .issueExistingCertificate(raProfile.getAuthorityInstanceReference().getSecuredParentUuid(),
                            raProfile.getSecuredUuid(), matchedRegistration.getUuid().toString(), requestDto);
        } catch (RequestAttributePolicyViolationException e) {
            // A policy violation is about CSR content, not registration identity, so it is not an enumeration
            // oracle and carries its platform-authored detail — the same shaping the plain enrolment sites use.
            // The failure precedes the enqueue, so the staged mapping goes.
            scepRegistrationTrackingWriter.discardPollMapping(scepRequest.getTransactionId(), scepProfile.getUuid());
            throw new ScepException(e.getMessage(), e, FailInfo.BAD_REQUEST); // platform-authored, safe
        } catch (ValidationException | NotFoundException e) {
            // Denial detail (locked authorization, expired window, wrong challenge) stays in the log and
            // the certificate event history; the wire carries the anti-enumeration text so challenge
            // failures are indistinguishable from lookup misses.
            scepRegistrationTrackingWriter.discardPollMapping(scepRequest.getTransactionId(), scepProfile.getUuid());
            logger.info("SCEP registration completion rejected: {}", e.getMessage());
            throw new ScepException(REGISTRATION_REJECTION, FailInfo.BAD_MESSAGE_CHECK);
        } catch (CertificateException e) {
            // A strict RA profile whose request-attribute set cannot be resolved is an authority-side outage, not
            // a client fault: no ISSUE reached the broker, so drop the staged mapping rather than leaving a retry
            // short-circuited to a poll. SCEP has no server-failure failInfo, so BAD_REQUEST is the closest the
            // protocol allows — passed explicitly, as every other ScepException in this file does.
            scepRegistrationTrackingWriter.discardPollMapping(scepRequest.getTransactionId(), scepProfile.getUuid());
            logger.error("SCEP registration completion could not be validated", e);
            throw new ScepException("Unable to complete certificate registration", e, FailInfo.BAD_REQUEST);
        } catch (RuntimeException e) {
            // A row-lock timeout, a data-integrity error, an authorization error, or a failed publish also
            // means no ISSUE reached the broker. Drop the staged mapping so a retry is not short-circuited to
            // a poll that never completes, then let the unexpected failure surface generically upstream.
            scepRegistrationTrackingWriter.discardPollMapping(scepRequest.getTransactionId(), scepProfile.getUuid());
            throw e;
        }
        applyProtocolAssociationBestEffort(matchedRegistration);
        ScepResponse scepResponse = new ScepResponse();
        scepResponse.setPkiStatus(PkiStatus.PENDING);
        return scepResponse;
    }

    /**
     * Protocol attribution is cosmetic and the completion is already committed and published, so an attribution failure
     * must not fail the enrolment — a retry would no longer match and the client would be stranded. Applied in its own
     * transaction so the tag survives an outer rollback; best-effort with the failure logged.
     */
    private void applyProtocolAssociationBestEffort(Certificate matchedRegistration) {
        try {
            scepRegistrationTrackingWriter
                    .recordProtocolAttribution(matchedRegistration.getUuid(), scepProfile.getUuid());
        } catch (Exception e) {
            logger
                    .warn("Failed to apply SCEP protocol associations to completed registration {}: {}",
                            matchedRegistration.getUuid(), e.getMessage());
        }
    }

    /**
     * Enforces the challenge password configured on the SCEP profile. A renewal request is signed with the key of the
     * certificate being replaced and carries no challengePassword attribute (RFC 8894 §3.3.1.2), so an absent password
     * is accepted once {@link #authenticateRenewal} has proven possession of that certificate's key. Absent covers a
     * blank attribute too — clients are commonly configured to send an empty challengePassword on renewal. A password
     * that carries a value must still match, so a wrong shared secret is never silently accepted.
     *
     * @throws ScepException with {@link FailInfo#BAD_MESSAGE_CHECK} when the password is missing where required, or
     * does not match the one configured on the profile
     */
    // package-private for unit tests
    void validateChallengePassword(String requestChallengePassword, boolean authenticatedRenewal) throws ScepException {
        String profileChallengePassword = scepProfile.getChallengePassword();
        if (profileChallengePassword == null || profileChallengePassword.isEmpty()) {
            return;
        }
        if (requestChallengePassword == null || requestChallengePassword.isEmpty()) {
            if (authenticatedRenewal) {
                logger.debug("Challenge password waived for an authenticated renewal request");
                return;
            }
            throw new ScepException(
                    "The SCEP profile requires a challenge password but the request does not contain one.",
                    FailInfo.BAD_MESSAGE_CHECK);
        }
        // Constant-time comparison: the endpoint is unauthenticated and the shared secret is long-lived.
        if (!MessageDigest
                .isEqual(profileChallengePassword.getBytes(StandardCharsets.UTF_8),
                        requestChallengePassword.getBytes(StandardCharsets.UTF_8))) {
            throw new ScepException("Challenge password validation failed.", FailInfo.BAD_MESSAGE_CHECK);
        }
    }

    private void verifyProofOfPossession(ScepRequest scepRequest) throws ScepException {

        // Throw exception if the request type is not renewal or issuing a new certificate
        if (!scepRequest.getMessageType().equals(MessageType.RENEWAL_REQ)
                && !scepRequest.getMessageType().equals(MessageType.PKCS_REQ)) {
            throw new ScepException("Unsupported Operation", FailInfo.BAD_REQUEST);
        }

        if (scepRequest.getMessageType().equals(MessageType.PKCS_REQ)) {
            try {
                if (!scepRequest.verifyRequest()) {
                    throw new ScepException("Failed to verify PKCS#10 request POP, invalid signature",
                            FailInfo.BAD_REQUEST);
                }
            } catch (PKCSException | NoSuchAlgorithmException | InvalidKeyException | OperatorCreationException e) {
                throw new ScepException("Failed to verify PKCS#10 request POP", FailInfo.BAD_REQUEST);
            }
        }
    }

    /**
     * Classifies the request as a renewal and validates it when it is one. The classification follows the signer
     * certificate rather than the message type: per draft-nourse-scep-23 §3.1.1.2 — the version implemented by common
     * clients such as sscep and jscep — a renewal is a PKCS_REQ signed with the key of the certificate being replaced.
     *
     * <p>
     * The waiver is deliberately narrower than the renewal itself: it additionally requires the renewed certificate to
     * be associated with this profile's RA profile and the request to ask for no name the renewed certificate does not
     * already carry. An RA-profile association can also be set by an operator on a certificate the platform never
     * issued, so the waiver trusts that association — narrowing it to proven issuance provenance is tracked separately.
     * </p>
     *
     * @return {@code true} when the request proved possession of a certificate of this RA profile and may therefore
     * enroll without the profile's challenge password
     * @throws ScepException when the request is a renewal that must be rejected (unverifiable signature, archived,
     * pending, revoked or otherwise unusable certificate, subject DN mismatch, outside the renewal timeframe)
     */
    // package-private for unit tests
    boolean authenticateRenewal(ScepRequest scepRequest) throws ScepException {
        Certificate renewedCertificate = resolveRenewedCertificate(scepRequest);
        if (renewedCertificate == null) {
            // No known certificate behind the signer: an initial enrollment, not a renewal.
            return false;
        }
        validateRenewal(scepRequest, renewedCertificate);
        // Waive the challenge password only for a certificate of this profile's RA profile: holding some
        // other RA profile's certificate does not entitle a client to enroll here.
        if (renewedCertificate.getRaProfileUuid() == null
                || !renewedCertificate.getRaProfileUuid().equals(raProfile.getUuid())) {
            logger.debug("Challenge password not waived: the signer certificate belongs to another RA profile");
            return false;
        }
        // ... nor when the platform could not establish that the certificate is still valid.
        if (INCONCLUSIVE_VALIDATION_STATUSES.contains(renewedCertificate.getValidationStatus())) {
            logger
                    .debug("Challenge password not waived: validation of certificate {} is inconclusive (status={})",
                            renewedCertificate.getUuid(), renewedCertificate.getValidationStatus());
            return false;
        }
        // ... and only when the request asks for no identity the renewed certificate does not already hold,
        // so a waived renewal cannot obtain a certificate for a name it was never issued.
        if (!requestedNamesAreAlreadyHeld(scepRequest)) {
            logger
                    .debug("Challenge password not waived: the request asks for subject alternative names the "
                            + "renewed certificate does not carry");
            return false;
        }
        return true;
    }

    /**
     * Whether every subject alternative name the request asks for is already present in the certificate being renewed —
     * which is the request's signer certificate, so no second parse of the inventory content is needed. Names that
     * cannot be read withhold the waiver rather than guess.
     */
    private boolean requestedNamesAreAlreadyHeld(ScepRequest scepRequest) {
        try {
            return subjectAlternativeNames(scepRequest.getSignerCertificate())
                    .containsAll(subjectAlternativeNames(scepRequest.getPkcs10Request()));
        } catch (RuntimeException e) {
            logger.debug("Unable to compare the subject alternative names of the renewal request", e);
            return false;
        }
    }

    /**
     * The names carried by the certificate being renewed, as DER structures. The comparison is deliberately made on the
     * encoded form rather than on the platform's string rendering of it: the renderings disagree for an iPAddress —
     * decoded text on the certificate side, a hex octet string on the request side — which would withhold the waiver
     * from a device renewing on an address it already holds.
     */
    private static Set<GeneralName> subjectAlternativeNames(X509Certificate certificate) {
        byte[] extension = certificate.getExtensionValue(Extension.subjectAlternativeName.getId());
        if (extension == null) {
            return Set.of();
        }
        return namesOf(GeneralNames.getInstance(ASN1OctetString.getInstance(extension).getOctets()));
    }

    /** The names the request asks for, read from its extensionRequest attribute as DER structures. */
    private static Set<GeneralName> subjectAlternativeNames(JcaPKCS10CertificationRequest pkcs10Request) {
        for (Attribute attribute : pkcs10Request.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
            if (attribute.getAttrValues().size() == 0) {
                continue;
            }
            GeneralNames names = GeneralNames
                    .fromExtensions(Extensions.getInstance(attribute.getAttrValues().getObjectAt(0)),
                            Extension.subjectAlternativeName);
            if (names != null) {
                return namesOf(names);
            }
        }
        return Set.of();
    }

    private static Set<GeneralName> namesOf(GeneralNames names) {
        return new HashSet<>(Arrays.asList(names.getNames()));
    }

    /**
     * Resolves the inventory certificate the request is signed with, or {@code null} when the platform does not know it
     * — meaning this is not a renewal. {@code ScepRequest} rejects a message with no resolvable signer certificate at
     * construction, so the null check below is defense in depth.
     */
    private Certificate resolveRenewedCertificate(ScepRequest scepRequest) throws ScepException {
        X509Certificate signerCertificate = scepRequest.getSignerCertificate();
        if (signerCertificate == null) {
            return null;
        }
        try {
            return certificateService
                    .getCertificateEntityByFingerprint(CertificateUtil.getThumbprint(signerCertificate));
        } catch (NotFoundException e) {
            return null;
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            throw new ScepException("Unable to parse the signer certificate");
        }
    }

    private void validateRenewal(ScepRequest scepRequest, Certificate renewedCertificate) throws ScepException {
        // Verify possession of the existing certificate's key first: the checks below report the state of
        // that certificate, which an unauthenticated client must not be able to probe by replaying a
        // certificate it does not own.
        try {
            if (!scepRequest.verifySignature(scepRequest.getSignerCertificate().getPublicKey())) {
                throw new ScepException("SCEP Request signature verification failed", FailInfo.BAD_MESSAGE_CHECK);
            }
        } catch (OperatorCreationException | CMSException e) {
            logger.debug("Failed to verify the signature of the SCEP request", e);
            throw new ScepException("Failed to verify the SCEP request signature", FailInfo.BAD_MESSAGE_CHECK);
        }
        if (renewedCertificate.isArchived()) {
            throw new ScepException("Certificate with UUID %s is archived. Cannot be renewed by SCEP."
                    .formatted(renewedCertificate.getUuid()), FailInfo.BAD_REQUEST);
        }
        if (renewedCertificate.getState() == CertificateState.PENDING_ISSUE
                || renewedCertificate.getState() == CertificateState.PENDING_REVOKE) {
            throw new ScepException(
                    "Cannot renew certificate with a pending operation. Finalize or cancel "
                            + "the pending operation first. Certificate UUID: " + renewedCertificate.getUuid(),
                    FailInfo.BAD_REQUEST);
        }
        // A certificate that is no longer usable must not be renewable — and must certainly not authenticate
        // the request in place of the challenge password. checkRenewalTimeframe applies the revoked/expired
        // test only on the branch where a renewal threshold is configured, so enforce it for every
        // configuration here, before the timeframe policy runs.
        if (renewedCertificate.getState() != CertificateState.ISSUED
                || NON_RENEWABLE_VALIDATION_STATUSES.contains(renewedCertificate.getValidationStatus())) {
            throw new ScepException(
                    "Cannot renew certificate with UUID %s: it is not in a renewable state (state=%s, validation status=%s)"
                            .formatted(renewedCertificate.getUuid(), renewedCertificate.getState(),
                                    renewedCertificate.getValidationStatus()),
                    FailInfo.BAD_REQUEST);
        }
        // A subject DN mismatch rejects the request rather than merely withholding the waiver, which is the
        // behaviour that predates the waiver: signing with a certificate and then asking for a different
        // subject is treated as a malformed renewal, not as an enrollment the shared secret could authorize.
        if (!(new X500Name(renewedCertificate.getSubjectDn())).equals(scepRequest.getPkcs10Request().getSubject())) {
            throw new ScepException("Subject DN for the renewal request does not match the original certificate",
                    FailInfo.BAD_REQUEST);
        }
        // No need to verify the same key pair used in request since it is already handled by the rekey method in client
        // operations
        checkRenewalTimeframe(renewedCertificate);
    }

    /**
     * Applies the profile's renewal window. Callers must have established that the certificate is in a renewable state
     * — {@link #validateRenewal} rejects revoked, expired and otherwise unusable certificates for every threshold
     * configuration, which is also why this method no longer repeats that test on the configured-threshold branch: it
     * was unreachable there, and dereferenced a nullable validation status to do it.
     */
    private void checkRenewalTimeframe(Certificate certificate) throws ScepException {
        // Empty renewal threshold or the value 0 will be considered as null value and the half life of the certificate
        // will be assumed
        if (scepProfile.getRenewalThreshold() == null || scepProfile.getRenewalThreshold() == 0) {
            // If the renewal timeframe is not given, we consider that renewal is possible only after the certificate
            // crosses its half lime time
            if (certificate.getValidity() / 2 < certificate.getExpiryInDays()) {
                throw new ScepException("Cannot renew certificate. Validity exceeds the half life time of certificate",
                        FailInfo.BAD_REQUEST);
            }
        } else if (certificate.getExpiryInDays() > scepProfile.getRenewalThreshold()) {
            throw new ScepException("Cannot renew certificate. Validity exceeds the configured value in SCEP profile",
                    FailInfo.BAD_REQUEST);
        }
    }

    private Properties getIntuneConfiguration() {
        return intuneConfigProperties.forScepProfile(scepProfile);
    }

    private IntuneScepServiceClient buildIntuneClient(Properties configProperties) {
        return new IntuneScepServiceClient(configProperties);
    }

    private void validateIntuneRequest(IntuneScepServiceClient client, ScepRequest scepRequest) throws ScepException {
        if (scepRequest.getTransactionId() == null || scepRequest.getTransactionId().isEmpty()) {
            throw new ScepException("Transaction ID cannot be empty for Intune requests");
        }
        if (scepRequest.getPkcs10Request() == null) {
            throw new ScepException("Cannot initiate Intune validation. PKCS#10 request is empty");
        }
        try {
            client
                    .ValidateRequest(scepRequest.getTransactionId(),
                            CertificateRequestUtils.byteArrayCsrToString(scepRequest.getPkcs10Request().getEncoded()));
        } catch (Exception e) {
            throw new ScepException("Validation failed for Intune request.", e, FailInfo.BAD_REQUEST);
        }
    }

    private void sendIntuneSuccessNotification(IntuneScepServiceClient client, ScepRequest request,
            X509Certificate certificate) {
        String pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX";
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
        String expiryDate = simpleDateFormat.format(certificate.getNotAfter());
        String serialNumber = certificate.getSerialNumber().toString(16);
        String issuingAuthority = certificate.getIssuerX500Principal().getName();

        try {
            String sha1Thumbprint = CertificateUtil.getSha1Thumbprint(certificate.getEncoded());
            client
                    .SendSuccessNotification(request.getTransactionId(),
                            CertificateRequestUtils.byteArrayCsrToString(request.getPkcs10Request().getEncoded()),
                            sha1Thumbprint, serialNumber, expiryDate, issuingAuthority, "", "");
        } catch (Exception e) {
            logger.error("Unable to update Intune with success notification: {}", e.getMessage());
        }
    }

    private void sendIntuneFailureMessage(IntuneScepServiceClient client, ScepRequest request, long errorCode,
            String error) {
        if (client != null) {
            try {
                client
                        .SendFailureNotification(request.getTransactionId(),
                                CertificateRequestUtils.byteArrayCsrToString(request.getPkcs10Request().getEncoded()),
                                errorCode, error);
            } catch (Exception e) {
                logger.error("Unable to update Intune with failed notification: {}", e.getMessage());
            }
        } else {
            logger.error("Unable to update Intune because the client is not available.");
        }
    }

    /**
     * @param tolerateNotChecked {@code true} only for the freshly-issued end-entity certificate, whose async validation
     * may not have landed yet: it is briefly waited on and NOT_CHECKED tolerated if unresolved. CA / issuer certs pass
     * {@code false} — they are long-lived and must already be VALID/EXPIRING, so a NOT_CHECKED CA cert is rejected as
     * before and never waited on.
     */
    private void checkCertificateValidity(CertificateDetailDto certificate, boolean tolerateNotChecked)
            throws ScepException {
        CertificateValidationStatus validationStatus = tolerateNotChecked
                ? validationStatusPoller.resolveOrKeep(certificate)
                : certificate.getValidationStatus();
        boolean acceptable = validationStatus == CertificateValidationStatus.VALID
                || validationStatus == CertificateValidationStatus.EXPIRING
                || (tolerateNotChecked && validationStatus == CertificateValidationStatus.NOT_CHECKED);
        if (!acceptable) {
            throw new ScepException(
                    String
                            .format("Certificate is not valid. UUID: %s, Fingerprint: %s, Status: %s",
                                    certificate.getUuid(), certificate.getFingerprint(), validationStatus.getLabel()),
                    FailInfo.BAD_REQUEST);
        }
    }
}
