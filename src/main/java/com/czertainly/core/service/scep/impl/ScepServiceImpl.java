package com.czertainly.core.service.scep.impl;

import com.czertainly.api.exception.*;
import com.czertainly.api.interfaces.client.v1.CryptographicOperationsSyncApiClient;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttributeV2;
import com.czertainly.api.model.common.enums.cryptography.KeyType;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateDetailDto;
import com.czertainly.api.model.core.certificate.CertificateState;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.enums.CertificateRequestFormat;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.api.model.core.scep.FailInfo;
import com.czertainly.api.model.core.scep.MessageType;
import com.czertainly.api.model.core.scep.PkiStatus;
import com.czertainly.api.model.core.v2.ClientCertificateDataResponseDto;
import com.czertainly.api.model.core.v2.ClientCertificateRequestDto;
import com.czertainly.api.model.core.v2.ClientCertificateSignRequestDto;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.client.ConnectorApiFactory;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.CryptographicKey;
import com.czertainly.core.dao.entity.CryptographicKeyItem;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.scep.ScepProfile;
import com.czertainly.core.dao.entity.scep.ScepTransaction;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.dao.repository.scep.ScepProfileRepository;
import com.czertainly.core.dao.repository.scep.ScepTransactionRepository;
import com.czertainly.core.intune.scepvalidation.IntuneScepServiceClient;
import com.czertainly.core.logging.LoggingHelper;
import com.czertainly.core.model.auth.CertificateProtocolInfo;
import com.czertainly.core.provider.CzertainlyProvider;
import com.czertainly.core.provider.key.CzertainlyPrivateKey;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.CryptographicKeyService;
import com.czertainly.core.service.scep.ScepService;
import com.czertainly.core.service.scep.message.ScepRequest;
import com.czertainly.core.service.scep.message.ScepResponse;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.CertificateUtil;
import com.czertainly.core.util.CertificateRequestUtils;
import com.czertainly.core.util.RandomUtil;
import org.bouncycastle.asn1.x500.X500Name;
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
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.*;

@Service
@Transactional
public class ScepServiceImpl implements ScepService {

    public static final String SCEP_URL_PREFIX = "/v1/protocols/scep";
    public static final String SCEP_OPERATION_GET_CA_CERT = "GetCACert";
    public static final String SCEP_OPERATION_GET_CA_CAPS = "GetCACaps";
    public static final String SCEP_OPERATION_PKI_OPERATION = "PKIOperation";

    private static final Logger logger = LoggerFactory.getLogger(ScepServiceImpl.class);
    private static final List<String> SCEP_CA_CAPABILITIES = List.of(
            "POSTPKIOperation",
            "SHA-1",
            "SHA-256",
            "SHA-512",
            "DES3",
            "AES",
            "Renewal",
            "SCEPStandard"
    );

    @Value("${app.version}")
    private String appVersion;

    private List<X509Certificate> caCertificateChain = new ArrayList<>();
    private X509Certificate recipient;
    private boolean raProfileBased;
    private RaProfile raProfile;
    private List<RequestAttribute> issueAttributes;
    private ScepProfile scepProfile;
    private RaProfileRepository raProfileRepository;
    private ScepProfileRepository scepProfileRepository;
    private ScepTransactionRepository scepTransactionRepository;
    private ClientOperationService clientOperationService;
    private CertificateService certificateService;
    private CryptographicKeyService cryptographicKeyService;
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
    public void setScepProfileRepository(ScepProfileRepository scepProfileRepository) {
        this.scepProfileRepository = scepProfileRepository;
    }

    @Autowired
    public void setScepTransactionRepository(ScepTransactionRepository scepTransactionRepository) {
        this.scepTransactionRepository = scepTransactionRepository;
    }

    @Autowired
    public void setClientOperationService(ClientOperationService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setCryptographicKeyService(CryptographicKeyService cryptographicKeyService) {
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
    public ResponseEntity<Object> handleGet(String profileName, String operation, String message) throws ScepException {
        logger.debug("SCEP GET request received for profile: {}, operation: {}, message: {}", profileName, operation, message);
        byte[] encoded = new byte[0];
        if (message != null) {
            encoded = message.getBytes();
        }
        return service(profileName, operation, encoded);
    }

    @Override
    public ResponseEntity<Object> handlePost(String profileName, String operation, byte[] message) throws ScepException {
        if (logger.isDebugEnabled()) {
            logger.debug("SCEP POST request received for profile: {}, operation: {}, message: {}", profileName, operation, Base64.getEncoder().encodeToString(message));
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
            default ->
                    buildResponse(null, buildFailedResponse(new ScepException("Unsupported Operation", FailInfo.BAD_REQUEST), null));
        };
    }

    private void init(String profileName) throws ScepException {
        this.raProfileBased = ServletUriComponentsBuilder.fromCurrentRequestUri().build().toUriString().contains("/raProfile/");
        if (raProfileBased) {
            raProfile = raProfileRepository.findByName(profileName).orElse(null);
            if (raProfile == null) {
                return;
            }
            scepProfile = raProfile.getScepProfile();
            String attributesJson = raProfile.getProtocolAttribute() != null ? raProfile.getProtocolAttribute().getScepIssueCertificateAttributes() : null;
            issueAttributes = AttributeDefinitionUtils.getClientAttributes(AttributeDefinitionUtils.deserialize(attributesJson, DataAttributeV2.class));
        } else {
            scepProfile = scepProfileRepository.findByName(profileName).orElse(null);
            if (scepProfile == null) {
                return;
            }
            raProfile = scepProfile.getRaProfile();
            if (raProfile == null) {
                return;
            }

            issueAttributes = attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.SCEP_PROFILE, scepProfile.getUuid()).connector(scepProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_ISSUE).build());
        }
        LoggingHelper.putLogResourceInfo(Resource.SCEP_PROFILE, true, scepProfile.getUuid().toString(), scepProfile.getName());

        Certificate scepCaCertificate = scepProfile.getCaCertificate();
        if (scepCaCertificate == null) {
            throw new ScepException("SCEP Profile does not have any associated CA certificate", FailInfo.BAD_REQUEST);
        }

        setRecipient(scepCaCertificate.getCertificateContent().getContent());
        try {
            this.caCertificateChain = loadCertificateChain(scepCaCertificate);
        } catch (NotFoundException e) {
            throw new ScepException("Failed to load certificate chain of SCEP profile CA certificate");
        }

        logger.debug("SCEP service initialized: isRaProfileBased: {}, raProfile: {}, scepProfile: {}", raProfileBased, raProfile, scepProfile);
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
        if (!CertificateUtil.isCertificateScepCaCertAcceptable(scepProfile.getCaCertificate(), scepProfile.isIntuneEnabled())) {
            throw new ScepException("SCEP Profile does not have associated acceptable CA certificate", FailInfo.BAD_REQUEST);
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
        if (contentLength != null) responseHeaders.set("Content-Length", String.valueOf(contentLength));
        return new ResponseEntity<>(body, responseHeaders, HttpStatus.OK);
    }

    private ResponseEntity<Object> pkiOperation(byte[] body) throws ScepException {
        ScepRequest scepRequest;
        ScepResponse scepResponse;
        IntuneScepServiceClient intuneClient = null;

        scepRequest = new ScepRequest(body);

        logger.debug("Processing SCEP request: transactionId={}", scepRequest.getTransactionId());

        CryptographicKey key = scepProfile.getCaCertificate().getKey();
        CryptographicKeyItem item = cryptographicKeyService.getKeyItemFromKey(key, KeyType.PRIVATE_KEY);
        var connectorDto = key.getTokenInstanceReference().getConnector().mapToDto();
        // Get the private key from the configuration of SCEP Profile
        CzertainlyPrivateKey czertainlyPrivateKey = new CzertainlyPrivateKey(
                key.getTokenInstanceReference().getTokenInstanceUuid(),
                item.getKeyReferenceUuid().toString(),
                connectorDto,
                item.getKeyAlgorithm().getLabel()
        );

        CryptographicOperationsSyncApiClient cryptoApiClient = connectorApiFactory.getCryptographicOperationsApiClient(connectorDto);
        CzertainlyProvider czertainlyProvider = CzertainlyProvider.getInstance(scepProfile.getName(), true, cryptoApiClient);

        // decrypt the PKCS#10 request
        try {
            scepRequest.decryptData(
                    czertainlyPrivateKey,
                    czertainlyProvider,
                    cryptographicKeyService.getKeyItemFromKey(scepProfile.getCaCertificate().getKey(), KeyType.PRIVATE_KEY).getKeyAlgorithm(),
                    scepProfile.getChallengePassword()
            );
        } catch (CMSException e) {
            return buildResponse(scepRequest, buildFailedResponse(new ScepException("Unable to decrypt the data. " + e.getMessage(), FailInfo.BAD_REQUEST), scepRequest.getTransactionId()));
        }

        if (scepProfile.isIntuneEnabled()) {
            Properties properties = getIntuneConfiguration();
            intuneClient = buildIntuneClient(properties);
        }

        // validate challenge password, if configured
        if (scepRequest.getMessageType().equals(MessageType.PKCS_REQ) || scepRequest.getMessageType().equals(MessageType.RENEWAL_REQ)) {
            if (!validateScepChallengePassword(scepRequest.getChallengePassword())) {
                return buildResponse(scepRequest, buildFailedResponse(new ScepException("Challenge password validation failed.", FailInfo.BAD_MESSAGE_CHECK), scepRequest.getTransactionId()));
            }
            // validate the request POP
            try {
                verifyRequest(scepRequest);
            } catch (ScepException e) {
                return buildResponse(scepRequest, buildFailedResponse(e, scepRequest.getTransactionId()));
            }
        }

        if (scepTransactionRepository.existsByTransactionIdAndScepProfile(scepRequest.getTransactionId(), scepProfile)) {
            LoggingHelper.putAuditLogOperation(Operation.SCEP_TRANSACTION_CHECK);
            try {
                scepResponse = getExistingTransaction(scepRequest.getTransactionId());
            } catch (ScepException e) {
                scepResponse = buildFailedResponse(new ScepException("Error while formatting certificate", FailInfo.BAD_REQUEST), scepRequest.getTransactionId());
            } catch (NotFoundException e) {
                scepResponse = buildFailedResponse(new ScepException("Transaction certificate not found", FailInfo.BAD_REQUEST), scepRequest.getTransactionId());
            }
        } else if (scepRequest.getMessageType().equals(MessageType.PKCS_REQ)) {
            try {
                // Manual approval for the SCEP clients are configured in the SCEP Profile.
                // If the SCEP Profile has the manual approval set to true, only the CSR will be generated
                if (scepProfile.getRequireManualApproval() != null && !scepProfile.getRequireManualApproval()) {
                    LoggingHelper.putAuditLogOperation(Operation.ISSUE);
                    scepResponse = issueCertificate(scepRequest, intuneClient);
                } else {
                    LoggingHelper.putAuditLogOperation(Operation.REQUEST);
                    scepResponse = generateCsr(scepRequest, intuneClient);
                }
            } catch (ScepException e) {
                scepResponse = buildFailedResponse(e, scepRequest.getTransactionId());
                // 32-bit error code formulated using the instructions specified in https://msdn.microsoft.com/en-us/library/cc231198.aspx
                // this is a vendor specific error code
                final long errorCode = 0x20000000L + e.getFailInfo().getValue();
                if (scepProfile.isIntuneEnabled()) {
                    sendIntuneFailureMessage(
                            intuneClient,
                            scepRequest,
                            errorCode,
                            e.getMessage().substring(0, Math.min(e.getMessage().length(), 255))
                    );
                }
            }
        } else if (scepRequest.getMessageType().equals(MessageType.CERT_POLL)) {
            LoggingHelper.putAuditLogOperation(Operation.SCEP_CERTIFICATE_POLL);
            scepResponse = pollCertificate(scepRequest, intuneClient);
        } else {
            scepResponse = buildFailedResponse(new ScepException("Unsupported Operation. The requested operation is not supported", FailInfo.BAD_REQUEST), scepRequest.getTransactionId());
        }
        return buildResponse(scepRequest, scepResponse);
    }

    private ScepResponse buildFailedResponse(ScepException scepException, String transactionId) {
        ScepResponse scepResponse = new ScepResponse();
        scepResponse.setPkiStatus(PkiStatus.FAILURE);
        scepResponse.setFailInfo(scepException.getFailInfo());
        scepResponse.setFailInfoText(scepException.getMessage());
        if (transactionId != null) {
            scepResponse.setTransactionId(transactionId);
        }

        logger.debug("SCEP request failed: {}, failInfo={}, cause={}, transactionId={}, scepProfile={}, raProfile={}",
                scepException.getMessage(),
                scepException.getFailInfo(),
                scepException.getCause() != null ? scepException.getCause().getMessage() : null,
                transactionId,
                this.scepProfile.getName(),
                this.raProfileBased ? this.raProfile.getName() : null
        );

        return scepResponse;
    }

    private ResponseEntity<Object> buildResponse(ScepRequest scepRequest, ScepResponse scepResponse) throws ScepException {
        prepareMessage(scepRequest, scepResponse);
        CryptographicKey key = scepProfile.getCaCertificate().getKey();
        var connectorDto = key.getTokenInstanceReference().getConnector().mapToDto();
        CryptographicOperationsSyncApiClient cryptoApiClient = connectorApiFactory.getCryptographicOperationsApiClient(connectorDto);
        CzertainlyProvider czertainlyProvider = CzertainlyProvider.getInstance(scepProfile.getName(), true, cryptoApiClient);
        CryptographicKeyItem item = cryptographicKeyService.getKeyItemFromKey(key, KeyType.PRIVATE_KEY);
        // Get the private key from the configuration of SCEP Profile
        CzertainlyPrivateKey czertainlyPrivateKey = new CzertainlyPrivateKey(
                key.getTokenInstanceReference().getTokenInstanceUuid(),
                item.getKeyReferenceUuid().toString(),
                connectorDto,
                item.getKeyAlgorithm().getLabel()
        );
        try {
            scepResponse.setSigningAttributes(
                    CertificateUtil.getX509Certificate(scepProfile.getCaCertificate().getCertificateContent().getContent()),
                    czertainlyPrivateKey,
                    czertainlyProvider

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

    private ScepResponse issueCertificate(ScepRequest scepRequest, IntuneScepServiceClient intuneClient) throws ScepException {
        if (scepProfile.isIntuneEnabled()) {
            validateIntuneRequest(
                    intuneClient,
                    scepRequest
            );
        }
        ClientCertificateSignRequestDto requestDto = new ClientCertificateSignRequestDto();
        try {
            requestDto.setRequest(new String(Base64.getEncoder().encode(scepRequest.getPkcs10Request().getEncoded())));
            requestDto.setFormat(CertificateRequestFormat.PKCS10);
            requestDto.setAttributes(issueAttributes);
        } catch (IOException e) {
            throw new ScepException("Unable to decode PKCS#10 request", e, FailInfo.BAD_REQUEST);
        }
        ClientCertificateDataResponseDto response;
        try {
            response = clientOperationService.issueCertificate(raProfile.getAuthorityInstanceReference().getSecuredParentUuid(), raProfile.getSecuredUuid(), requestDto, CertificateProtocolInfo.Scep(scepProfile.getUuid()));
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
            throw new ScepException(String.format("Issued certificate not found in inventory: uuid=%s", response.getUuid()), FailInfo.BAD_REQUEST);
        }

        addTransactionEntity(scepRequest.getTransactionId(), response.getUuid());

        scepResponse.setPkiStatus(PkiStatus.SUCCESS);
        if (scepProfile.isIntuneEnabled()) sendIntuneSuccessNotification(
                intuneClient,
                scepRequest,
                certificate
        );
        return scepResponse;
    }


    private ScepResponse generateCsr(ScepRequest scepRequest, IntuneScepServiceClient intuneClient) throws ScepException {
        if (scepProfile.isIntuneEnabled()) {
            validateIntuneRequest(
                    intuneClient,
                    scepRequest
            );
        }
        ScepResponse scepResponse = new ScepResponse();
        ClientCertificateRequestDto requestDto = new ClientCertificateRequestDto();
        if (raProfile != null) requestDto.setRaProfileUuid(raProfile.getUuid());
        try {
            requestDto.setRequest(new String(Base64.getEncoder().encode(scepRequest.getPkcs10Request().getEncoded())));
            requestDto.setFormat(CertificateRequestFormat.PKCS10);
        } catch (IOException e) {
            throw new ScepException("Unable to decode PKCS#10 request", e, FailInfo.BAD_REQUEST);
        }
        CertificateDetailDto response;
        try {
            response = clientOperationService.submitCertificateRequest(requestDto, CertificateProtocolInfo.Scep(scepProfile.getUuid()));
        } catch (CertificateException | NotFoundException | NoSuchAlgorithmException | AttributeException |
                 ConnectorException | CertificateRequestException e) {
            throw new ScepException("Unable to submit certificate request", e, FailInfo.BAD_REQUEST);
        }

        addTransactionEntity(scepRequest.getTransactionId(), response.getUuid());
        scepResponse.setPkiStatus(PkiStatus.PENDING);

        return scepResponse;
    }

    private ScepResponse getExistingTransaction(String transactionId) throws ScepException, NotFoundException {
        ScepTransaction scepTransaction = scepTransactionRepository.findByTransactionIdAndScepProfile(transactionId, scepProfile).orElse(null);
        assert scepTransaction != null;
        Certificate certificate = scepTransaction.getCertificate();

        if (certificate.getState() == CertificateState.REJECTED) {
            return buildFailedResponse(new ScepException("Certificate issuance was rejected", FailInfo.BAD_REQUEST), transactionId);
        }
        if (certificate.getState() == CertificateState.FAILED) {
            return buildFailedResponse(new ScepException("Certificate issuance failed", FailInfo.BAD_REQUEST), transactionId);
        }

        ScepResponse scepResponse = new ScepResponse();
        if (certificate.getState() == CertificateState.ISSUED) {
            scepResponse.setPkiStatus(PkiStatus.SUCCESS);
            scepResponse.setCertificateChain(getIssuedCertificateChain(certificate));
        } else {
            scepResponse.setPkiStatus(PkiStatus.PENDING);
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
            if (transaction != null) {
                Certificate certificate = transaction.getCertificate();
                if (certificate.getState() == CertificateState.REJECTED) {
                    return buildFailedResponse(new ScepException("Certificate issuance was rejected", FailInfo.BAD_REQUEST), scepRequest.getTransactionId());
                }
                if (certificate.getState() == CertificateState.FAILED) {
                    return buildFailedResponse(new ScepException("Certificate issuance failed", FailInfo.BAD_REQUEST), scepRequest.getTransactionId());
                }

                if (certificate.getState().equals(CertificateState.ISSUED)) {
                    X509Certificate x509Certificate = CertificateUtil.parseCertificate(certificate.getCertificateContent().getContent());
                    scepResponse.setCertificateChain(getIssuedCertificateChain(certificate));
                    scepResponse.setPkiStatus(PkiStatus.SUCCESS);
                    sendIntuneSuccessNotification(
                            intuneClient,
                            scepRequest,
                            x509Certificate
                    );
                }
            } else {
                scepResponse.setPkiStatus(PkiStatus.PENDING);
            }
            prepareMessage(scepRequest, scepResponse);

        } catch (Exception e) {
            logger.error(e.getMessage());
        }
        return scepResponse;
    }

    private List<X509Certificate> loadCertificateChain(Certificate leafCertificate) throws ScepException, NotFoundException {
        ArrayList<X509Certificate> certificateChain = new ArrayList<>();
        for (CertificateDetailDto certificate : certificateService.getCertificateChain(leafCertificate.getSecuredUuid(), true).getCertificates()) {
            // only certificate with valid status should be used
            checkCertificateValidity(certificate);
            try {
                certificateChain.add(CertificateUtil.parseCertificate(certificate.getCertificateContent()));
            } catch (CertificateException e) {
                // This should not happen
                throw new IllegalArgumentException("Failed to parse certificate content: " +
                        certificate.getCertificateContent());
            }
        }

        return certificateChain;
    }

    private List<X509Certificate> getIssuedCertificateChain(Certificate certificate) throws ScepException, NotFoundException {
        if (!this.scepProfile.isIncludeCaCertificateChain() && !this.scepProfile.isIncludeCaCertificate()) {
            try {
                checkCertificateValidity(certificate.mapToDto());

                return List.of(CertificateUtil.parseCertificate(certificate.getCertificateContent().getContent()));
            } catch (CertificateException e) {
                // This should not happen
                throw new IllegalArgumentException("Failed to parse certificate content: " +
                        certificate.getCertificateContent().getContent());
            }
        }

        logger.debug("Building the certificate chain for the response message");
        var certificateChain = loadCertificateChain(certificate);
        if (this.scepProfile.isIncludeCaCertificateChain()) return certificateChain;
        else return certificateChain.subList(0, Math.min(2, certificateChain.size()));
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
        scepResponse.setRecipientKeyInfo(scepRequest.getRequestKeyInfo());
        scepResponse.setDigestAlgorithmOid(scepRequest.getDigestAlgorithmOid());
        scepResponse.setSenderNonce(RandomUtil.generateRandomNonceBase64(16));
        scepResponse.setContentEncryptionAlgorithm(scepRequest.getContentEncryptionAlgorithm());
    }

    private ScepTransaction getTransaction(String transactionId) {
        return scepTransactionRepository.findByTransactionId(transactionId).orElse(null);
    }

    private boolean validateScepChallengePassword(String challengePassword) {
        if (scepProfile.getChallengePassword() == null || scepProfile.getChallengePassword().isEmpty()) {
            return true;
        }
        return challengePassword.equals(scepProfile.getChallengePassword());
    }

    public void verifyRequest(ScepRequest scepRequest) throws ScepException {

        // Throw exception if the request type is not renewal or issuing a new certificate
        if (!scepRequest.getMessageType().equals(MessageType.RENEWAL_REQ) && !scepRequest.getMessageType().equals(MessageType.PKCS_REQ)) {
            throw new ScepException("Unsupported Operation", FailInfo.BAD_REQUEST);
        }

        if (scepRequest.getMessageType().equals(MessageType.PKCS_REQ)) {
            // Renewal check must be done for PKCS Request also. According to the RFC Version 3.1.1.2
            // (https://datatracker.ietf.org/doc/id/draft-nourse-scep-23.txt), RENEWAL_REQ is not part of the message type
            // Commonly used SCEP clients like JSCEP and SSCEP uses this version of RFC and
            // may use PKCS_REQ for renewal
            renewalValidation(scepRequest);
            try {
                if (!scepRequest.verifyRequest()) {
                    throw new ScepException("Failed to verify PKCS#10 request POP, invalid signature", FailInfo.BAD_REQUEST);
                }
            } catch (PKCSException | NoSuchAlgorithmException | InvalidKeyException | OperatorCreationException e) {
                throw new ScepException("Failed to verify PKCS#10 request POP", FailInfo.BAD_REQUEST);
            }
        } else if (scepRequest.getMessageType().equals(MessageType.RENEWAL_REQ)) {
            renewalValidation(scepRequest);
        }
    }

    private void renewalValidation(ScepRequest scepRequest) throws ScepException {
        JcaPKCS10CertificationRequest pkcs10Request = scepRequest.getPkcs10Request();
        Certificate extCertificate;
        try {
            extCertificate = certificateService.getCertificateEntityByFingerprint(CertificateUtil.getThumbprint(scepRequest.getSignerCertificate()));
        } catch (NotFoundException e) {
            // Certificate is not found with the fingerprint. Meaning its not a renewal request. So do nothing
            return;
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            throw new ScepException("Unable to parse the signer certificate");
        }
        if (extCertificate.isArchived())
            throw new ScepException("Certificate with UUID %s is archived. Cannot be renewed by SCEP.".formatted(extCertificate.getUuid()));
        if (!(new X500Name(extCertificate.getSubjectDn())).equals(pkcs10Request.getSubject())) {
            throw new ScepException("Subject DN for the renewal request does not match the original certificate");
        }
        try {
            if (!scepRequest.verifySignature(scepRequest.getSignerCertificate().getPublicKey())) {
                throw new ScepException("SCEP Request signature verification failed");
            }
        } catch (OperatorCreationException | CMSException e) {
            throw new ScepException("Exception when verifying signature." + e.getMessage());
        }
        // No need to verify the same key pair used in request since it is already handled by the rekey method in client operations
        checkRenewalTimeframe(extCertificate);
    }

    private void checkRenewalTimeframe(Certificate certificate) throws ScepException {
        // Empty renewal threshold or the value 0 will be considered as null value and the half life of the certificate will be assumed
        if (scepProfile.getRenewalThreshold() == null || scepProfile.getRenewalThreshold() == 0) {
            // If the renewal timeframe is not given, we consider that renewal is possible only after the certificate
            // crosses its half lime time
            if (certificate.getValidity() / 2 < certificate.getExpiryInDays()) {
                throw new ScepException("Cannot renew certificate. Validity exceeds the half life time of certificate", FailInfo.BAD_REQUEST);
            }
        } else if (certificate.getValidationStatus().equals(CertificateValidationStatus.EXPIRED) || certificate.getState().equals(CertificateState.REVOKED)) {
            throw new ScepException("Cannot renew certificate. Certificate is already in expired or revoked state", FailInfo.BAD_REQUEST);
        } else {
            if (certificate.getExpiryInDays() > scepProfile.getRenewalThreshold()) {
                throw new ScepException("Cannot renew certificate. Validity exceeds the configured value in SCEP profile", FailInfo.BAD_REQUEST);
            }
        }
    }

    private Properties getIntuneConfiguration() {
        // Create the properties based on the SCEP profile Intune properties
        Properties configProperties = new Properties();
        configProperties.put("AAD_APP_ID", scepProfile.getIntuneApplicationId());
        configProperties.put("AAD_APP_KEY", scepProfile.getIntuneApplicationKey());
        configProperties.put("TENANT", scepProfile.getIntuneTenant());
        configProperties.put("PROVIDER_NAME_AND_VERSION", "CZERTAINLY-V" + appVersion);
        return configProperties;
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
            client.ValidateRequest(
                    scepRequest.getTransactionId(),
                    CertificateRequestUtils.byteArrayCsrToString(scepRequest.getPkcs10Request().getEncoded())
            );
        } catch (Exception e) {
            throw new ScepException("Validation failed for Intune request.", e, FailInfo.BAD_REQUEST);
        }
    }

    private void sendIntuneSuccessNotification(
            IntuneScepServiceClient client,
            ScepRequest request,
            X509Certificate certificate) {
        String pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSXXX";
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(pattern);
        String expiryDate = simpleDateFormat.format(certificate.getNotAfter());
        String serialNumber = certificate.getSerialNumber().toString(16);
        String issuingAuthority = certificate.getIssuerX500Principal().getName();

        try {
            String sha1Thumbprint = CertificateUtil.getSha1Thumbprint(certificate.getEncoded());
            client.SendSuccessNotification(
                    request.getTransactionId(),
                    CertificateRequestUtils.byteArrayCsrToString(request.getPkcs10Request().getEncoded()),
                    sha1Thumbprint,
                    serialNumber,
                    expiryDate,
                    issuingAuthority,
                    "",
                    ""
            );
        } catch (Exception e) {
            logger.error("Unable to update Intune with success notification: {}", e.getMessage());
        }
    }

    private void sendIntuneFailureMessage(IntuneScepServiceClient client, ScepRequest request, long errorCode, String error) {
        if (client != null) {
            try {
                client.SendFailureNotification(
                        request.getTransactionId(),
                        CertificateRequestUtils.byteArrayCsrToString(request.getPkcs10Request().getEncoded()),
                        errorCode,
                        error
                );
            } catch (Exception e) {
                logger.error("Unable to update Intune with failed notification: {}", e.getMessage());
            }
        } else {
            logger.error("Unable to update Intune because the client is not available.");
        }
    }

    private void checkCertificateValidity(CertificateDetailDto certificate) throws ScepException {
        if (certificate.getValidationStatus() != CertificateValidationStatus.VALID
                && certificate.getValidationStatus() != CertificateValidationStatus.EXPIRING) {
            throw new ScepException(String.format("Certificate is not valid. UUID: %s, Fingerprint: %s, Status: %s",
                    certificate.getUuid(),
                    certificate.getFingerprint(),
                    certificate.getValidationStatus().getLabel()),
                    FailInfo.BAD_REQUEST);
        }
    }
}
