package com.czertainly.core.service.cmp.impl;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.cmp.PkiMessageError;
import com.czertainly.api.interfaces.core.cmp.error.*;
import com.czertainly.api.model.client.attribute.RequestAttribute;
import com.czertainly.api.model.common.attribute.v2.DataAttributeV2;
import com.czertainly.api.model.core.auth.Resource;
import com.czertainly.api.model.core.certificate.CertificateDetailDto;
import com.czertainly.api.model.core.certificate.CertificateValidationStatus;
import com.czertainly.api.model.core.cmp.CmpTransactionState;
import com.czertainly.api.model.core.cmp.ProtectionMethod;
import com.czertainly.api.model.core.logging.enums.Operation;
import com.czertainly.core.dao.entity.cmp.CmpTransaction;
import com.czertainly.core.logging.LoggingHelper;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.cmp.message.CertificateKeyServiceImpl;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.CmpTransactionService;
import com.czertainly.core.service.cmp.message.PkiMessageDumper;
import com.czertainly.core.service.cmp.message.builder.PkiMessageBuilder;
import com.czertainly.core.service.cmp.message.handler.*;
import com.czertainly.core.service.cmp.message.validator.impl.BodyValidator;
import com.czertainly.core.service.cmp.message.validator.impl.HeaderValidator;
import com.czertainly.core.service.cmp.message.validator.impl.ProtectionValidator;
import com.czertainly.core.service.cmp.configurations.variants.CmpConfigurationContext;
import com.czertainly.core.service.cmp.configurations.variants.Mobile3gppProfileContext;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.attribute.engine.AttributeOperation;
import com.czertainly.core.attribute.engine.records.ObjectAttributeContentInfo;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.RaProfile;
import com.czertainly.core.dao.entity.cmp.CmpProfile;
import com.czertainly.core.dao.repository.RaProfileRepository;
import com.czertainly.core.dao.repository.cmp.CmpProfileRepository;
import com.czertainly.core.service.cmp.CmpService;
import com.czertainly.core.util.AttributeDefinitionUtils;
import com.czertainly.core.util.CertificateUtil;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.servlet.support.ServletUriComponentsBuilder;

import static com.czertainly.core.service.cmp.CmpConstants.*;

import java.io.IOException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;

@Service
@Transactional
public class CmpServiceImpl implements CmpService {

    private static final Logger LOG = LoggerFactory.getLogger(CmpServiceImpl.class.getName());

    // -- RA PROFILE
    private boolean raProfileBased;
    private RaProfile raProfile;
    private RaProfileRepository raProfileRepository;

    @Autowired
    public void setRaProfileRepository(RaProfileRepository raProfileRepository) {
        this.raProfileRepository = raProfileRepository;
    }

    // -- CMP PROFILE
    private CmpProfile cmpProfile;
    private CmpProfileRepository cmpProfileRepository;

    @Autowired
    public void setCmpProfileRepository(CmpProfileRepository cmpProfileRepository) {
        this.cmpProfileRepository = cmpProfileRepository;
    }

    private List<RequestAttribute> issueAttributes;
    private List<RequestAttribute> revokeAttributes;

    // -- CRYPTO
    private CertificateKeyServiceImpl certificateKeyServiceImpl;

    @Autowired
    private void setCertificateKeyService(CertificateKeyServiceImpl certificateKeyServiceImpl) {
        this.certificateKeyServiceImpl = certificateKeyServiceImpl;
    }

    // -- HANDLER
    private CrmfMessageHandler crmfMessageHandler;

    @Autowired
    public void setCrmfMessageHandler(CrmfMessageHandler crmfMessageHandler) {
        this.crmfMessageHandler = crmfMessageHandler;
    }

    private CertConfirmMessageHandler certConfirmMessageHandler;

    @Autowired
    public void setCertConfirmMessageHandler(CertConfirmMessageHandler certConfirmMessageHandler) {
        this.certConfirmMessageHandler = certConfirmMessageHandler;
    }

    private RevocationMessageHandler revocationMessageHandler;

    @Autowired
    public void setRevocationMessageHandler(RevocationMessageHandler revocationMessageHandler) {
        this.revocationMessageHandler = revocationMessageHandler;
    }

    private PollReqMessageHandler pollReqMessageHandler;

    @Autowired
    public void setPollReqMessageHandler(PollReqMessageHandler pollReqMessageHandler) {
        this.pollReqMessageHandler = pollReqMessageHandler;
    }

    // -- TRANSACTION
    private CmpTransactionService cmpTransactionService;

    @Autowired
    private void setCmpTransactionService(CmpTransactionService cmpTransactionService) {
        this.cmpTransactionService = cmpTransactionService;
    }

    // -- VALIDATORS
    private HeaderValidator headerValidator;

    @Autowired
    private void setHeaderValidator(HeaderValidator headerValidator) {
        this.headerValidator = headerValidator;
    }

    private BodyValidator bodyValidator;

    @Autowired
    private void setBodyValidator(BodyValidator bodyValidator) {
        this.bodyValidator = bodyValidator;
    }

    private ProtectionValidator protectionValidator;

    @Autowired
    private void setProtectionValidator(ProtectionValidator protectionValidator) {
        this.protectionValidator = protectionValidator;
    }

    @Value("${cmp.verbose:false}")
    private boolean verbose;

    // -- OTHERS
    private AttributeEngine attributeEngine;
    private CertificateService certificateService;

    @Autowired
    private void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }

    /**
     * Handling http post's request (which include binary <code>request</code> content of {@link PKIMessage}) related to
     * specific <code>profileName</code>.
     *
     * @param profileName specific customer-based configuration/customization
     * @param request     contains  {@link PKIMessage}
     * @return response contains {@link PKIMessage}
     * @throws CmpBaseException if any error has been raised
     */
    @Override
    public ResponseEntity<byte[]> handlePost(String profileName, byte[] request) throws CmpBaseException {
        final PKIMessage pkiRequest;
        try {
            pkiRequest = PKIMessage.getInstance(request);
        } catch (IllegalArgumentException e) {
            LOG.error("PN={} | request message cannot be parsed", profileName, e);
            return buildBadRequest(PkiMessageError.unprotectedMessage(
                    PKIFailureInfo.badRequest,
                    ImplFailureInfo.CMPSRV100));
        }
        ASN1OctetString tid = pkiRequest.getHeader().getTransactionID();
        String requestAsString = PkiMessageDumper.dumpPkiMessage(pkiRequest);
        String logPrefix = PkiMessageDumper.logPrefix(pkiRequest, profileName);

        if (LOG.isInfoEnabled()) {
            LOG.info("{} | request processing: {}", logPrefix, PkiMessageDumper.dumpPkiMessage(verbose, pkiRequest));
            if (verbose) {
                LOG.info("{} | request as base64: {}", logPrefix, Base64.getEncoder().encodeToString(request));
            }
        }

        // -- (processing) part
        init(profileName);
        ConfigurationContext configuration = switch (cmpProfile.getVariant()) {
            /*   3gpp*/
            case V2_3GPP -> new Mobile3gppProfileContext(cmpProfile, raProfile, pkiRequest,
                    certificateKeyServiceImpl, issueAttributes, revokeAttributes);
            /*rfc4210*/
            case V2 -> new CmpConfigurationContext(cmpProfile, raProfile, pkiRequest,
                    certificateKeyServiceImpl, issueAttributes, revokeAttributes);
            /*rfc9483*/
            case V3 -> throw new UnsupportedOperationException("not implemented");
        };

        try {
            PKIMessage pkiResponse;
            int bodyType = pkiRequest.getBody().getType();
            validateProfile(tid, bodyType, profileName);

            headerValidator.validate(pkiRequest, configuration);
            bodyValidator.validate(pkiRequest, configuration);
            protectionValidator.validateIn(pkiRequest, configuration);

            //see https://www.rfc-editor.org/rfc/rfc4210#section-5.1.2, PKI Message Body
            switch (bodyType) {
                case PKIBody.TYPE_INIT_REQ,         // ( 1)       ir, Initial Request; CertReqMessages
                     PKIBody.TYPE_CERT_REQ,         // ( 2)       cr, Certification Req; CertReqMessages
                     PKIBody.TYPE_KEY_UPDATE_REQ:   // ( 7)      kur, Key Update Request; CertReqMessages
                    pkiResponse = crmfMessageHandler.handle(pkiRequest, configuration);
                    if (pkiResponse == null) {
                        throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.systemFailure,
                                String.format(" %s | general problem while handling crmf message", logPrefix));
                    }
                    LoggingHelper.putAuditLogOperation(bodyType == PKIBody.TYPE_KEY_UPDATE_REQ ? Operation.REKEY : Operation.ISSUE);
                    break;
                case PKIBody.TYPE_REVOCATION_REQ:                  // (11)       rr, Revocation Request; RevReqContent
                    pkiResponse = revocationMessageHandler.handle(pkiRequest, configuration);
                    LoggingHelper.putAuditLogOperation(Operation.REVOKE);
                    break;
                case PKIBody.TYPE_CERT_CONFIRM:                    // (24) certConf, Certificate confirm; CertConfirmContent
                    pkiResponse = certConfirmMessageHandler.handle(pkiRequest, configuration);
                    LoggingHelper.putAuditLogOperation(Operation.CMP_CONFIRM);
                    break;
                case PKIBody.TYPE_POLL_REQ:                        // (25) pollReq, Polling Request (RFC 4210 §5.2.6)
                    pkiResponse = pollReqMessageHandler.handle(pkiRequest, configuration);
                    LoggingHelper.putAuditLogOperation(Operation.GET_STATUS);
                    break;
                case PKIBody.TYPE_CROSS_CERT_REQ,
                     PKIBody.TYPE_KEY_RECOVERY_REQ,
                     PKIBody.TYPE_GEN_MSG,
                     PKIBody.TYPE_NESTED,
                     PKIBody.TYPE_P10_CERT_REQ,
                     PKIBody.TYPE_REVOCATION_ANN,
                     PKIBody.TYPE_CERT_ANN,
                     PKIBody.TYPE_CA_KEY_UPDATE_ANN,
                     PKIBody.TYPE_CRL_ANN,
                     PKIBody.TYPE_POPO_CHALL:
                    throw new CmpProcessingException(PKIFailureInfo.badRequest, ImplFailureInfo.CMPVALMSG200);
                default:
                    if (LOG.isErrorEnabled()) {
                        LOG.error("{} | unknown cmp message type", PkiMessageDumper.logPrefix(pkiRequest, profileName));
                    }
                    throw new CmpProcessingException(PKIFailureInfo.badRequest, ImplFailureInfo.CMPVALMSG201);
            }

            if (pkiResponse == null) {
                throw new CmpProcessingException(
                        PKIFailureInfo.systemFailure,
                        String.format(" %s | general problem while handling PKIMessage", logPrefix));
            }
            if (LOG.isInfoEnabled()) {
                LOG.info("{} | response processed: {}",
                        PkiMessageDumper.logPrefix(pkiResponse, profileName),
                        PkiMessageDumper.dumpPkiMessage(verbose, pkiResponse));
            }

            headerValidator.validate(pkiResponse, configuration);
            bodyValidator.validate(pkiResponse, configuration);
            protectionValidator.validateOut(pkiResponse, configuration);

            return buildOk(pkiResponse);
        } catch (CmpBaseException e) {
            handleTrxError(tid, e);
            PKIMessage pkiResponse = new PkiMessageBuilder(configuration)
                    .addHeader(PkiMessageBuilder.buildBasicHeaderTemplate(pkiRequest))
                    .addBody(e.toPKIBody())
                    .addExtraCerts(null)
                    .build();
            if (verbose) {
                LOG.error("{} | processing failed: \n\n response:\n {}", logPrefix,
                        PkiMessageDumper.dumpPkiMessage(pkiResponse), e);
            } else {
                LOG.error("{} | processing failed: \n\nrequest:\n {}\n response:\n {}", logPrefix,
                        requestAsString, PkiMessageDumper.dumpPkiMessage(pkiResponse), e);
            }
            return buildBadRequest(pkiResponse);
        } catch (IOException e) {
            handleTrxError(tid, e);
            PKIMessage pkiResponse = PkiMessageError.unprotectedMessage(
                    pkiRequest.getHeader(),
                    PKIFailureInfo.badDataFormat,
                    ImplFailureInfo.CMPSRV101);
            if (verbose) {
                LOG.error("{} | parsing failed: \n\n response:\n {}", logPrefix,
                        PkiMessageDumper.dumpPkiMessage(pkiResponse), e);
            } else {
                LOG.error("{} | parsing failed: \n\nrequest:\n {}\n response:\n {}", logPrefix,
                        requestAsString, PkiMessageDumper.dumpPkiMessage(pkiResponse), e);
            }
            return buildBadRequest(pkiResponse);
        } catch (Exception e) {
            handleTrxError(tid, e);
            PKIMessage pkiResponse = PkiMessageError.unprotectedMessage(pkiRequest.getHeader(), e);
            if (verbose) {
                LOG.error("{} | handling failed: \n\n response:\n {}", logPrefix,
                        PkiMessageDumper.dumpPkiMessage(pkiResponse), e);
            } else {
                LOG.error("{} | handling failed: \n\nrequest:\n {}\n response:\n {}", logPrefix,
                        requestAsString, PkiMessageDumper.dumpPkiMessage(pkiResponse), e);
            }
            return buildBadRequest(pkiResponse);
        }
    }

    // Should it be handled in new transaction? It wqs made private since it was called intra class so Transactional annotation was ignored anyway
    //    @Transactional(propagation = Propagation.REQUIRES_NEW)
    private void handleTrxError(ASN1OctetString tid, Exception e) {
        List<CmpTransaction> trx = cmpTransactionService.findByTransactionId(tid.toString());
        if (!trx.isEmpty()) {
            for (CmpTransaction updatedTransaction : trx) {
                updatedTransaction.setState(CmpTransactionState.FAILED);
                String customReason = e.getMessage();
                updatedTransaction.setCustomReason(customReason.substring(0, Math.min(254, customReason.length())));
                cmpTransactionService.save(updatedTransaction);
            }
        }
    }

    private ResponseEntity<byte[]> buildBadRequest(PKIMessage pkiMessage) {
        return ResponseEntity
                .status(HttpStatus.OK)
                .header("Content-Type", HTTP_HEADER_CONTENT_TYPE)
                .body(PkiMessageError.encode(pkiMessage));
    }

    private ResponseEntity<byte[]> buildOk(PKIMessage pkiMessage) throws IOException {
        return ResponseEntity
                .status(HttpStatus.OK)
                .header("Content-Type", HTTP_HEADER_CONTENT_TYPE)
                .body(pkiMessage.getEncoded());
    }

    private void init(String profileName) {
        this.raProfileBased = ServletUriComponentsBuilder.fromCurrentRequestUri().build()
                .toUriString().contains("/raProfile/");
        if (raProfileBased) {
            raProfile = raProfileRepository.findByName(profileName).orElse(null);
            if (raProfile == null) {
                return;
            }
            cmpProfile = raProfile.getCmpProfile();
            if (cmpProfile == null) {
                return;
            }
            LoggingHelper.putLogResourceInfo(Resource.CMP_PROFILE, true, cmpProfile.getUuid().toString(), cmpProfile.getName());

            String attributesJson = raProfile.getProtocolAttribute() != null ? raProfile.getProtocolAttribute().getCmpIssueCertificateAttributes() : null;
            issueAttributes = AttributeDefinitionUtils.getClientAttributes(AttributeDefinitionUtils.deserialize(attributesJson, DataAttributeV2.class));
            String revokeAttributesJson = raProfile.getProtocolAttribute() != null ? raProfile.getProtocolAttribute().getCmpRevokeCertificateAttributes() : null;
            revokeAttributes = AttributeDefinitionUtils.getClientAttributes(AttributeDefinitionUtils.deserialize(revokeAttributesJson, DataAttributeV2.class));
        } else {
            cmpProfile = cmpProfileRepository.findByName(profileName).orElse(null);
            if (cmpProfile == null) {
                return;
            }
            LoggingHelper.putLogResourceInfo(Resource.CMP_PROFILE, true, cmpProfile.getUuid().toString(), cmpProfile.getName());
            raProfile = cmpProfile.getRaProfile();
            if (raProfile == null) {
                return;
            }
            issueAttributes = attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CMP_PROFILE, cmpProfile.getUuid()).connector(cmpProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_ISSUE).build());
            revokeAttributes = attributeEngine.getRequestObjectDataAttributesContent(ObjectAttributeContentInfo.builder(Resource.CMP_PROFILE, cmpProfile.getUuid()).connector(cmpProfile.getRaProfile().getAuthorityInstanceReference().getConnectorUuid()).operation(AttributeOperation.CERTIFICATE_REVOKE).build());
        }
        LOG.debug("PN={} | CMP service initialized: isRaProfileBased: {}, raProfile: {}, cmpProfile: {}", profileName, raProfileBased, raProfile, cmpProfile);
    }

    private void validateProfile(ASN1OctetString tid, int bodyType, String incomingProfileName) throws CmpBaseException {
        try {
            validateCmpProfile(incomingProfileName);
            validateRaProfile(incomingProfileName);
        } catch (CmpConfigurationException e) {
            switch (bodyType) {
                case PKIBody.TYPE_INIT_REQ, PKIBody.TYPE_CERT_REQ, PKIBody.TYPE_KEY_UPDATE_REQ:
                    throw new CmpCrmfValidationException(tid, bodyType, PKIFailureInfo.systemFailure, e.getMessage());
                default:
                    throw new CmpProcessingException(PKIFailureInfo.systemFailure, e.getMessage());
            }
        }
    }

    private void validateCmpProfile(String incomingProfileName) throws CmpConfigurationException {
        if (cmpProfile == null) {
            throw new CmpConfigurationException(PKIFailureInfo.systemFailure,
                    "PN=" + incomingProfileName + " | Requested CMP Profile not found");
        }
        if (Boolean.FALSE.equals(cmpProfile.getEnabled())) {
            throw new CmpConfigurationException(PKIFailureInfo.systemFailure,
                    "PN=" + incomingProfileName + " | CMP Profile is not enabled");
        }

        if (ProtectionMethod.SIGNATURE.equals(cmpProfile.getResponseProtectionMethod())) {
            Certificate cmpCaCertificate = cmpProfile.getSigningCertificate();
            if (cmpCaCertificate == null) {
                throw new CmpConfigurationException(PKIFailureInfo.systemFailure,
                        "PN=" + incomingProfileName + " | CMP profile does not have any associated CA certificate");
            }

            try {
                CertificateUtil.parseCertificate(cmpCaCertificate.getCertificateContent().getContent());
            } catch (CertificateException e) { // This should not occur
                throw new CmpConfigurationException(PKIFailureInfo.systemFailure,
                        "PN=" + incomingProfileName + " | Error converting the certificate to x509 object");
            }


            String certificateContent = null;
            try {
                for (CertificateDetailDto certificate : certificateService.getCertificateChain(cmpCaCertificate.getSecuredUuid(), true).getCertificates()) {
                    // only certificate with valid status should be used
                    if (!certificate.getValidationStatus().equals(CertificateValidationStatus.VALID)) {
                        throw new CmpConfigurationException(PKIFailureInfo.systemFailure,
                                String.format("Certificate is not valid. UUID: %s, Fingerprint: %s, Status: %s",
                                        certificate.getUuid(),
                                        certificate.getFingerprint(),
                                        certificate.getValidationStatus().getLabel()));
                    }

                    certificateContent = certificate.getCertificateContent();
                    CertificateUtil.parseCertificate(certificate.getCertificateContent());
                }
            } catch (NotFoundException e) {
                throw new CmpConfigurationException(PKIFailureInfo.systemFailure,
                        "PN=" + incomingProfileName + " | CMP Profile does not have associated CA certificate chain");
            } catch (CertificateException e) {
                // This should not happen
                throw new IllegalArgumentException("PN=" + this.cmpProfile.getName() + " | Failed to parse certificate content: " +
                        certificateContent);
            }

            if (!CertificateUtil.isCertificateCmpAcceptable(cmpCaCertificate)) {
                throw new CmpConfigurationException(PKIFailureInfo.systemFailure, "CMP Profile does not have associated acceptable CA certificate");
            }
        }
        if (!raProfileBased && cmpProfile.getRaProfile() == null) {
            throw new CmpConfigurationException(PKIFailureInfo.systemFailure,
                    "PN=" + incomingProfileName + " | CMP Profile does not contain associated RA Profile");
        }
    }

    private void validateRaProfile(String incomingProfileName) throws CmpConfigurationException {
        if (raProfile == null) {
            throw new CmpConfigurationException(PKIFailureInfo.systemFailure,
                    "PN=" + incomingProfileName + " | Requested RA Profile not found");
        }
        if (Boolean.FALSE.equals(raProfile.getEnabled())) {
            throw new CmpConfigurationException(PKIFailureInfo.systemFailure,
                    "PN=" + incomingProfileName + " | RA Profile is not enabled");
        }
        if (raProfileBased && raProfile.getCmpProfile() == null) {
            throw new CmpConfigurationException(PKIFailureInfo.systemFailure,
                    "PN=" + incomingProfileName + " | RA Profile does not contain associated CMP Profile");
        }
    }

}
