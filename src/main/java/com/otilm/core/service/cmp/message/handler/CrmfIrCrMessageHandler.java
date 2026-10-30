package com.otilm.core.service.cmp.message.handler;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpCrmfValidationException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.cmp.CmpTransactionState;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateIssueRequestDto;
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.PkiMessageDumper;
import com.otilm.core.service.cmp.registration.CmpRegistrationIdentityVerifier;
import com.otilm.core.service.cmp.registration.CmpRegistrationResolver;
import com.otilm.core.service.v2.ClientOperationExternalService;
import com.otilm.core.service.v2.ClientOperationInternalService;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.slf4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * <p>
 * Interface how to handle incoming request (ir/cr) message from client.
 * </p>
 *
 * <p>
 * See Appendix C and [CRMF] for CertReqMessages syntax.
 * </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-4.2.1.1">[1] - Initial Request</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.3.1">[2] - CertReqMessages syntax</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4211#section-3">[3] - CertRequest syntax</a>
 * @see <a href=
 * "https://doc.primekey.com/bouncycastle/how-to-guides-pki-at-the-edge/how-to-generate-key-pairs-and-certification-requests#HowtoGenerateKeyPairsandCertificationRequests-GenerateCRMFCertificationRequestusingCMP">How
 * to generate CRMF request</a>
 */
@Component
@Transactional
public class CrmfIrCrMessageHandler implements MessageHandler<ClientCertificateDataResponseDto> {

    private static final List<Integer> ALLOWED_TYPES = List
            .of(PKIBody.TYPE_INIT_REQ, // ir [0] CertReqMessages, --Initialization Req
                    PKIBody.TYPE_CERT_REQ); // cr [2] CertReqMessages, --Certification Req

    private static final Logger logger = org.slf4j.LoggerFactory.getLogger(CrmfIrCrMessageHandler.class);

    private ClientOperationInternalService clientOperationService;
    private ClientOperationExternalService clientOperationExternalService;
    private CmpRegistrationIdentityVerifier registrationIdentityVerifier;
    private CertificateInternalService certificateService;

    @Autowired
    public void setClientOperationService(ClientOperationInternalService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    @Autowired
    public void setCertificateService(CertificateInternalService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setClientOperationExternalService(ClientOperationExternalService clientOperationExternalService) {
        this.clientOperationExternalService = clientOperationExternalService;
    }

    @Autowired
    public void setRegistrationIdentityVerifier(CmpRegistrationIdentityVerifier registrationIdentityVerifier) {
        this.registrationIdentityVerifier = registrationIdentityVerifier;
    }

    /**
     * Process request (issue certificate) to CA in asynchronous manner; only create request (without waiting for
     * response).
     *
     * @param request incoming {@link PKIMessage} as request
     * @param configuration server (profile) configuration
     * @return dto object keeps information about potentially issued certificate
     * @throws CmpBaseException if any error is raised
     */
    @Override
    public ClientCertificateDataResponseDto handle(PKIMessage request, ConfigurationContext configuration)
            throws CmpBaseException {
        ASN1OctetString tid = request.getHeader().getTransactionID();
        String msgBodyType = PkiMessageDumper.msgTypeAsString(request);
        String msgKey = PkiMessageDumper.msgTypeAsShortCut(false, request);
        if (!ALLOWED_TYPES.contains(request.getBody().getType())) {
            throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                    "message " + msgKey + " cannot be handled - wrong type, type=" + msgBodyType);
        }

        // -- process issue (asynchronous) operation
        CertReqMessages crmf = (CertReqMessages) request.getBody().getContent();
        if (configuration.isRegistrationMode()) {
            return completeRegistration(crmf, configuration, tid);
        }
        try {
            ClientCertificateIssueRequestDto dto = new ClientCertificateIssueRequestDto();
            dto.setRequest(Base64.getEncoder().encodeToString(crmf.getEncoded()));
            dto.setFormat(CertificateRequestFormat.CRMF);
            RaProfile raProfile = configuration.getRaProfile();
            // -- (1)certification request (ask for issue)
            return clientOperationService
                    .issueCertificate(SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()),
                            raProfile.getSecuredUuid(), dto,
                            CertificateProtocolInfo.Cmp(configuration.getCmpProfile().getUuid()));
        } catch (RequestAttributePolicyViolationException e) {
            throw new CmpCrmfValidationException(tid, request.getBody().getType(), PKIFailureInfo.badCertTemplate,
                    e.getMessage());
        } catch (CertificateRequestException | NotFoundException | CertificateException | IOException
                | NoSuchAlgorithmException | InvalidKeyException | CertificateOperationException e) {
            throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure, "cannot issue certificate", e);
        }
        // CrmfMessageHandler get certificate in sync manner (via polling ...)
    }

    /**
     * Completes the pre-registration the MAC resolved to (protection validation already verified the MAC and stashed
     * the match on the context): the CRMF identity must exactly equal the registration, and issuance runs through the
     * register→issue completion with the registration challenge as the authorization secret. Every rejection reuses the
     * single generic wire message.
     */
    private ClientCertificateDataResponseDto completeRegistration(CertReqMessages crmf,
            ConfigurationContext configuration, ASN1OctetString tid) throws CmpBaseException {
        Certificate matched = configuration.getMatchedRegistration();
        if (matched == null) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    CmpRegistrationResolver.REGISTRATION_REJECTION);
        }
        registrationIdentityVerifier.verify(crmf, matched, CertificateEvent.ISSUE, tid);

        try {
            ClientCertificateIssueRequestDto dto = new ClientCertificateIssueRequestDto();
            dto.setRequest(Base64.getEncoder().encodeToString(crmf.getEncoded()));
            dto.setFormat(CertificateRequestFormat.CRMF);
            dto.setAuthorizationSecret(configuration.getMatchedChallenge());
            RaProfile raProfile = configuration.getRaProfile();
            ClientCertificateDataResponseDto response = clientOperationExternalService
                    .issueExistingCertificate(SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()),
                            raProfile.getSecuredUuid(), matched.getUuid().toString(), dto);
            applyProtocolAssociationBestEffort(matched, configuration);
            return response;
        } catch (RequestAttributePolicyViolationException e) {
            // A policy violation concerns CRMF content, not registration identity, so it is not an enumeration
            // oracle and carries its platform-authored detail — matching the plain ir/cr path above.
            throw new CmpProcessingException(tid, PKIFailureInfo.badCertTemplate, e.getMessage());
        } catch (ValidationException | NotFoundException e) {
            // Challenge/gate denial, or the registration raced away (cert/RA profile gone mid-flight): both
            // mean "no active registration to complete" — surface the single generic rejection, detail logged.
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    CmpRegistrationResolver.REGISTRATION_REJECTION);
        } catch (IOException | CertificateException e) {
            throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                    "cannot complete certificate registration", e);
        }
    }

    /**
     * The completion is committed and its ISSUE action enqueued, so an association failure must not fail the enrolment
     * (the registration would no longer match a retry). Best-effort, logged.
     */
    private void applyProtocolAssociationBestEffort(Certificate matched, ConfigurationContext configuration) {
        try {
            certificateService
                    .applyProtocolAssociations(matched.getUuid(),
                            CertificateProtocolInfo.Cmp(configuration.getCmpProfile().getUuid()));
        } catch (Exception e) {
            logger
                    .warn("Failed to apply CMP protocol associations to completed registration {}: {}",
                            matched.getUuid(), e.getMessage());
        }
    }

    public CmpTransactionState getTransactionState() {
        return CmpTransactionState.CERT_ISSUED;
    }

}
