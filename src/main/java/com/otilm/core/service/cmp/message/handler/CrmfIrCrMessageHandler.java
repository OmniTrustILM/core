package com.otilm.core.service.cmp.message.handler;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpCrmfValidationException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.core.cmp.CmpTransactionState;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateSignRequestDto;
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.model.auth.CertificateProtocolInfo;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.PkiMessageDumper;
import com.otilm.core.service.v2.ClientOperationInternalService;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Base64;
import java.util.List;

/**
 * <p>Interface how to handle incoming request (ir/cr) message from client.</p>
 *
 * <p>See Appendix C and [CRMF] for CertReqMessages syntax. </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-4.2.1.1">[1] - Initial Request</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.3.1">[2] - CertReqMessages syntax</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4211#section-3">[3] - CertRequest syntax</a>
 * @see <a href="https://doc.primekey.com/bouncycastle/how-to-guides-pki-at-the-edge/how-to-generate-key-pairs-and-certification-requests#HowtoGenerateKeyPairsandCertificationRequests-GenerateCRMFCertificationRequestusingCMP">How to generate CRMF request</a>
 */
@Component
@Transactional
public class CrmfIrCrMessageHandler implements MessageHandler<ClientCertificateDataResponseDto> {

    private static final List<Integer> ALLOWED_TYPES = List.of(
            PKIBody.TYPE_INIT_REQ,          // ir       [0]  CertReqMessages,       --Initialization Req
            PKIBody.TYPE_CERT_REQ);         // cr       [2]  CertReqMessages,       --Certification Req

    private ClientOperationInternalService clientOperationService;

    @Autowired
    public void setClientOperationService(ClientOperationInternalService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    /**
     * Process request (issue certificate) to CA in asynchronous manner;
     * only create request (without waiting for response).
     *
     * @param request       incoming {@link PKIMessage} as request
     * @param configuration server (profile) configuration
     * @return dto object keeps information about potentially issued certificate
     * @throws CmpBaseException if any error is raised
     */
    @Override
    public ClientCertificateDataResponseDto handle(PKIMessage request, ConfigurationContext configuration) throws CmpBaseException {
        ASN1OctetString tid = request.getHeader().getTransactionID();
        String msgBodyType = PkiMessageDumper.msgTypeAsString(request);
        String msgKey = PkiMessageDumper.msgTypeAsShortCut(false, request);
        if (!ALLOWED_TYPES.contains(request.getBody().getType())) {
            throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                    "message " + msgKey + " cannot be handled - wrong type, type=" + msgBodyType);
        }

        // -- process issue (asynchronous) operation
        CertReqMessages crmf = (CertReqMessages) request.getBody().getContent();
        try {
            ClientCertificateSignRequestDto dto = new ClientCertificateSignRequestDto();
            dto.setRequest(Base64.getEncoder().encodeToString(crmf.getEncoded()));
            dto.setFormat(CertificateRequestFormat.CRMF);
            RaProfile raProfile = configuration.getRaProfile();
            // -- (1)certification request (ask for issue)
            return clientOperationService.issueCertificate(
                    SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()),
                    raProfile.getSecuredUuid(),
                    dto, CertificateProtocolInfo.Cmp(raProfile.getUuid()));
        } catch (RequestAttributePolicyViolationException e) {
            throw new CmpCrmfValidationException(tid, request.getBody().getType(), PKIFailureInfo.badCertTemplate, e.getMessage());
        } catch (CertificateRequestException | NotFoundException | CertificateException | IOException |
                 NoSuchAlgorithmException | InvalidKeyException | CertificateOperationException e) {
            throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                    "cannot issue certificate", e);
        }
        // CrmfMessageHandler get certificate in sync manner (via polling ...)
    }

    public CmpTransactionState getTransactionState() {
        return CmpTransactionState.CERT_ISSUED;
    }

}
