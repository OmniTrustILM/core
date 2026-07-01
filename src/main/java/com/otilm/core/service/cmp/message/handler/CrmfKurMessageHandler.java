package com.otilm.core.service.cmp.message.handler;

import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.CertificateRequestException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cmp.CmpTransactionState;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import com.otilm.api.model.core.v2.ClientCertificateDataResponseDto;
import com.otilm.api.model.core.v2.ClientCertificateRekeyRequestDto;
import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.logging.LoggingHelper;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import com.otilm.core.service.cmp.message.PkiMessageDumper;
import com.otilm.core.service.v2.ClientOperationInternalService;
import com.otilm.core.util.CertificateUtil;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Optional;

/**
 * <p>Interface how to handle incoming request (kur) message from client.</p>
 *
 * <p>See Appendix C and [CRMF] for CertReqMessages syntax. </p>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.3.1">[2] - CertReqMessages syntax</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4211#section-3">[3] - CertRequest syntax</a>
 * @see <a href="https://doc.primekey.com/bouncycastle/how-to-guides-pki-at-the-edge/how-to-generate-key-pairs-and-certification-requests#HowtoGenerateKeyPairsandCertificationRequests-GenerateCRMFCertificationRequestusingCMP">How to generate CRMF request</a>
 */
@Component
@Transactional
public class CrmfKurMessageHandler implements MessageHandler<ClientCertificateDataResponseDto> {

    private CertificateRepository certificateRepository;

    @Autowired
    public void setCertificateRepository(CertificateRepository certificateRepository) {
        this.certificateRepository = certificateRepository;
    }

    private ClientOperationInternalService clientOperationService;

    @Autowired
    public void setClientOperationService(ClientOperationInternalService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    /**
     * Process request (modify/re-key certificate) to CA in asynchronous manner;
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
        if (PKIBody.TYPE_KEY_UPDATE_REQ != request.getBody().getType()) {
            throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                    "message " + msgKey + " cannot be handled - wrong type, type=" + msgBodyType);
        }
        CertReqMessages crmf = (CertReqMessages) request.getBody().getContent();
        CertRequest certRequest = crmf.toCertReqMsgArray()[0].getCertReq();

        // -- public key (from request)
        PublicKey reqPublicKey = getPublicKey(tid, certRequest);

        // -- public key (from database)
        Certificate dbCertificate = getCertificate(tid, certRequest);
        LoggingHelper.putLogResourceInfo(Resource.CERTIFICATE, false, dbCertificate.getUuid().toString(), dbCertificate.getSubjectDn());
        PublicKey dbPublicKey = convertCertificate(tid, dbCertificate).getPublicKey();

        if (dbPublicKey.toString().equals(reqPublicKey.toString())) {//re-key is only about public keys change
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    "re-key operation failed: both public key are the same; must be different");
        }

        // -- process re-key (asynchronous) operation
        String certificateUUID = dbCertificate.getUuid().toString();
        try {
            ClientCertificateRekeyRequestDto.ClientCertificateRekeyRequestDtoBuilder dtoBuilder =
                    ClientCertificateRekeyRequestDto.builder();
            dtoBuilder.request(Base64.getEncoder().encodeToString(crmf.getEncoded()));
            dtoBuilder.format(CertificateRequestFormat.CRMF);
            RaProfile raProfile = configuration.getRaProfile();
            // -- (1)certification request (ask for issue)
            return clientOperationService.rekeyCertificate(
                    SecuredParentUUID.fromUUID(raProfile.getAuthorityInstanceReferenceUuid()),
                    raProfile.getSecuredUuid(),
                    certificateUUID,
                    dtoBuilder.build());
        } catch (NotFoundException | CertificateException | IOException |
                 NoSuchAlgorithmException | InvalidKeyException | CertificateOperationException |
                 CertificateRequestException e) {
            throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                    "cannot re-key certificate", e);
        }
        // CrmfMessageHandler get certificate in sync manner (via polling ...)
    }

    private PublicKey getPublicKey(ASN1OctetString tid, CertRequest certRequest)
            throws CmpProcessingException {
        PublicKey publicKey;
        try {
            publicKey = new JcaPEMKeyConverter().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .getPublicKey(certRequest.getCertTemplate().getPublicKey());
        } catch (PEMException e) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    "re-key operation failed: public key from request cannot be parsed");
        }
        if (publicKey == null) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badMessageCheck,
                    "re-key operation failed: public key from request not found");
        }
        return publicKey;
    }

    private Certificate getCertificate(ASN1OctetString tid, CertRequest certRequest)
            throws CmpProcessingException {
        String serialNumber = getSerialNumber(tid, certRequest);
        Optional<Certificate> dbCertificate = certificateRepository.findBySerialNumberIgnoreCase(serialNumber);
        if (dbCertificate.isEmpty()) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badCertId,
                    "current certificate is not found in inventory");
        }
        return dbCertificate.get();
    }

    /**
     * Get current certificate from the ILM database and parse/convert into x509 format.
     *
     * @param tid         identifier of current flow (see {@link PKIHeader#getTransactionID()})
     * @param currentCert found certificate for update
     * @return converted entity certificate into x509 format
     * @throws CmpProcessingException if found/convert/parse failed
     */
    private X509Certificate convertCertificate(ASN1OctetString tid, Certificate currentCert)
            throws CmpProcessingException {
        try {
            return CertificateUtil.parseCertificate(currentCert.getCertificateContent().getContent());
        } catch (CertificateException e) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badDataFormat,
                    "current certificate (in database) cannot parsed");
        }
    }

    /**
     * <p>Get serial number from {@link CertRequest} in {@link Controls} field;
     * using {@link CMPObjectIdentifiers#regCtrl_oldCertID}.</p>
     *
     * @param tid         is identifier of running transactionId flow
     * @param certRequest CRMF request body
     * @return get serial number as hex-string
     * @throws CmpProcessingException if parsing serial number failed
     */
    private String getSerialNumber(ASN1OctetString tid, CertRequest certRequest)
            throws CmpProcessingException {
        CertId certId = null;
        AttributeTypeAndValue[] attributes = certRequest.getControls().toAttributeTypeAndValueArray();
        for (AttributeTypeAndValue atr : attributes) {
            if (CMPObjectIdentifiers.regCtrl_oldCertID.equals(atr.getType())) {
                certId = CertId.getInstance(atr.getValue());
                break;
            }
        }
        if (certId == null || certId.getSerialNumber() == null) {
            throw new CmpProcessingException(tid, PKIFailureInfo.badCertId,
                    "cannot find serial number of current certificate");
        }
        return certId.getSerialNumber().getValue().toString(16);
    }

    public CmpTransactionState getTransactionState() {
        return CmpTransactionState.CERT_REKEYED;
    }

}
