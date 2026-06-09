package com.czertainly.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.validator.Validator;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.*;

/**
 * {@link PKIMessage} validator for type Certificate Confirmation
 * Content (certConf, {@link PKIBody#TYPE_CERT_CONFIRM}).
 */
public class BodyCertConfValidator extends BaseValidator implements Validator<PKIMessage, Void> {

    /**
     * <p>Certificate Confirmation Content</p>
     * <pre>
     *          CertConfirmContent ::= SEQUENCE OF CertStatus
     *
     *          CertStatus ::= SEQUENCE {
     *             certHash    OCTET STRING,
     *             certReqId   INTEGER,
     *             statusInfo  PKIStatusInfo OPTIONAL
     *          }
     * </pre>
     *
     * @param request of certConf message, {@link CertConfirmContent}
     * @throws CmpProcessingException if validation has failed
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.3.18">Certificate Confirmation Content</a>
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#appendix-F">Appendix F.  Compilable ASN.1 Definitions (rfc4210)</a>
     */
    @Override
    public Void validate(PKIMessage request, ConfigurationContext configuration) throws CmpBaseException {
        assertEqualBodyType(PKIBody.TYPE_CERT_CONFIRM, request);
        ASN1OctetString tid = request.getHeader().getTransactionID();
        CertConfirmContent content = (CertConfirmContent) request.getBody().getContent();
        CertStatus[] certStatuses = content.toCertStatusArray();
        checkOneElementInArray(tid, certStatuses, "certStatus");
        CertStatus certStatus = certStatuses[0];
        checkValueNotNull(tid, certStatus.getCertHash(), PKIFailureInfo.badDataFormat, "CertHash");
        return null;
    }

}
