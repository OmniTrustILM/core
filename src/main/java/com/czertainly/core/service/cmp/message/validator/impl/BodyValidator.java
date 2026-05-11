package com.czertainly.core.service.cmp.message.validator.impl;

import com.czertainly.api.interfaces.core.cmp.error.CmpBaseException;
import com.czertainly.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.PkiMessageDumper;
import com.czertainly.core.service.cmp.message.validator.Validator;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.*;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Validator dispatches concrete instance of validator, dispatch per
 * field {@link PKIBody#getType()}.
 */
@Component
@Transactional
public class BodyValidator extends BaseValidator implements Validator<PKIMessage, Void> {

    @Override
    public Void validate(PKIMessage message, ConfigurationContext configuration) throws CmpBaseException {
        ASN1OctetString tid = message.getHeader().getTransactionID();
        try {
            switch (message.getBody().getType()) {
                case PKIBody.TYPE_INIT_REQ:
                case PKIBody.TYPE_CERT_REQ:
                case PKIBody.TYPE_KEY_UPDATE_REQ:
                    new BodyCertReqResValidator().validateIn(message, configuration);
                    break;
                case PKIBody.TYPE_CERT_REP:
                case PKIBody.TYPE_INIT_REP:
                case PKIBody.TYPE_KEY_UPDATE_REP:
                    new BodyCertReqResValidator().validateOut(message, configuration);
                    break;
                case PKIBody.TYPE_REVOCATION_REQ:
                    new BodyRevocationValidator().validateIn(message, configuration);
                    break;
                case PKIBody.TYPE_REVOCATION_REP:
                    new BodyRevocationValidator().validateOut(message, configuration);
                    break;
                case PKIBody.TYPE_CERT_CONFIRM:
                    new BodyCertConfValidator().validate(message, configuration);
                    break;
                case PKIBody.TYPE_CONFIRM:
                    new BodyPkiConfirmValidator().validate(message, configuration);
                    break;
                case PKIBody.TYPE_ERROR:
                    new BodyErrorMessageValidator().validate(message, configuration);
                    break;
                case PKIBody.TYPE_POLL_REQ:
                    new BodyPollValidator().validateIn(message, configuration);
                    break;
                case PKIBody.TYPE_POLL_REP:
                    new BodyPollValidator().validateOut(message, configuration);
                    break;
                case PKIBody.TYPE_P10_CERT_REQ:
                case PKIBody.TYPE_GEN_MSG:
                case PKIBody.TYPE_GEN_REP:
                case PKIBody.TYPE_NESTED:
                    throw new CmpProcessingException(tid, PKIFailureInfo.badDataFormat,
                            "body validator: " + PkiMessageDumper.msgTypeAsString(message.getBody()) + " is not implemented");
                default:
                    throw new CmpProcessingException(tid, PKIFailureInfo.badDataFormat,
                            "body validator: " + PkiMessageDumper.msgTypeAsString(message.getBody()) + " is not supported");
            }
        } catch (CmpProcessingException ex) {
            throw remapException(tid, message.getBody().getType(), ex);
        } catch (Throwable thr) {
            throw new CmpProcessingException(tid, PKIFailureInfo.systemFailure,
                    "body validator: internal error - " + thr.getLocalizedMessage());
        }
        return null;
    }
}
