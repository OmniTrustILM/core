package com.czertainly.core.service.cmp.message.validator.impl;

import com.czertainly.api.interfaces.core.cmp.error.CmpBaseException;
import com.czertainly.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.validator.Validator;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.cmp.PollReqContent;

/**
 * Validator for the polling-related CMP messages (RFC 4210 §5.2.6 / §5.3.22):
 * <ul>
 *   <li><b>pollReq</b> — sent by a client to retry a previously-pending operation;
 *       the body must carry at least one {@code certReqId};</li>
 *   <li><b>pollRep</b> — sent by the server when an operation is still pending;
 *       the body must carry exactly one {@code certReqId} and a non-negative
 *       {@code checkAfter} value (free-text reason is optional).</li>
 * </ul>
 *
 * <pre>
 *   PollReqContent ::= SEQUENCE OF SEQUENCE {
 *       certReqId    INTEGER }
 *
 *   PollRepContent ::= SEQUENCE OF SEQUENCE {
 *       certReqId    INTEGER,
 *       checkAfter   INTEGER,         -- time in seconds
 *       reason       PKIFreeText OPTIONAL }
 * </pre>
 */
public class BodyPollValidator extends BaseValidator implements Validator<PKIMessage, Void> {

    /**
     * Validate an inbound {@code pollReq} message: assert the body type and that at
     * least one {@code certReqId} is present.
     */
    public Void validateIn(PKIMessage request, ConfigurationContext configuration) throws CmpBaseException {
        assertEqualBodyType(PKIBody.TYPE_POLL_REQ, request);
        PollReqContent content = (PollReqContent) request.getBody().getContent();
        if (content == null || content.getCertReqIdValues() == null || content.getCertReqIdValues().length == 0) {
            throw new CmpProcessingException(request.getHeader().getTransactionID(),
                    PKIFailureInfo.badDataFormat,
                    "pollReq body validator: at least one certReqId is required");
        }
        return null;
    }

    /**
     * Validate an outbound {@code pollRep} message: assert the body type and the
     * presence of exactly one {@code certReqId} with a non-negative {@code checkAfter}.
     */
    public Void validateOut(PKIMessage response, ConfigurationContext configuration) throws CmpBaseException {
        assertEqualBodyType(PKIBody.TYPE_POLL_REP, response);
        PollRepContent content = (PollRepContent) response.getBody().getContent();
        if (content == null || content.size() == 0) {
            throw new CmpProcessingException(response.getHeader().getTransactionID(),
                    PKIFailureInfo.badDataFormat,
                    "pollRep body validator: at least one (certReqId, checkAfter) pair is required");
        }
        for (int i = 0; i < content.size(); i++) {
            if (content.getCertReqId(i) == null) {
                throw new CmpProcessingException(response.getHeader().getTransactionID(),
                        PKIFailureInfo.badDataFormat,
                        "pollRep body validator: certReqId is required");
            }
            if (content.getCheckAfter(i) == null
                    || content.getCheckAfter(i).getValue().signum() < 0) {
                throw new CmpProcessingException(response.getHeader().getTransactionID(),
                        PKIFailureInfo.badDataFormat,
                        "pollRep body validator: checkAfter must be a non-negative integer");
            }
        }
        return null;
    }

    /**
     * Dispatcher used when the caller does not yet know the direction; not used by
     * {@link BodyValidator} (which dispatches via type), kept for completeness.
     */
    @Override
    public Void validate(PKIMessage message, ConfigurationContext configuration) throws CmpBaseException {
        if (message.getBody().getType() == PKIBody.TYPE_POLL_REQ) {
            return validateIn(message, configuration);
        }
        return validateOut(message, configuration);
    }
}
