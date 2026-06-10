package com.czertainly.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.validator.Validator;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;

/**
 * Validator of {@link PKIMessage} which contains {@link ErrorMsgContent} which is subject
 * for validation.
 */
public class BodyErrorMessageValidator extends BaseValidator implements Validator<PKIMessage, Void> {

    /**
     * <p>This data structure MAY be used by EE, CA, or RA to convey error
     * info.</p>
     *
     * <pre>
     *     ErrorMsgContent ::= SEQUENCE {
     *         pKIStatusInfo          PKIStatusInfo,
     *         errorCode              INTEGER           OPTIONAL,
     *         errorDetails           PKIFreeText       OPTIONAL
     *     }
     *    </pre>
     *
     * <p>This message MAY be generated at any time during a PKI transaction.
     * If the client sends this request, the server MUST respond with a
     * PKIConfirm response, or another ErrorMsg if any part of the header is
     * not valid.  Both sides MUST treat this message as the end of the
     * transaction (if a transaction is in progress).</p>
     *
     * <p>If protection is desired on the message, the client MUST protect it
     * using the same technique (i.e., signature or MAC) as the starting
     * message of the transaction.  The CA MUST always sign it with a
     * signature key.</p>
     *
     * @param response which contains {@link ErrorMsgContent}
     * @return null if validation is ok
     * @throws CmpProcessingException if validation has failed
     * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.3.21">Error Message Content</a>
     */
    @Override
    public Void validate(PKIMessage response, ConfigurationContext configuration) throws CmpBaseException {
        ErrorMsgContent content = (ErrorMsgContent) response.getBody().getContent();
        PKIStatusInfo pkiStatusInfo = content.getPKIStatusInfo();
        checkValueNotNull(
                response.getHeader().getTransactionID(),
                pkiStatusInfo, PKIFailureInfo.badDataFormat,
                "PKIStatusInfo");
        return null;//validation is ok
    }
}
