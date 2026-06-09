package com.czertainly.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.validator.Validator;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * Validator for PKI Conformation message (pkiConf)
 * <pre>PKIConfirmContent ::= NULL</pre>
 *
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#section-5.3.17">PKI Confirmation Content</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc4210#appendix-F">Appendix F.  Compilable ASN.1 Definitions (rfc4210)</a>
 */
public class BodyPkiConfirmValidator extends BaseValidator implements Validator<PKIMessage, Void> {

    /**
     * @param response of pkiConf message
     * @return has null body (there is nothing to validate)
     */
    @Override
    public Void validate(PKIMessage response, ConfigurationContext configuration) throws CmpBaseException {
        assertEqualBodyType(PKIBody.TYPE_CONFIRM, response);
        return null;
    }
}
