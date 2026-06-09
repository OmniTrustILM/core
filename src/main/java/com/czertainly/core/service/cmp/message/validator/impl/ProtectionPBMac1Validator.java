package com.czertainly.core.service.cmp.message.validator.impl;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.message.validator.Validator;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8018">PKCS #5: Password-Based Cryptography Specification Version 2.1</a>
 * @see <a href="https://www.rfc-editor.org/rfc/rfc8018#section-7.1">7.1.1.  PBMAC1 Generation Operation</a>
 */
public class ProtectionPBMac1Validator implements Validator<PKIMessage, Void> {

    @Override
    public Void validate(PKIMessage message, ConfigurationContext configuration) throws CmpBaseException {
        throw new UnsupportedOperationException("not implemented yet");
    }
}
