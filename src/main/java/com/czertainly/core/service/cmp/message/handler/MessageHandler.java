package com.czertainly.core.service.cmp.message.handler;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.czertainly.core.service.cmp.configurations.ConfigurationContext;
import com.czertainly.core.service.cmp.impl.CmpServiceImpl;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * Basic interface for handling various type of {@link PKIMessage}.
 * See specific usage at {@link CmpServiceImpl}.
 */
public interface MessageHandler<R> {

    /**
     * Processing of <code>request</code> in order to get related <code>response</code>.
     *
     * @param request       incoming {@link PKIMessage} as request
     * @param configuration server (profile) configuration
     * @return processed response
     * @throws CmpProcessingException if any error occurs during handling
     *                                given message
     */
    R handle(PKIMessage request, ConfigurationContext configuration)
            throws CmpBaseException;

}
