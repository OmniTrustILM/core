package com.otilm.core.service.cmp.message.validator;

import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import org.bouncycastle.asn1.cmp.PKIMessage;

/**
 * Bidirectional validator for {@link PKIMessage} object
 *
 * @param <E> result of incoming validation
 * @param <R> result of outgoing validation
 */
public interface BiValidator<E, R> {

    /**
     * validate incoming request message (from client - ILM is server)
     *
     * @param request message incoming from client
     * @return null if validation is ok
     * @throws CmpBaseException if validation has failed
     */
    R validateIn(PKIMessage request, ConfigurationContext configuration) throws CmpBaseException;

    /**
     * validate outgoing response message (from CR/RA - ILM is client)
     *
     * @param response message incoming from CA/RA
     * @return null if validation is ok
     * @throws CmpProcessingException if validation has failed
     */
    E validateOut(PKIMessage response, ConfigurationContext configuration) throws CmpBaseException;

}
