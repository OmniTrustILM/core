package com.otilm.core.signing.tsa;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.interfaces.core.tsp.error.TspException;
import com.otilm.core.signing.tsa.messages.TspRequest;
import com.otilm.core.signing.tsa.messages.TspResponse;

public interface TsaExternalService {

    TspResponse processTspRequestForTspProfile(String tspProfileName, TspRequest request) throws NotFoundException, TspException;

    TspResponse processTspRequestForSigningProfile(String signingProfileName, TspRequest request) throws NotFoundException, TspException;

}
