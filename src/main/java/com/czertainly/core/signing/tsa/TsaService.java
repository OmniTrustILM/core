package com.czertainly.core.signing.tsa;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.interfaces.core.tsp.error.TspException;
import com.czertainly.core.signing.tsa.messages.TspRequest;
import com.czertainly.core.signing.tsa.messages.TspResponse;

public interface TsaService {

    TspResponse processTspRequestForTspProfile(String tspProfileName, TspRequest request) throws NotFoundException, TspException;

    TspResponse processTspRequestForSigningProfile(String signingProfileName, TspRequest request) throws NotFoundException, TspException;

}
