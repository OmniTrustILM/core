package com.otilm.core.service.est;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.core.dao.entity.RaProfile;

import java.io.IOException;

/**
 * Produces the EST /csrattrs response body (RFC 7030 §4.5) for an RA Profile: a DER-encoded CsrAttrs projected from the resolved
 * request-attribute set.
 */
public interface EstCsrAttrsService {
    byte[] buildCsrAttrs(RaProfile raProfile) throws ConnectorException, NotFoundException, IOException;
}
