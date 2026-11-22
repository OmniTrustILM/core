package com.otilm.core.util.crl;

import com.otilm.api.exception.PlatformException;
import java.security.cert.CRLException;

/** A readable CRL that Core does not read because it exceeds a limit, with the reason worded as why it was not used. */
public class CrlRefusedException extends CRLException implements PlatformException {

    private final String reason;

    public CrlRefusedException(String reason) {
        super("The CRL was not read: " + reason);
        this.reason = reason;
    }

    /** Why the CRL was not used, worded to follow "it was ignored because". */
    public String reason() {
        return reason;
    }
}
