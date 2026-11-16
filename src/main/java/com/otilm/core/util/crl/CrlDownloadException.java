package com.otilm.core.util.crl;

import com.otilm.api.exception.PlatformException;
import java.io.IOException;

/** A CRL download that Core stopped itself, with the reason worded as why the CRL was not used. */
public class CrlDownloadException extends IOException implements PlatformException {

    private final String reason;

    public CrlDownloadException(String crlUrl, String reason) {
        super("The CRL from %s was not read: %s".formatted(crlUrl, reason));
        this.reason = reason;
    }

    /** Why the CRL was not used, worded to follow "it was ignored because". */
    public String reason() {
        return reason;
    }
}
