package com.czertainly.core.security.authn;

import com.czertainly.api.exception.PlatformException;
import org.springframework.security.core.AuthenticationException;

public class CzertainlyAuthenticationException extends AuthenticationException implements PlatformException {

    public CzertainlyAuthenticationException(String msg) {
        super(msg);
    }

    public CzertainlyAuthenticationException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
