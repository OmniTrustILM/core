package com.otilm.core.security.authn;

import com.otilm.api.exception.PlatformException;
import org.springframework.security.core.AuthenticationException;

public class PlatformAuthenticationException extends AuthenticationException implements PlatformException {

    public PlatformAuthenticationException(String msg) {
        super(msg);
    }

    public PlatformAuthenticationException(String msg, Throwable cause) {
        super(msg, cause);
    }
}
