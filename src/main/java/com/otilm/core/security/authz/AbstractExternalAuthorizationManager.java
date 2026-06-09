package com.otilm.core.security.authz;

import com.otilm.core.security.authn.CzertainlyAuthenticationToken;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.function.Supplier;

@Component
public abstract class AbstractExternalAuthorizationManager<T> implements AuthorizationManager<T> {

    protected final Log logger = LogFactory.getLog(this.getClass());


    @Override
    public AuthorizationDecision check(Supplier<Authentication> authenticationSupplier, T object) {
        Authentication authentication = authenticationSupplier.get();
        if (!(authentication instanceof CzertainlyAuthenticationToken || authentication instanceof AnonymousAuthenticationToken)) {
            logger.trace("Authentication is not of type 'CzertainlyAuthenticationToken' or 'AnonymousAuthenticationToken'. Cannot authorize.");
            return new AuthorizationDecision(false);
        }

        if (!canDecide(authentication, object)) {
            logger.trace("Abstaining from voting as voter can't decide for given object.");
            return new AuthorizationDecision(false);
        }

        if (authentication instanceof CzertainlyAuthenticationToken token) {
            return checkInternal(token, object);
        } else {
            return checkInternal((AnonymousAuthenticationToken) authentication, object);
        }

    }

    protected abstract AuthorizationDecision checkInternal(CzertainlyAuthenticationToken authentication, T object);

    protected abstract AuthorizationDecision checkInternal(AnonymousAuthenticationToken authenticationToken, T object);

    protected abstract boolean canDecide(Authentication auth, T object);
}
