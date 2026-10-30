package com.otilm.core.security.authz;

import com.otilm.core.security.authn.PlatformAuthenticationToken;
import java.util.function.Supplier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public abstract class AbstractExternalAuthorizationManager<T> implements AuthorizationManager<T> {

    protected final Log logger = LogFactory.getLog(this.getClass());

    /**
     * Decides whether the authenticated caller may act on {@code object}.
     *
     * <p>
     * <b>Never abstains.</b> The interface permits {@code null} to mean "no decision", but an unrecognised token type
     * and a subclass that cannot decide both come back as an explicit denial instead.
     */
    @Override
    public AuthorizationDecision authorize(Supplier<? extends Authentication> authenticationSupplier, T object) {
        Authentication authentication = authenticationSupplier.get();
        if (!(authentication instanceof PlatformAuthenticationToken
                || authentication instanceof AnonymousAuthenticationToken)) {
            logger
                    .trace("Authentication is not of type 'PlatformAuthenticationToken' or 'AnonymousAuthenticationToken'. Cannot authorize.");
            return new AuthorizationDecision(false);
        }

        if (!canDecide(authentication, object)) {
            logger.trace("Denying as this manager can't decide for the given object.");
            return new AuthorizationDecision(false);
        }

        if (authentication instanceof PlatformAuthenticationToken token) {
            return checkInternal(token, object);
        } else {
            return checkInternal((AnonymousAuthenticationToken) authentication, object);
        }

    }

    protected abstract AuthorizationDecision checkInternal(PlatformAuthenticationToken authentication, T object);

    protected abstract AuthorizationDecision checkInternal(AnonymousAuthenticationToken authenticationToken, T object);

    protected abstract boolean canDecide(Authentication auth, T object);
}
