package com.otilm.core.service.est.authentication;

import com.otilm.api.model.core.est.EstAuthenticationPolicy;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.message.EstException;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;
import org.springframework.stereotype.Component;

/**
 * Hands a request to the authenticator of the policy that its EST Profile selects, and to no other. Two authenticators
 * that claim one policy would make the choice depend on bean order, and a policy without an authenticator would leave
 * the profiles that select it unable to authenticate a client, so the application does not start in either case.
 */
@Component
public class EstAuthenticators {

    private final Map<EstAuthenticationPolicy, EstAuthenticator> byPolicy = new EnumMap<>(
            EstAuthenticationPolicy.class);

    public EstAuthenticators(List<EstAuthenticator> authenticators) {
        for (EstAuthenticator authenticator : authenticators) {
            EstAuthenticator claimed = byPolicy.put(authenticator.policy(), authenticator);
            if (claimed != null) {
                throw new IllegalStateException("The EST authentication policy " + authenticator.policy().getCode()
                        + " is claimed by both " + claimed.getClass().getSimpleName() + " and "
                        + authenticator.getClass().getSimpleName());
            }
        }
        List<String> unserved = Arrays
                .stream(EstAuthenticationPolicy.values())
                .filter(policy -> !byPolicy.containsKey(policy))
                .map(EstAuthenticationPolicy::getCode)
                .toList();
        if (!unserved.isEmpty()) {
            throw new IllegalStateException(
                    "No EST authenticator serves the authentication policies: " + String.join(", ", unserved));
        }
    }

    /**
     * @param route the route of the request
     * @param credentials what the client presented
     * @param csr the certification request of the client, whose subject alternative names can be read and whose
     * signature is not verified yet
     * @return the client that the authenticator of the profile's policy accepted
     * @throws EstException what that authenticator refuses with
     */
    public EstClient authenticate(EstRoute route, @Sensitive EstClientCredentials credentials, CertificateRequest csr) {
        EstAuthenticationPolicy policy = route.estProfile().getAuthenticationPolicy();
        return byPolicy.get(policy).authenticate(route, credentials, csr);
    }
}
