package com.otilm.core.security.authz.opa;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.security.authz.opa.dto.OpaInput;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestWrapper;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaResultWrapper;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;

@Component
public class OpaClient {

    protected final Log logger = LogFactory.getLog(this.getClass());

    private WebClient client;

    ObjectMapper om;

    private final String opaBaseUrl;

    private final AuthorizationCache authorizationCache;

    public OpaClient(@Autowired ObjectMapper om, @Value("${opa.base-url}") String opaBaseUrl,
            @Autowired AuthorizationCache authorizationCache) {
        this.om = om;
        this.opaBaseUrl = opaBaseUrl;
        this.authorizationCache = authorizationCache;
    }

    public OpaResourceAccessResult checkResourceAccess(String policyName, OpaRequestedResource resource,
            String principal, OpaRequestDetails details) throws AccessDeniedException {
        return authorizationCache
                .getOrCheckResourceAccess(policyName, resource, principal, details, () -> sendRequest(policyName,
                        resource, principal, details, OpaReturnType.fromInner(OpaResourceAccessResult.class)));
    }

    public OpaObjectAccessResult checkObjectAccess(String policyName, OpaRequestedResource resource, String principal,
            OpaRequestDetails details) throws AccessDeniedException {
        return authorizationCache
                .getOrCheckObjectAccess(policyName, resource, principal, details, () -> sendRequest(policyName,
                        resource, principal, details, OpaReturnType.fromInner(OpaObjectAccessResult.class)));
    }

    private <T> T sendRequest(String policyName, OpaRequestedResource resource, String principal,
            OpaRequestDetails details, ParameterizedType type) throws AccessDeniedException {
        logger
                .trace(

                        "Going to call OPA policy '%s' with %s and %s."
                                .formatted(policyName, resource.toString(),
                                        details != null ? details.toString() : "no additional details"));

        try {
            ParameterizedTypeReference<OpaResultWrapper<T>> typeReference = ParameterizedTypeReference.forType(type);
            String body = om.writeValueAsString(new OpaRequestWrapper<>(new OpaInput(resource, principal, details)));

            OpaResultWrapper<T> wrapper = getClient()
                    .post()
                    .uri("/v1/data/" + policyName)
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .bodyValue(body)
                    .retrieve()
                    .bodyToMono(typeReference)
                    .block();

            if (wrapper == null) {
                throw new RuntimeException("Empty response received from OPA.");
            }
            return wrapper.getResult();
        } catch (Exception e) {
            throw new AccessDeniedException("An error occurred when calling OPA.", e);
        }
    }

    public WebClient getClient() {
        if (client == null) {
            client = WebClient.builder().baseUrl(opaBaseUrl).build();
        }
        return client;
    }

    private static class OpaReturnType implements ParameterizedType {

        private final Type[] innerType;

        public static OpaReturnType fromInner(Type innerType) {
            return new OpaReturnType(innerType);
        }

        private OpaReturnType(Type innerType) {
            this.innerType = new Type[]{innerType};
        }

        @Override
        public Type[] getActualTypeArguments() {
            return innerType;
        }

        @Override
        public Type getRawType() {
            return OpaResultWrapper.class;
        }

        @Override
        public Type getOwnerType() {
            return null;
        }
    }
}
