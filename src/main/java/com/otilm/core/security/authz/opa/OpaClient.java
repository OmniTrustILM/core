package com.otilm.core.security.authz.opa;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.clients.ApiClientCodecs;
import com.otilm.core.security.ai.AiReadInvocationContext;
import com.otilm.core.security.authz.opa.dto.OpaInput;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaRequestDetails;
import com.otilm.core.security.authz.opa.dto.OpaRequestWrapper;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.security.authz.opa.dto.OpaResourceAccessResult;
import com.otilm.core.security.authz.opa.dto.OpaResultWrapper;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.time.Duration;
import java.util.UUID;
import java.util.function.Supplier;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@Component
public class OpaClient {
    private static final String GROUP_ACCESS = "actionAllowedForGroupOfObjects";
    private static final String ALLOWED_OBJECTS = "allowedObjects";

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
        if (AiReadInvocationContext.isActive()) {
            JsonNode result = sendScopedRequest(policyName, resource, details);
            validateMethodResult(result);
            try {
                return om
                        .readerFor(OpaResourceAccessResult.class)
                        .without(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                        .readValue(result);
            } catch (Exception failure) {
                throw scopedFailure();
            }
        }
        return authorizationCache
                .getOrCheckResourceAccess(policyName, resource, principal, details, () -> sendRequest(policyName,
                        resource, principal, details, OpaReturnType.fromInner(OpaResourceAccessResult.class)));
    }

    public OpaObjectAccessResult checkObjectAccess(String policyName, OpaRequestedResource resource, String principal,
            OpaRequestDetails details) throws AccessDeniedException {
        if (AiReadInvocationContext.isActive()) {
            JsonNode result = sendScopedRequest(policyName, resource, details);
            validateObjectResult(result);
            try {
                return om
                        .readerFor(OpaObjectAccessResult.class)
                        .without(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES)
                        .readValue(result);
            } catch (Exception failure) {
                throw scopedFailure();
            }
        }
        return authorizationCache
                .getOrCheckObjectAccess(policyName, resource, principal, details, () -> sendRequest(policyName,
                        resource, principal, details, OpaReturnType.fromInner(OpaObjectAccessResult.class)));
    }

    /** Fresh method and exact-object votes share one elapsed budget and never consult authorization caches. */
    public void requireObjectAccessUncached(OpaRequestedResource resource, String principal, UUID object,
            Duration timeout) {
        try {
            if (resource == null || principal == null || principal.isBlank() || object == null) {
                throw scopedFailure();
            }
            var budget = AiRuntimeOperationBudget.start(timeout);
            JsonNode method = sendFreshRequest("method", resource, principal, null, budget::remaining);
            validateMethodResult(method);
            JsonNode objects = sendFreshRequest("objects", resource, principal, null, budget::remaining);
            validateObjectResult(objects);
            if (containsUuid(objects.path("forbiddenObjects"), object) || (!objects.path(GROUP_ACCESS).booleanValue()
                    && !containsUuid(objects.path(ALLOWED_OBJECTS), object))) {
                throw scopedFailure();
            }
            budget.remaining();
        } catch (Exception failure) {
            throw scopedFailure();
        }
    }

    private static boolean containsUuid(JsonNode values, UUID object) {
        for (JsonNode value : values) {
            if (object.toString().equalsIgnoreCase(value.textValue())) {
                return true;
            }
        }
        return false;
    }

    private JsonNode sendScopedRequest(String policyName, OpaRequestedResource resource, OpaRequestDetails details) {
        var context = AiReadInvocationContext.current().orElseThrow(OpaClient::scopedFailure);
        return sendFreshRequest(policyName, resource, context.refreshPrincipal(), details,
                context::remainingAuthorityTimeout);
    }

    private JsonNode sendFreshRequest(String policyName, OpaRequestedResource resource, String principal,
            OpaRequestDetails details, Supplier<Duration> remaining) {
        try {
            remaining.get();
            String body = om.writeValueAsString(new OpaRequestWrapper<>(new OpaInput(resource, principal, details)));
            String response = getClient()
                    .post()
                    .uri("/v1/data/" + policyName)
                    .contentType(MediaType.APPLICATION_JSON)
                    .accept(MediaType.APPLICATION_JSON)
                    .bodyValue(body)
                    .exchangeToMono(reply -> reply.statusCode().is2xxSuccessful()
                            ? reply.bodyToMono(String.class)
                            : reply.releaseBody().then(Mono.error(scopedFailure())))
                    .block(remaining.get());
            remaining.get();
            JsonNode wrapper = response == null ? null : om.readTree(response);
            if (wrapper == null || !wrapper.isObject() || !wrapper.path("result").isObject()) {
                throw scopedFailure();
            }
            return wrapper.get("result");
        } catch (Exception failure) {
            throw scopedFailure();
        }
    }

    private static void validateMethodResult(JsonNode result) {
        if (!result.path("authorized").isBoolean()) {
            throw scopedFailure();
        }
        validateList(result.path("allow"), false);
        validateList(result.path("deny"), false);
        if (!result.path("authorized").booleanValue() || result.path("allow").isEmpty()
                || !result.path("deny").isEmpty()) {
            throw scopedFailure();
        }
    }

    private static void validateObjectResult(JsonNode result) {
        if (!result.path(GROUP_ACCESS).isBoolean()) {
            throw scopedFailure();
        }
        validateList(result.path(ALLOWED_OBJECTS), true);
        validateList(result.path("forbiddenObjects"), true);
        if (!result.path(GROUP_ACCESS).booleanValue() && result.path(ALLOWED_OBJECTS).isEmpty()) {
            throw scopedFailure();
        }
    }

    private static void validateList(JsonNode values, boolean uuids) {
        if (!values.isArray()) {
            throw scopedFailure();
        }
        for (JsonNode value : values) {
            if (!value.isTextual() || value.textValue().isBlank()) {
                throw scopedFailure();
            }
            if (uuids) {
                try {
                    if (!UUID.fromString(value.textValue()).toString().equalsIgnoreCase(value.textValue())) {
                        throw scopedFailure();
                    }
                } catch (IllegalArgumentException failure) {
                    throw scopedFailure();
                }
            }
        }
    }

    private static AccessDeniedException scopedFailure() {
        return new AccessDeniedException("Certificate read authorization unavailable");
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
            client = WebClient.builder().baseUrl(opaBaseUrl).codecs(ApiClientCodecs::configureJsonCodecs).build();
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
