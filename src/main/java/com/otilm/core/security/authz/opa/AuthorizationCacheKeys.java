package com.otilm.core.security.authz.opa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/**
 * Derives the cache keys for OPA decisions.
 *
 * <p>
 * The principal is reduced to its {@code permissions} document and a flag for the anonymous pseudo-user. Those are the
 * only two things the method and objects policies read about a caller: every allow rule resolves through
 * {@code input.principal.permissions}, and the single rule that touches {@code input.principal.user} compares the
 * username against {@code anonymousUser}. Dropping the rest is what lets callers with the same effective permissions
 * share one entry. A policy that starts reading another user field, or the roles, invalidates that reduction and this
 * kernel has to change with it.
 *
 * <p>
 * The decision key is formed by joining four variable-length string components with length prefixes to prevent
 * collisions. If {@code spring.jackson.serialization.indent-output} is enabled, the {@code resourceJson} and
 * {@code detailsJson} will contain newlines. Naive newline-separated joining would allow component-boundary
 * repositioning to produce the same key from different tuples; instead, each component is prefixed with its
 * character-count to ensure the split is deterministic (see {@code PlatformAuthenticationCache.tokenCacheKey} for the
 * identical pattern).
 */
final class AuthorizationCacheKeys {

    private static final String ANONYMOUS_USERNAME = "anonymousUser";
    private static final String ANONYMOUS_FIELD = "anonymous";
    private static final String PERMISSIONS_FIELD = "permissions";

    private AuthorizationCacheKeys() {
    }

    static String principalDigest(ObjectMapper om, String principal) throws JsonProcessingException {
        JsonNode root = om.readTree(principal);
        ObjectNode digestInput = om.createObjectNode();
        digestInput.put(ANONYMOUS_FIELD, ANONYMOUS_USERNAME.equals(root.path("user").path("username").asText("")));
        JsonNode permissions = root.get(PERMISSIONS_FIELD);
        if (permissions != null) {
            digestInput.set(PERMISSIONS_FIELD, permissions);
        }
        return sha256Hex(om.writeValueAsString(digestInput));
    }

    static String decisionKey(String policyName, String principalDigest, String resourceJson, String detailsJson) {
        return sha256Hex(policyName.length() + ":" + policyName + ":" + principalDigest.length() + ":" + principalDigest
                + ":" + resourceJson.length() + ":" + resourceJson + ":" + detailsJson.length() + ":" + detailsJson);
    }

    private static String sha256Hex(String value) {
        try {
            return HexFormat
                    .of()
                    .formatHex(MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required by every Java platform implementation.", e);
        }
    }
}
