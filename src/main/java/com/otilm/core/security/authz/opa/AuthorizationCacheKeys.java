package com.otilm.core.security.authz.opa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.otilm.core.cbom.asset.identity.IdentityDigests;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

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
 * The requested resource is reduced to a canonical form whose field and element order does not depend on the order the
 * caller happened to assemble it in. Both policies consume {@code uuids} and {@code parentUUIDs} with set semantics, so
 * two requests differing only in the order of those lists are one decision and belong on one entry. The canonical form
 * preserves absent-versus-present and preserves emptiness, because {@code not input.requestedResource.uuids}
 * distinguishes an absent list from an empty one. It feeds the key only; the request sent to OPA is unchanged.
 *
 * <p>
 * The decision key is formed by joining four variable-length string components with length prefixes to prevent
 * collisions. If {@code spring.jackson.serialization.indent-output} is enabled, the {@code resourceJson} and
 * {@code detailsJson} will contain newlines. Naive newline-separated joining would allow component-boundary
 * repositioning to produce the same key from different tuples; instead, each component is prefixed with its
 * character-count to ensure the split is deterministic (see {@code PlatformAuthenticationCache.tokenCacheKey} for the
 * same length-prefix pattern applied to a single variable-length field rather than to every component).
 */
final class AuthorizationCacheKeys {

    private static final String ANONYMOUS_USERNAME = "anonymousUser";
    private static final String ANONYMOUS_FIELD = "anonymous";
    private static final String PERMISSIONS_FIELD = "permissions";

    private AuthorizationCacheKeys() {
    }

    /**
     * Rejects a principal carrying anything after its top-level value. Jackson stops at the end of the first value, so
     * {@code {"permissions":{}} {"permissions":{"allowAllResources":true}}} would otherwise reduce to the digest of its
     * first half and share an entry with a caller holding only that half's permissions.
     */
    static String principalDigest(ObjectMapper om, String principal) throws JsonProcessingException {
        JsonNode root = om
                .readerFor(JsonNode.class)
                .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                .readValue(principal);
        ObjectNode digestInput = om.createObjectNode();
        digestInput.put(ANONYMOUS_FIELD, ANONYMOUS_USERNAME.equals(root.path("user").path("username").asText("")));
        JsonNode permissions = root.get(PERMISSIONS_FIELD);
        if (permissions != null) {
            digestInput.set(PERMISSIONS_FIELD, permissions);
        }
        return sha256Hex(om.writeValueAsString(digestInput));
    }

    /**
     * The requested resource rendered with its property entries and its UUID lists in sorted order, so that two
     * assemblies of the same request produce one key.
     */
    static String canonicalResourceJson(ObjectMapper om, OpaRequestedResource resource) throws JsonProcessingException {
        ObjectNode canonical = om.createObjectNode();
        Map<String, String> properties = resource.getProperties();
        if (properties != null) {
            new TreeMap<>(properties).forEach(canonical::put);
        }
        putSorted(canonical, "uuids", resource.getObjectUUIDs());
        putSorted(canonical, "parentUUIDs", resource.getParentObjectUUIDs());
        List<String> url = resource.getUrl();
        if (url != null) {
            ArrayNode urls = canonical.putArray("url");
            url.forEach(urls::add);
        }
        return om.writeValueAsString(canonical);
    }

    static String decisionKey(String policyName, String principalDigest, String resourceJson, String detailsJson) {
        return sha256Hex(policyName.length() + ":" + policyName + ":" + principalDigest.length() + ":" + principalDigest
                + ":" + resourceJson.length() + ":" + resourceJson + ":" + detailsJson.length() + ":" + detailsJson);
    }

    private static void putSorted(ObjectNode target, String field, List<String> values) {
        if (values == null) {
            return;
        }
        ArrayNode array = target.putArray(field);
        values.stream().sorted().forEach(array::add);
    }

    /**
     * Rejects an unpaired surrogate rather than hashing the {@code ?} that {@code String.getBytes(UTF_8)} substitutes
     * for one, which would merge distinct pre-images onto a single key.
     */
    private static String sha256Hex(String value) {
        return IdentityDigests.sha256Hex(value);
    }
}
