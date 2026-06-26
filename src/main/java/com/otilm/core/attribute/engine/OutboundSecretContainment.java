package com.otilm.core.attribute.engine;

import com.otilm.api.model.client.attribute.ResponseAttribute;
import com.otilm.api.model.client.connector.v2.attribute.AttributeCallbackResponseDto;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.data.CredentialAttributeContentData;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.content.CredentialAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v3.content.ResourceObjectContent;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceObjectContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSecretContentData;
import com.otilm.api.model.common.attribute.v3.content.data.ResourceSimpleContentData;
import com.otilm.api.model.connector.secrets.content.SecretContent;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.Iterator;
import java.util.Set;

/**
 * Bounded outbound containment for callback responses (#1624 AC4 / D19, widened).
 * <p>
 * Two complementary checks ensure stored secret material the expander materialized server-side never echoes back
 * to the FE through a connector's callback response:
 * <ol>
 *   <li><b>Value-echo:</b> reject if any leaf in the response equals a secret value this call expanded
 *       ({@code expandedSecrets}).</li>
 *   <li><b>Structural:</b> reject if the response carries a populated {@link ResourceSecretContentData#getContent()}
 *       or a {@link CredentialAttributeContentV2} — secret-bearing shapes that must never appear in an FE-bound
 *       response regardless of value. This closes the v3-inline-secret blind spot the (false) "v3 has no SECRET
 *       content class" premise hid; {@code ResourceSecretContentData} demonstrably exists and carries inline
 *       {@link SecretContent}.</li>
 * </ol>
 * Refuse (do not strip) is the fail-closed default: a connector that returns expanded secret content is violating
 * the contract, and silently stripping would mask the violation.
 */
@Component
public class OutboundSecretContainment {

    private static final Logger logger = LoggerFactory.getLogger(OutboundSecretContainment.class);

    private final ObjectMapper objectMapper = new ObjectMapper();

    private static final int MAX_WALK_DEPTH = 12;

    /**
     * Record the secret leaf values materialized by expanding {@code blob}, so a later echo of them in the
     * connector's response can be detected. Records ONLY genuinely secret-typed leaves — a
     * {@link ResourceSecretContentData}'s inline {@link SecretContent} and a {@link SecretAttributeContentData}'s
     * {@code secret} — never benign metadata, so the value-echo check cannot false-positive on a public value.
     * <p>
     * A credential/authority blob is a {@link ResourceSimpleContentData}, not a {@link ResourceSecretContentData}:
     * its secret material surfaces as a {@link SecretAttributeContentV2} nested in its attributes. Walking the
     * blob with the same traversal the structural check uses records those too (O1).
     */
    void recordExpandedSecrets(ResourceObjectContentData blob, Set<String> expandedSecrets) {
        if (expandedSecrets == null) {
            return;
        }
        walkSecretGraph(blob, 0, node -> recordIfSecretLeaf(node, expandedSecrets));
    }

    private void recordIfSecretLeaf(Object node, Set<String> sink) {
        if (node instanceof ResourceSecretContentData secret && secret.getContent() != null) {
            JsonNode tree = objectMapper.valueToTree(secret.getContent());
            // Drop the @JsonTypeInfo discriminator ("type": apiKey/basicAuth/...): it is a low-entropy type tag,
            // not secret material, and recording it would false-positive the value-echo check on benign responses.
            if (tree instanceof ObjectNode obj) {
                obj.remove("type");
            }
            collectScalarStrings(tree, sink);
        } else if (node instanceof SecretAttributeContentData data) {
            addIfPresent(data.getSecret(), sink);
        }
    }

    private static void addIfPresent(String value, Set<String> sink) {
        if (value != null && !value.isBlank()) {
            sink.add(value);
        }
    }

    /**
     * Assert that an FE-bound callback response neither echoes a secret expanded on this call nor structurally
     * carries a secret-bearing content shape. Throws {@link OutboundSecretLeakException} (fail-closed) on a match.
     *
     * @param response        the connector's callback response payload (any content/attributes structure)
     * @param expandedSecrets the secret values this call materialized server-side
     */
    public void assertNoExpandedSecretOutbound(Object response, Set<String> expandedSecrets) {
        if (response == null) {
            return;
        }
        // Structural: walk the response object graph (incl. typed DTO wrappers, not just collections) and reject
        // any secret-bearing shape — same traversal as recordExpandedSecrets, so a wrapped secret cannot slip.
        walkSecretGraph(response, 0, this::rejectIfSecretShape);

        if (expandedSecrets == null || expandedSecrets.isEmpty()) {
            return;
        }
        JsonNode tree = objectMapper.valueToTree(response);
        if (containsAnyScalar(tree, expandedSecrets)) {
            logger.warn("Callback response echoes a server-expanded secret value; refusing to forward to FE");
            throw new OutboundSecretLeakException(
                    "Callback response echoes a secret value expanded by Core this call");
        }
    }

    /** Structural reject: a secret-bearing content shape that must never appear in an FE-bound response. */
    private void rejectIfSecretShape(Object node) {
        if (node instanceof ResourceSecretContentData secret) {
            if (secret.getContent() != null) {
                logger.warn("Callback response carries populated ResourceSecretContentData; refusing");
                throw new OutboundSecretLeakException(
                        "Callback response carries populated ResourceSecretContentData.content");
            }
            return;
        }
        if (node instanceof CredentialAttributeContentV2) {
            logger.warn("Callback response carries CredentialAttributeContentV2; refusing");
            throw new OutboundSecretLeakException(
                    "Callback response carries an expanded CredentialAttributeContentV2 shape");
        }
        if (node instanceof SecretAttributeContentV2) {
            logger.warn("Callback response carries SecretAttributeContentV2; refusing");
            throw new OutboundSecretLeakException(
                    "Callback response carries an expanded SecretAttributeContentV2 shape");
        }
        if (node instanceof SecretAttributeContentData data && data.getSecret() != null) {
            logger.warn("Callback response carries populated SecretAttributeContentData; refusing");
            throw new OutboundSecretLeakException(
                    "Callback response carries an expanded SecretAttributeContentData shape");
        }
    }

    /**
     * Walk the secret-relevant object graph of a content payload, invoking {@code visitor} on every node, and
     * descend the wrappers that can nest secret content: collections AND the typed DTO wrappers
     * (AttributeCallbackResponseDto / ResponseAttribute / DataAttribute / ResourceObjectContent /
     * ResourceSimpleContentData / Credential + Secret content) that a Jackson value-tree walk cannot type-detect.
     * Both the value-recording and structural-rejection checks share this traversal so they cannot diverge.
     */
    private void walkSecretGraph(Object node, int depth, java.util.function.Consumer<Object> visitor) {
        if (node == null || depth > MAX_WALK_DEPTH) {
            return;
        }
        visitor.accept(node);

        if (node instanceof Iterable<?> iterable) {
            iterable.forEach(o -> walkSecretGraph(o, depth + 1, visitor));
        } else if (node instanceof Object[] array) {
            for (Object o : array) {
                walkSecretGraph(o, depth + 1, visitor);
            }
        } else if (node instanceof java.util.Map<?, ?> map) {
            map.values().forEach(o -> walkSecretGraph(o, depth + 1, visitor));
        } else if (node instanceof AttributeCallbackResponseDto response) {
            walkSecretGraph(response.getContent(), depth + 1, visitor);
            walkSecretGraph(response.getAttributes(), depth + 1, visitor);
        } else if (node instanceof ResourceObjectContent resourceObjectContent) {
            walkSecretGraph(resourceObjectContent.getData(), depth + 1, visitor);
        } else if (node instanceof ResourceSimpleContentData simple) {
            walkSecretGraph(simple.getAttributes(), depth + 1, visitor);
        } else if (node instanceof ResponseAttribute responseAttribute) {
            walkSecretGraph(responseAttribute.getContent(), depth + 1, visitor);
        } else if (node instanceof BaseAttribute baseAttribute) {
            // The response 'attributes' arm is List<BaseAttribute> — Data/Metadata/Custom all expose content via
            // the universal getContent(); descend the base type so a secret nested in any of them is reached.
            walkSecretGraph(baseAttribute.getContent(), depth + 1, visitor);
        } else if (node instanceof CredentialAttributeContentV2 credential) {
            walkSecretGraph(credential.getData(), depth + 1, visitor);
        } else if (node instanceof CredentialAttributeContentData credential) {
            walkSecretGraph(credential.getAttributes(), depth + 1, visitor);
        } else if (node instanceof SecretAttributeContentV2 secret) {
            walkSecretGraph(secret.getData(), depth + 1, visitor);
        }
    }

    private static boolean containsAnyScalar(JsonNode node, Set<String> needles) {
        if (node == null || node.isNull()) {
            return false;
        }
        if (node.isValueNode()) {
            return needles.contains(node.asText());
        }
        for (Iterator<JsonNode> it = node.elements(); it.hasNext(); ) {
            if (containsAnyScalar(it.next(), needles)) {
                return true;
            }
        }
        return false;
    }

    private static void collectScalarStrings(JsonNode node, Set<String> sink) {
        if (node == null || node.isNull()) {
            return;
        }
        if (node.isValueNode()) {
            String text = node.asText();
            if (text != null && !text.isBlank()) {
                sink.add(text);
            }
            return;
        }
        node.elements().forEachRemaining(child -> collectScalarStrings(child, sink));
    }
}
