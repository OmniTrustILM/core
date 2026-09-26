package com.otilm.core.util;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.networknt.schema.JsonSchema;
import com.networknt.schema.JsonSchemaFactory;
import com.networknt.schema.SchemaLocation;
import com.networknt.schema.SpecVersion;
import com.networknt.schema.ValidationMessage;
import com.networknt.schema.resource.ClasspathSchemaLoader;
import com.networknt.schema.resource.DisallowSchemaLoader;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.serialization.ObjectMapperFactory;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Checks a JSON Schema document an attribute definition carries as a constraint, before it is stored.
 *
 * <p>
 * A constraint is policy over a value the extension's own ASN.1 type already governs, so this says nothing about what
 * the value must be - only that the document is one the platform can trust to constrain anything at all.
 */
public final class ConstraintSchemas {

    // ObjectMapperFactory is the single home of production mapper recipes; reading a JSON tree needs
    // nothing beyond the wire recipe.
    private static final ObjectMapper MAPPER = ObjectMapperFactory.wire();
    // Schema loading must never reach the network. A $ref target is resolved on first use rather than when
    // the schema is compiled, so a schema reaching the table by any route other than requireValidSchema would
    // otherwise fetch a URL of its author's choosing partway through validating a request.
    private static final Logger logger = LoggerFactory.getLogger(ConstraintSchemas.class);

    /**
     * Validates a candidate schema document against the dialect's own metaschema. Classpath loading is permitted so the
     * library's bundled metaschema resolves; the network stays refused.
     */
    private static final JsonSchema METASCHEMA = JsonSchemaFactory
            .getInstance(SpecVersion.VersionFlag.V202012,
                    builder -> builder
                            .schemaLoaders(loaders -> loaders
                                    .add(new ClasspathSchemaLoader())
                                    .add(DisallowSchemaLoader.getInstance())))
            .getSchema(SchemaLocation.of(SpecVersion.VersionFlag.V202012.getId()));

    // Draft 2020-12 keywords whose values are subschemas. Walking only these keeps the check off instance data
    // (const, enum, default, examples) and off unknown keywords, which the dialect permits as annotations — a
    // member named $ref inside either is a literal. "definitions" is absent for that reason: 2020-12 replaced
    // it with $defs and treats it as an annotation. DisallowSchemaLoader remains the boundary for anything this
    // list does not reach.
    /** Both reference keywords the dialect defines; networknt resolves each lazily. */
    private static final Set<String> REFERENCE_KEYWORDS = Set.of("$ref", "$dynamicRef");

    private static final Set<String> SUBSCHEMA_KEYWORDS = Set
            .of("additionalProperties", "items", "not", "if", "then", "else", "contains", "propertyNames",
                    "unevaluatedItems", "unevaluatedProperties");
    private static final Set<String> SUBSCHEMA_LIST_KEYWORDS = Set.of("allOf", "anyOf", "oneOf", "prefixItems");
    private static final Set<String> SUBSCHEMA_MAP_KEYWORDS = Set
            .of("properties", "patternProperties", "$defs", "dependentSchemas");

    private static final Set<String> SUPPORTED_DIALECTS = Set
            .of("https://json-schema.org/draft/2020-12/schema", "https://json-schema.org/draft/2020-12/schema#");
    private static final JsonSchemaFactory FACTORY = JsonSchemaFactory
            .getInstance(SpecVersion.VersionFlag.V202012,
                    builder -> builder.schemaLoaders(loaders -> loaders.add(DisallowSchemaLoader.getInstance())));

    private ConstraintSchemas() {
    }

    /**
     * Rejects a schema document that cannot be trusted to constrain anything: it must parse as exactly one JSON value,
     * declare no dialect but draft 2020-12, reference nothing outside itself, carry well-formed keywords, and compile.
     *
     * <p>
     * A reference resolved only on use escapes all of that, so one that cannot be resolved locally is refused here
     * rather than discovered when a value is checked against the document.
     */
    public static void requireValidSchema(String schemaDocument) {
        if (schemaDocument == null) {
            // readTree(null) throws IllegalArgumentException, which is not this method's contract.
            throw new ValidationException("Not a valid JSON Schema document: no document was supplied");
        }
        JsonNode parsed;
        try {
            parsed = MAPPER
                    .reader()
                    .with(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
                    .with(JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
                    .readTree(schemaDocument);
        } catch (IOException e) {
            throw new ValidationException("Not a valid JSON Schema document: not JSON");
        }
        if (parsed == null || !(parsed.isObject() || parsed.isBoolean())) {
            throw new ValidationException("Not a valid JSON Schema document: the root must be an object or a boolean");
        }
        requireSupportedDialect(parsed);
        rejectNonLocalRefs(parsed, "$", documentId(parsed));
        requireWellFormedKeywords(parsed);
        try {
            FACTORY.getSchema(parsed);
        } catch (RuntimeException e) {
            // The library's own message names parser and resource-loading internals; this one reaches the
            // custom-OID API, so keep the detail in the log and hand the operator a controlled message.
            logger.debug("JSON Schema document could not be compiled", e);
            throw new ValidationException("Not a valid JSON Schema document: it could not be compiled");
        }
    }

    /**
     * Rejects a document whose keywords are malformed. {@code getSchema} compiles a schema without checking keyword
     * shapes, so {@code {"minItems": "x"}} or {@code {"type": 123}} would otherwise register and then constrain
     * nothing. Validating against the dialect's own metaschema is the check the document claims to satisfy.
     */
    private static void requireWellFormedKeywords(JsonNode document) {
        Set<String> messages = new java.util.LinkedHashSet<>();
        for (ValidationMessage violation : METASCHEMA.validate(document)) {
            messages.add("%s %s".formatted(violation.getInstanceLocation(), violation.getMessage()));
        }
        if (!messages.isEmpty()) {
            throw new ValidationException("Not a valid JSON Schema document: " + String.join("; ", messages));
        }
    }

    /**
     * Rejects a declared {@code $schema} other than draft 2020-12. The factory's default applies only when the document
     * omits the keyword, so a declared older draft would be honoured instead — and under draft-04 a keyword such as
     * {@code prefixItems} is unknown, so a schema that looks restrictive would enforce nothing.
     */
    private static void requireSupportedDialect(JsonNode document) {
        if (!document.isObject() || !document.has("$schema")) {
            return;
        }
        JsonNode declared = document.get("$schema");
        if (!declared.isTextual() || !SUPPORTED_DIALECTS.contains(declared.textValue())) {
            throw new ValidationException(
                    "Not a valid JSON Schema document: only the draft 2020-12 dialect is supported");
        }
    }

    /**
     * Rejects a {@code $ref} that points outside the document. Such a reference cannot be resolved without fetching it,
     * which the platform does not do, so accepting one would register a schema that silently constrains nothing.
     */
    private static void rejectNonLocalRefs(JsonNode node, String path, String documentId) {
        if (node == null || !node.isObject()) {
            return;
        }
        for (String keyword : REFERENCE_KEYWORDS) {
            JsonNode ref = node.get(keyword);
            if (ref != null && ref.isTextual() && !resolvesWithinDocument(ref.textValue(), documentId)) {
                throw new ValidationException(
                        "Not a valid JSON Schema document: %s at %s points outside the document; only local references such as #/$defs/name are supported"
                                .formatted(keyword, path));
            }
        }
        for (Map.Entry<String, JsonNode> property : node.properties()) {
            String childPath = path + "." + property.getKey();
            subschemasOf(property.getKey(), property.getValue())
                    .forEach(child -> rejectNonLocalRefs(child, childPath, documentId));
        }
    }

    /** The document's own {@code $id}, against which an absolute self-reference resolves, or {@code null}. */
    private static String documentId(JsonNode document) {
        JsonNode id = document == null ? null : document.get("$id");
        return id != null && id.isTextual() ? id.textValue() : null;
    }

    /**
     * Whether a reference stays inside the document: empty (the root), a fragment, or absolute but matching the
     * document's own {@code $id}.
     *
     * <p>
     * A nested {@code $id} re-scopes the base URI, which this does not follow — a reference relying on one falls
     * through to the loader, which refuses it, so the failure surfaces later rather than being missed.
     */
    private static boolean resolvesWithinDocument(String ref, String documentId) {
        if (ref.isEmpty() || ref.startsWith("#")) {
            return true;
        }
        if (documentId == null) {
            return false;
        }
        int fragment = ref.indexOf('#');
        return documentId.equals(fragment < 0 ? ref : ref.substring(0, fragment));
    }

    /** The subschemas a keyword's value holds, or nothing when the keyword does not hold subschemas. */
    private static List<JsonNode> subschemasOf(String keyword, JsonNode value) {
        if (SUBSCHEMA_KEYWORDS.contains(keyword)) {
            return List.of(value);
        }
        List<JsonNode> children = new ArrayList<>();
        if (SUBSCHEMA_LIST_KEYWORDS.contains(keyword) && value.isArray()) {
            value.forEach(children::add);
        } else if (SUBSCHEMA_MAP_KEYWORDS.contains(keyword) && value.isObject()) {
            value.properties().forEach(entry -> children.add(entry.getValue()));
        }
        return children;
    }
}
