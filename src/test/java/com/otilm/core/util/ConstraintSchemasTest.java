package com.otilm.core.util;

import com.otilm.api.exception.ValidationException;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ConstraintSchemasTest {

    @Test
    void requireValidSchemaAcceptsASchemaAndRejectsGarbage() {
        ConstraintSchemas.requireValidSchema("{\"type\":\"object\"}");
        assertThatThrownBy(() -> ConstraintSchemas.requireValidSchema("this is not json"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("valid JSON Schema document");
    }

    @Test
    void requireValidSchemaRejectsARootThatIsNotAnObjectOrBoolean() {
        // Each of these parses as JSON and compiles into a schema that constrains nothing, so an operator
        // would believe they had registered a shape and get none.
        for (String document : List.of("\"hello\"", "123", "null", "[]", "\"\"")) {
            assertThatThrownBy(() -> ConstraintSchemas.requireValidSchema(document))
                    .as("document: %s", document)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("object or a boolean");
        }
    }

    @Test
    void requireValidSchemaAcceptsABooleanRoot() {
        assertThatNoException().isThrownBy(() -> ConstraintSchemas.requireValidSchema("true"));
        assertThatNoException().isThrownBy(() -> ConstraintSchemas.requireValidSchema("false"));
    }

    @Test
    void requireValidSchemaRejectsARefPointingOutsideTheDocument() {
        for (String ref : List
                .of("https://evil.example.com/x.json", "http://169.254.169.254/latest/meta-data/",
                        "file:///etc/passwd")) {
            assertThatThrownBy(() -> ConstraintSchemas.requireValidSchema("{\"$ref\":\"" + ref + "\"}"))
                    .as("ref: %s", ref)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("points outside the document");
        }
    }

    @Test
    void requireValidSchemaRejectsANestedRemoteRef() {
        assertThatThrownBy(() -> ConstraintSchemas
                .requireValidSchema("{\"properties\":{\"a\":{\"items\":{\"$ref\":\"https://x/y\"}}}}"))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("points outside the document");
    }

    @Test
    void requireValidSchemaAcceptsALocalFragmentRef() {
        assertThatNoException()
                .isThrownBy(() -> ConstraintSchemas
                        .requireValidSchema("{\"$defs\":{\"x\":{\"type\":\"integer\"}},\"$ref\":\"#/$defs/x\"}"));
    }

    @Test
    void requireValidSchemaRejectsADeclaredOlderDialect() {
        // The factory default applies only when $schema is absent. Under draft-04, prefixItems is an unknown
        // keyword, so a schema that reads as restrictive would enforce nothing.
        String draft4 = "{\"$schema\":\"http://json-schema.org/draft-04/schema#\",\"type\":\"object\"}";

        assertThatThrownBy(() -> ConstraintSchemas.requireValidSchema(draft4))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("draft 2020-12");
    }

    @Test
    void requireValidSchemaAcceptsTheDeclaredSupportedDialect() {
        String declared = "{\"$schema\":\"https://json-schema.org/draft/2020-12/schema\",\"type\":\"object\"}";

        assertThatNoException().isThrownBy(() -> ConstraintSchemas.requireValidSchema(declared));
    }

    @Test
    void requireValidSchemaRejectsTrailingContent() {
        // readTree stops at the first complete value, so trailing text would be discarded unnoticed.
        assertThatThrownBy(() -> ConstraintSchemas.requireValidSchema("{\"type\":\"object\"} and then some"))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void requireValidSchemaRejectsMalformedKeywords() {
        // getSchema compiles these without complaint, so they would register and then constrain nothing.
        assertThatThrownBy(() -> ConstraintSchemas.requireValidSchema("{\"minItems\":\"x\"}"))
                .isInstanceOf(ValidationException.class);
        assertThatThrownBy(() -> ConstraintSchemas.requireValidSchema("{\"type\":123}"))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void requireValidSchemaRejectsAMissingDocument() {
        // readTree(null) throws IllegalArgumentException, which is not this method's contract.
        assertThatThrownBy(() -> ConstraintSchemas.requireValidSchema(null)).isInstanceOf(ValidationException.class);
    }

    @Test
    void requireValidSchemaAcceptsARefInsideInstanceData() {
        // const holds a literal value, so a member named $ref there is data and not a reference.
        assertThatNoException()
                .isThrownBy(() -> ConstraintSchemas
                        .requireValidSchema("{\"const\":{\"$ref\":\"https://example.invalid/x\"}}"));
    }

    @Test
    void requireValidSchemaAcceptsARefUnderAnAnnotationKeyword() {
        // Draft 2020-12 permits unknown keywords as annotations, and it replaced definitions with $defs — so a
        // member named $ref inside either is data rather than a reference.
        assertThatNoException()
                .isThrownBy(() -> ConstraintSchemas
                        .requireValidSchema("{\"x-ui\":{\"$ref\":\"https://example.invalid/x\"}}"));
        assertThatNoException()
                .isThrownBy(() -> ConstraintSchemas
                        .requireValidSchema("{\"definitions\":{\"x\":{\"$ref\":\"https://example.invalid/x\"}}}"));
    }

    @Test
    void requireValidSchemaStillRejectsARemoteRefInASubschema() {
        assertThatThrownBy(() -> ConstraintSchemas
                .requireValidSchema("{\"$defs\":{\"x\":{\"$ref\":\"https://example.invalid/x\"}}}"))
                .isInstanceOf(ValidationException.class);
        assertThatThrownBy(() -> ConstraintSchemas
                .requireValidSchema("{\"properties\":{\"a\":{\"$ref\":\"https://example.invalid/x\"}}}"))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void requireValidSchemaAcceptsReferencesThatResolveInsideTheDocument() {
        assertThatNoException()
                .isThrownBy(() -> ConstraintSchemas.requireValidSchema("{\"$defs\":{\"n\":{\"$ref\":\"\"}}}"));
        assertThatNoException()
                .isThrownBy(() -> ConstraintSchemas
                        .requireValidSchema("{\"$id\":\"https://example.test/s\",\"$defs\":{\"n\":"
                                + "{\"type\":\"object\"}},\"$ref\":\"https://example.test/s#/$defs/n\"}"));
    }

    @Test
    void requireValidSchemaRejectsARemoteDynamicRef() {
        // $dynamicRef is the dialect's other reference keyword and networknt resolves it just as lazily.
        assertThatThrownBy(
                () -> ConstraintSchemas.requireValidSchema("{\"$dynamicRef\":\"https://example.invalid/x\"}"))
                .isInstanceOf(ValidationException.class);
    }

    @Test
    void requireValidSchemaRejectsADuplicateKey() {
        // The last wins silently, so the operator's first constraint would vanish.
        assertThatThrownBy(() -> ConstraintSchemas.requireValidSchema("{\"required\":[\"a\"],\"required\":[\"b\"]}"))
                .isInstanceOf(ValidationException.class);
    }

}
