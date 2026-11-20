package com.otilm.core.security.authz;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;

class AllResourcesGrantTest {

    private static final String CERTIFICATES = "certificates";

    @ParameterizedTest(name = "{0}")
    @MethodSource("principals")
    void decidesWhetherCertificatesSkipOpa_whenParsingThePrincipal(String shape, String principal, boolean granted) {
        // given — a principal shape and whether its certificate checks can skip OPA, from principals()

        // when
        AllResourcesGrant grant = AllResourcesGrant.of(new ObjectMapper(), principal);

        // then
        assertThat(grant.grants(CERTIFICATES)).isEqualTo(granted);
    }

    @Test
    void grantsNoResource_whenTheResourceHasNoName() {
        // given
        String allowedAllResources = createPermissions("true", null);

        // when
        AllResourcesGrant grant = AllResourcesGrant.of(new ObjectMapper(), allowedAllResources);

        // then
        assertThat(grant.grants(null)).isFalse();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Arguments> principals() {
        return Stream
                .of(Arguments.of("unparseable principal", "not json", false),
                        Arguments.of("absent principal", null, false), Arguments.of("no permissions", "{}", false),
                        Arguments.of("all resources not allowed", createPermissions("false", null), false),
                        Arguments.of("all resources allowed as text", createPermissions("\"true\"", null), false),
                        Arguments.of("all resources allowed, no resources", createPermissions("true", null), true),
                        Arguments.of("all resources allowed, null resources", createPermissions("true", "null"), true),
                        Arguments.of("resources not a list", createPermissions("true", "{}"), false),
                        Arguments
                                .of("a certificate denied",
                                        createPermissions("true", createResource(CERTIFICATES, "[\"update\"]")), false),
                        Arguments
                                .of("only a token denied",
                                        createPermissions("true", createResource("tokens", "[\"update\"]")), true),
                        Arguments.of("empty deny", createPermissions("true", createResource(CERTIFICATES, "[]")), true),
                        Arguments
                                .of("null deny", createPermissions("true", createResource(CERTIFICATES, "null")), true),
                        Arguments
                                .of("deny not a list",
                                        createPermissions("true", createResource(CERTIFICATES, "\"update\"")), false),
                        Arguments
                                .of("objects not a list", createPermissions("true",
                                        "[{\"name\":\"" + CERTIFICATES + "\",\"objects\":{}}]"), false));
    }

    private static String createPermissions(String allowAllResources, String resources) {
        String resourcesField = resources == null ? "" : ",\"resources\":" + resources;
        return "{\"permissions\":{\"allowAllResources\":" + allowAllResources + resourcesField + "}}";
    }

    private static String createResource(String name, String deny) {
        return "[{\"name\":\"" + name + "\",\"objects\":[{\"uuid\":\"u\",\"deny\":" + deny + "}]}]";
    }
}
