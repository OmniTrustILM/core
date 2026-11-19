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
    void grantsCertificatesOnlyWhenTheMethodPolicyWouldWithoutARequest(String shape, String principal,
            boolean granted) {
        // when
        AllResourcesGrant grant = AllResourcesGrant.of(new ObjectMapper(), principal);

        // then
        assertThat(grant.grants(CERTIFICATES)).isEqualTo(granted);
    }

    @Test
    void grantsNoResourceWithoutAName() {
        // when
        AllResourcesGrant grant = AllResourcesGrant.of(new ObjectMapper(), permissions("true", null));

        // then
        assertThat(grant.grants(null)).isFalse();
    }

    static Stream<Arguments> principals() {
        return Stream
                .of(Arguments.of("unparseable principal", "not json", false),
                        Arguments.of("absent principal", null, false), Arguments.of("no permissions", "{}", false),
                        Arguments.of("all resources not allowed", permissions("false", null), false),
                        Arguments.of("all resources allowed as text", permissions("\"true\"", null), false),
                        Arguments.of("all resources allowed, no resources", permissions("true", null), true),
                        Arguments.of("all resources allowed, null resources", permissions("true", "null"), true),
                        Arguments.of("resources not a list", permissions("true", "{}"), false),
                        Arguments
                                .of("a certificate denied", permissions("true", resource(CERTIFICATES, "[\"update\"]")),
                                        false),
                        Arguments
                                .of("only a token denied", permissions("true", resource("tokens", "[\"update\"]")),
                                        true),
                        Arguments.of("empty deny", permissions("true", resource(CERTIFICATES, "[]")), true),
                        Arguments.of("null deny", permissions("true", resource(CERTIFICATES, "null")), true),
                        Arguments
                                .of("deny not a list", permissions("true", resource(CERTIFICATES, "\"update\"")),
                                        false),
                        Arguments
                                .of("objects not a list",
                                        permissions("true", "[{\"name\":\"" + CERTIFICATES + "\",\"objects\":{}}]"),
                                        false));
    }

    private static String permissions(String allowAllResources, String resources) {
        String resourcesField = resources == null ? "" : ",\"resources\":" + resources;
        return "{\"permissions\":{\"allowAllResources\":" + allowAllResources + resourcesField + "}}";
    }

    private static String resource(String name, String deny) {
        return "[{\"name\":\"" + name + "\",\"objects\":[{\"uuid\":\"u\",\"deny\":" + deny + "}]}]";
    }
}
