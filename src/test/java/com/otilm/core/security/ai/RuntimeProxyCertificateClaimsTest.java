package com.otilm.core.security.ai;

import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RuntimeProxyCertificateClaimsTest {
    private static final UUID POD = UUID.fromString("9becdc03-81ae-4b49-a913-a30b1c2cd774");
    private static final String VALID = "ilm-runtime-proxy://cluster-one/ns/ai-proof/sa/runner/pod/agent-1/uid/" + POD;

    @Test
    void validProxyUriRoundTripsWithoutImplyingAuthentication() {
        RuntimeProxyCertificateClaims claims = RuntimeProxyCertificateClaims.parse(VALID).orElseThrow();
        assertThat(claims.cluster()).isEqualTo("cluster-one");
        assertThat(claims.namespace()).isEqualTo("ai-proof");
        assertThat(claims.serviceAccount()).isEqualTo("runner");
        assertThat(claims.podName()).isEqualTo("agent-1");
        assertThat(claims.podUid()).isEqualTo(POD);
        assertThat(claims.uri()).isEqualTo(VALID);
    }

    @Test
    void exactFieldBoundsAndMultipleLabelsRoundTrip() {
        String label = "a".repeat(63);
        String subdomain = label + "." + label + "." + label + "." + "b".repeat(61);
        assertThat(subdomain).hasSize(253);
        for (RuntimeProxyCertificateClaims value : List
                .of(new RuntimeProxyCertificateClaims("a", "0", "a", "0", POD),
                        new RuntimeProxyCertificateClaims("a", "a", "a", "a", new UUID(0, 1)),
                        new RuntimeProxyCertificateClaims(label, label, subdomain, subdomain, POD),
                        new RuntimeProxyCertificateClaims("cluster", "namespace", "account.example", "agent-0.example",
                                POD))) {
            assertThat(RuntimeProxyCertificateClaims.parse(value.uri())).contains(value);
        }
    }

    @ParameterizedTest
    @MethodSource("malformed")
    void rejectsAlternateAuthorityPathOrAudience(String input) {
        assertThat(RuntimeProxyCertificateClaims.parse(input)).isEmpty();
    }

    static Stream<String> malformed() {
        return Stream
                .of("", " " + VALID, VALID + " ", VALID.replace("ilm-runtime-proxy", "ilm-runtime"),
                        VALID.replace("ilm-runtime-proxy", "ILM-RUNTIME-PROXY"),
                        VALID.replace("ilm-runtime-proxy", "https"), VALID.replace("ilm-runtime-proxy://", "//"),
                        VALID.replace("://", ":"), VALID.replace("cluster-one", "c:"),
                        VALID.replace("cluster-one", "c:0"), VALID.replace("cluster-one", "u@c"),
                        VALID.replace("cluster-one", "[::1]"), VALID.replace("cluster-one", "c."),
                        VALID.replace("cluster-one", "a.b"), VALID.replace("cluster-one", ""),
                        VALID.replace("/ns/", "/NS/"), VALID.replace("/ns/", "/%6e%73/"), VALID.replace("/ns/", "/sa/"),
                        VALID.replace("/sa/", "/SA/"), VALID.replace("/pod/", "/POD/"), VALID.replace("/uid/", "/UID/"),
                        VALID.replace("/sa/runner", ""), VALID.replace("/ns/ai-proof", "/ns//ai-proof"),
                        VALID.replace("ai-proof", "."), VALID.replace("ai-proof", ".."),
                        VALID.replace("agent-1", "agent%2F1"), VALID.replace("agent-1", "agent%2f1"),
                        VALID.replace("agent-1", "%41gent-1"), VALID.replace("agent-1", "Agent-1"), VALID + "/",
                        VALID + "/extra", VALID + "?", VALID + "?x=1", VALID + "#", VALID + "#x");
    }

    @Test
    void rejectsNoncanonicalOrNilUuid() {
        for (String uid : List
                .of(POD.toString().toUpperCase(java.util.Locale.ROOT), "1-1-1-1-1", "{" + POD + "}",
                        "00000000-0000-0000-0000-000000000000", "not-a-uuid")) {
            assertThat(RuntimeProxyCertificateClaims.parse(VALID.replace(POD.toString(), uid))).isEmpty();
        }
    }

    @Test
    void rejectsNullOversizeControlAndUnicodeBeforeUriParsing() {
        assertThat(RuntimeProxyCertificateClaims.parse(null)).isEmpty();
        assertThat(RuntimeProxyCertificateClaims.parse(VALID + "a".repeat(1025))).isEmpty();
        for (String value : List
                .of("a\nb", "a\tb", "a\rb", "a b", "aé", "a" + Character.MIN_HIGH_SURROGATE,
                        "a" + Character.MIN_LOW_SURROGATE, "a" + (char) 0x7f)) {
            assertThat(RuntimeProxyCertificateClaims.parse(VALID.replace("agent-1", value))).isEmpty();
        }
    }

    @Test
    void constructorRejectsInvalidLabelsAndAdjacentLengthBounds() {
        for (String bad : List.of("", "-a", "a-", "a_b", "A", "é", "a..b", "a/b", "a%2eb", "a".repeat(64))) {
            assertThatThrownBy(() -> new RuntimeProxyCertificateClaims(bad, "ns", "sa", "pod", POD))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> new RuntimeProxyCertificateClaims("c", bad, "sa", "pod", POD))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        String tooLong = "a".repeat(63) + "." + "b".repeat(63) + "." + "c".repeat(63) + "." + "d".repeat(62);
        for (String bad : List
                .of("", ".a", "a.", "a..b", "a/b", "a%2eb", "A", "é", "-a", "a-", "a".repeat(64), tooLong)) {
            assertThatThrownBy(() -> new RuntimeProxyCertificateClaims("c", "ns", bad, "pod", POD))
                    .isInstanceOf(IllegalArgumentException.class);
            assertThatThrownBy(() -> new RuntimeProxyCertificateClaims("c", "ns", "sa", bad, POD))
                    .isInstanceOf(IllegalArgumentException.class);
        }
        assertThatThrownBy(() -> new RuntimeProxyCertificateClaims("a.b", "ns", "sa", "pod", POD))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RuntimeProxyCertificateClaims("c", "a.b", "sa", "pod", POD))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void constructorRejectsNullFieldsWithoutEchoingInput() {
        assertThatThrownBy(() -> new RuntimeProxyCertificateClaims(null, "ns", "sa", "pod", POD))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RuntimeProxyCertificateClaims("c", null, "sa", "pod", POD))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RuntimeProxyCertificateClaims("c", "ns", null, "pod", POD))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RuntimeProxyCertificateClaims("c", "ns", "sa", null, POD))
                .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> new RuntimeProxyCertificateClaims("c", "ns", "sa", "pod", null))
                .isInstanceOf(IllegalArgumentException.class);
        UUID nil = new UUID(0, 0);
        assertThatThrownBy(() -> new RuntimeProxyCertificateClaims("c", "ns", "sa", "pod", nil))
                .isInstanceOf(IllegalArgumentException.class);
    }
}
