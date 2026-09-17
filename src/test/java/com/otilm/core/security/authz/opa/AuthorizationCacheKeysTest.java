package com.otilm.core.security.authz.opa;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationCacheKeysTest {

    private static final String PERMISSIONS = """
            {"allowAllResources":false,"resources":[\
            {"name":"certificates","allowAllActions":false,"actions":["detail","list"],"objects":[]}]}""";

    private final ObjectMapper om = new ObjectMapper();

    private static String profile(String userUuid, String username, String roles, String permissions) {
        return """
                {"user":{"uuid":"%s","username":"%s"},"roles":%s,"permissions":%s}"""
                .formatted(userUuid, username, roles, permissions);
    }

    @Test
    void sameDigest_whenUsersDifferButPermissionsMatch() throws Exception {
        String alice = profile("1111", "alice", """
                [{"uuid":"aaaa","name":"Certificate Operator"}]""", PERMISSIONS);
        String bob = profile("2222", "bob", """
                [{"uuid":"aaaa","name":"Certificate Operator"}]""", PERMISSIONS);

        String digest = AuthorizationCacheKeys.principalDigest(om, alice);
        assertThat(digest).hasSize(64).matches("[0-9a-f]{64}");
        assertThat(digest).isEqualTo(AuthorizationCacheKeys.principalDigest(om, bob));
    }

    @Test
    void sameDigest_whenRoleSetsDifferButPermissionsMatch() throws Exception {
        String oneRole = profile("1111", "alice", """
                [{"uuid":"aaaa","name":"Certificate Operator"}]""", PERMISSIONS);
        String twoRoles = profile("1111", "alice", """
                [{"uuid":"aaaa","name":"Certificate Operator"},{"uuid":"bbbb","name":"Redundant"}]""", PERMISSIONS);

        assertThat(AuthorizationCacheKeys.principalDigest(om, oneRole))
                .isEqualTo(AuthorizationCacheKeys.principalDigest(om, twoRoles));
    }

    @Test
    void differentDigest_whenPermissionsDiffer() throws Exception {
        String operator = profile("1111", "alice", "[]", PERMISSIONS);
        String admin = profile("1111", "alice", "[]", """
                {"allowAllResources":true,"resources":[]}""");

        assertThat(AuthorizationCacheKeys.principalDigest(om, operator))
                .isNotEqualTo(AuthorizationCacheKeys.principalDigest(om, admin));
    }

    @Test
    void differentDigest_whenAnonymousAndAuthenticatedBothCarryNoPermissions() throws Exception {
        String anonymous = """
                {"user":{"username":"anonymousUser"}}""";
        String namedWithoutPermissions = """
                {"user":{"username":"alice"}}""";

        assertThat(AuthorizationCacheKeys.principalDigest(om, anonymous))
                .isNotEqualTo(AuthorizationCacheKeys.principalDigest(om, namedWithoutPermissions));
    }

    @Test
    void sameDigest_forAnonymousCallersCarryingDifferentUserFields() throws Exception {
        String first = """
                {"user":{"uuid":"1111","username":"anonymousUser"},"roles":[]}""";
        String second = """
                {"user":{"uuid":"2222","username":"anonymousUser"},"roles":[{"uuid":"aaaa","name":"Ignored"}]}""";

        assertThat(AuthorizationCacheKeys.principalDigest(om, first))
                .isEqualTo(AuthorizationCacheKeys.principalDigest(om, second));
    }

    @Test
    void differentDigest_whenAnonymousAndNamedCarryTheSamePermissions() throws Exception {
        String anonymous = """
                {"user":{"username":"anonymousUser"},"roles":[],"permissions":%s}""".formatted(PERMISSIONS);
        String named = """
                {"user":{"username":"alice"},"roles":[],"permissions":%s}""".formatted(PERMISSIONS);

        assertThat(AuthorizationCacheKeys.principalDigest(om, anonymous))
                .isNotEqualTo(AuthorizationCacheKeys.principalDigest(om, named));
    }

    @Test
    void digestsAPrincipalWithNoUserNode() throws Exception {
        String noUser = """
                {"permissions":%s}""".formatted(PERMISSIONS);
        String namedNonAnonymous = profile("1111", "alice", "[]", PERMISSIONS);

        assertThat(AuthorizationCacheKeys.principalDigest(om, noUser))
                .isEqualTo(AuthorizationCacheKeys.principalDigest(om, namedNonAnonymous));
    }

    @Test
    void differentDigest_whenPermissionsIsNullVersusAbsent() throws Exception {
        String explicitNull = """
                {"user":{"username":"alice"},"permissions":null}""";
        String absent = """
                {"user":{"username":"alice"}}""";

        assertThat(AuthorizationCacheKeys.principalDigest(om, explicitNull))
                .isNotEqualTo(AuthorizationCacheKeys.principalDigest(om, absent));
    }

    @Test
    void decisionKeyVariesWithEveryComponent() {
        String base = AuthorizationCacheKeys.decisionKey("method", "digest", "{\"name\":\"certificates\"}", "{}");

        assertThat(base).hasSize(64);
        assertThat(base)
                .isNotEqualTo(
                        AuthorizationCacheKeys.decisionKey("objects", "digest", "{\"name\":\"certificates\"}", "{}"));
        assertThat(base)
                .isNotEqualTo(
                        AuthorizationCacheKeys.decisionKey("method", "other", "{\"name\":\"certificates\"}", "{}"));
        assertThat(base)
                .isNotEqualTo(AuthorizationCacheKeys.decisionKey("method", "digest", "{\"name\":\"groups\"}", "{}"));
        assertThat(base)
                .isNotEqualTo(AuthorizationCacheKeys
                        .decisionKey("method", "digest", "{\"name\":\"certificates\"}", "{\"a\":1}"));
    }

    @Test
    void decisionKeyResistsPrincipalCollisionsAcrossComponentBoundaries() {
        // Naive newline joining would collide: "a\nb\nc" + "\n" + "d"
        // versus "a\nb" + "\n" + "c\nd". Length-prefixed format prevents this.
        String key1 = AuthorizationCacheKeys.decisionKey("a", "b\nc", "d", "e");
        String key2 = AuthorizationCacheKeys.decisionKey("a\nb", "c", "d", "e");

        assertThat(key1).isNotEqualTo(key2);
    }
}
