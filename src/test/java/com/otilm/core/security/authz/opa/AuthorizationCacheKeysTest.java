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

        assertThat(AuthorizationCacheKeys.principalDigest(om, alice))
                .isEqualTo(AuthorizationCacheKeys.principalDigest(om, bob));
    }

    @Test
    void sameDigest_whenRoleSetsDifferButPermissionsMatch() throws Exception {
        String oneRole = profile("1111", "alice", """
                [{"uuid":"aaaa","name":"Certificate Operator"}]""", PERMISSIONS);
        String twoRoles = profile("2222", "bob", """
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
    void sameDigest_forEveryAnonymousCaller() throws Exception {
        String anonymous = """
                {"user":{"username":"anonymousUser"}}""";

        assertThat(AuthorizationCacheKeys.principalDigest(om, anonymous))
                .isEqualTo(AuthorizationCacheKeys.principalDigest(om, anonymous));
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
}
