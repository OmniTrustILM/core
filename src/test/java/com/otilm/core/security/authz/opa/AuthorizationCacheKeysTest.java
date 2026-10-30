package com.otilm.core.security.authz.opa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.core.security.authz.opa.dto.OpaRequestedResource;
import com.otilm.core.util.PrincipalFixtures;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AuthorizationCacheKeysTest {

    private final ObjectMapper om = new ObjectMapper();

    @Test
    void sameDigest_whenUsersDifferButPermissionsMatch() throws Exception {
        String alice = PrincipalFixtures.operator("1111", "alice");
        String bob = PrincipalFixtures.operator("2222", "bob");

        String digest = AuthorizationCacheKeys.principalDigest(om, alice);
        assertThat(digest)
                .hasSize(64)
                .matches("[0-9a-f]{64}")
                .isEqualTo(AuthorizationCacheKeys.principalDigest(om, bob));
    }

    @Test
    void sameDigest_whenRoleSetsDifferButPermissionsMatch() throws Exception {
        UserProfileDto oneRole = PrincipalFixtures.operatorProfile("1111", "alice");
        oneRole.setRoles(List.of(new NameAndUuidDto("aaaa", "Certificate Operator")));
        UserProfileDto twoRoles = PrincipalFixtures.operatorProfile("1111", "alice");
        twoRoles
                .setRoles(List
                        .of(new NameAndUuidDto("aaaa", "Certificate Operator"),
                                new NameAndUuidDto("bbbb", "Redundant")));

        assertThat(AuthorizationCacheKeys.principalDigest(om, PrincipalFixtures.principal(oneRole)))
                .isEqualTo(AuthorizationCacheKeys.principalDigest(om, PrincipalFixtures.principal(twoRoles)));
    }

    @Test
    void differentDigest_whenPermissionsDiffer() throws Exception {
        String operator = PrincipalFixtures.operator("1111", "alice");
        String admin = PrincipalFixtures.admin("1111", "alice");

        assertThat(AuthorizationCacheKeys.principalDigest(om, operator))
                .isNotEqualTo(AuthorizationCacheKeys.principalDigest(om, admin));
    }

    @Test
    void differentDigest_whenAnonymousAndAuthenticatedBothCarryNoPermissions() throws Exception {
        UserProfileDto namedWithoutPermissions = PrincipalFixtures.anonymousProfile();
        namedWithoutPermissions.getUser().setUsername("alice");

        assertThat(AuthorizationCacheKeys.principalDigest(om, PrincipalFixtures.anonymous()))
                .isNotEqualTo(AuthorizationCacheKeys
                        .principalDigest(om, PrincipalFixtures.principal(namedWithoutPermissions)));
    }

    @Test
    void sameDigest_forAnonymousCallersCarryingDifferentUserFields() throws Exception {
        UserProfileDto first = PrincipalFixtures.anonymousProfile();
        first.getUser().setUuid("1111");
        UserProfileDto second = PrincipalFixtures.anonymousProfile();
        second.getUser().setUuid("2222");
        second.setRoles(List.of(new NameAndUuidDto("aaaa", "Ignored")));

        assertThat(AuthorizationCacheKeys.principalDigest(om, PrincipalFixtures.principal(first)))
                .isEqualTo(AuthorizationCacheKeys.principalDigest(om, PrincipalFixtures.principal(second)));
    }

    @Test
    void differentDigest_whenAnonymousAndNamedCarryTheSamePermissions() throws Exception {
        String anonymous = PrincipalFixtures.operator("1111", "anonymousUser");
        String named = PrincipalFixtures.operator("1111", "alice");

        assertThat(AuthorizationCacheKeys.principalDigest(om, anonymous))
                .isNotEqualTo(AuthorizationCacheKeys.principalDigest(om, named));
    }

    @Test
    void digestsAPrincipalWithNoUserNode() throws Exception {
        String namedNonAnonymous = PrincipalFixtures.operator("1111", "alice");
        // Deliberately malformed: a principal whose user node is absent, which no fixture can produce.
        String noUser = """
                {"permissions":%s}""".formatted(om.readTree(namedNonAnonymous).get("permissions"));

        assertThat(AuthorizationCacheKeys.principalDigest(om, noUser))
                .isEqualTo(AuthorizationCacheKeys.principalDigest(om, namedNonAnonymous));
    }

    @Test
    void differentDigest_whenPermissionsIsNullVersusAbsent() throws Exception {
        // Deliberately malformed: an explicit null permissions node against an absent one, which no fixture can
        // produce because the DTO cannot express the difference.
        String explicitNull = """
                {"user":{"username":"alice"},"permissions":null}""";
        String absent = """
                {"user":{"username":"alice"}}""";

        assertThat(AuthorizationCacheKeys.principalDigest(om, explicitNull))
                .isNotEqualTo(AuthorizationCacheKeys.principalDigest(om, absent));
    }

    @Test
    void rejectsAPrincipalCarryingTrailingContent() {
        // Deliberately malformed: a complete profile followed by a second one, which no fixture can produce.
        String twoDocuments = PrincipalFixtures.operator("1111", "alice") + PrincipalFixtures.admin("2222", "bob");

        assertThatThrownBy(() -> AuthorizationCacheKeys.principalDigest(om, twoDocuments))
                .isInstanceOf(JsonProcessingException.class);
    }

    @Test
    void canonicalResourceJsonIsIndependentOfAssemblyOrder() throws Exception {
        Map<String, String> reversed = new LinkedHashMap<>();
        reversed.put("action", "detail");
        reversed.put("name", "certificates");
        OpaRequestedResource first = new OpaRequestedResource(Map.of("name", "certificates", "action", "detail"));
        first.setObjectUUIDs(List.of("abc-123", "def-456"));
        first.setParentObjectUUIDs(List.of("ghi-789", "jkl-012"));
        OpaRequestedResource second = new OpaRequestedResource(reversed);
        second.setObjectUUIDs(List.of("def-456", "abc-123"));
        second.setParentObjectUUIDs(List.of("jkl-012", "ghi-789"));

        assertThat(AuthorizationCacheKeys.canonicalResourceJson(om, first))
                .isEqualTo(AuthorizationCacheKeys.canonicalResourceJson(om, second));
    }

    @Test
    void canonicalResourceJsonKeepsAnAbsentUuidListApartFromAnEmptyOne() throws Exception {
        OpaRequestedResource absent = new OpaRequestedResource(Map.of("name", "certificates"));
        OpaRequestedResource empty = new OpaRequestedResource(Map.of("name", "certificates"));
        empty.setObjectUUIDs(List.of());

        assertThat(AuthorizationCacheKeys.canonicalResourceJson(om, absent))
                .isNotEqualTo(AuthorizationCacheKeys.canonicalResourceJson(om, empty));
    }

    @Test
    void decisionKeyVariesWithEveryComponent() {
        String base = AuthorizationCacheKeys.decisionKey("method", "digest", "{\"name\":\"certificates\"}", "{}");

        assertThat(base)
                .hasSize(64)
                .isNotEqualTo(
                        AuthorizationCacheKeys.decisionKey("objects", "digest", "{\"name\":\"certificates\"}", "{}"))
                .isNotEqualTo(
                        AuthorizationCacheKeys.decisionKey("method", "other", "{\"name\":\"certificates\"}", "{}"))
                .isNotEqualTo(AuthorizationCacheKeys.decisionKey("method", "digest", "{\"name\":\"groups\"}", "{}"))
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
