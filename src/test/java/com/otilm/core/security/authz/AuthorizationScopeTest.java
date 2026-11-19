package com.otilm.core.security.authz;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.util.PrincipalFixtures;
import jakarta.persistence.EntityManagerFactory;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@ExtendWith(MockitoExtension.class)
class AuthorizationScopeTest {

    private static final String CERTIFICATES = Resource.CERTIFICATE.getCode();

    @Mock
    EntityManagerFactory entityManagerFactory;

    AuthorizationScope scope;

    PlatformUserDetails administrator = principal(PrincipalFixtures.adminProfile(UUID.randomUUID().toString(), "a"));

    @BeforeEach
    void createScope() {
        scope = new AuthorizationScope(entityManagerFactory, new ObjectMapper());
    }

    @Test
    void grantsAllResources_insideTheBatchOfAnAllResourcesPrincipal() {
        // when
        boolean granted = scope
                .batched(administrator, Resource.CERTIFICATE, List.of(),
                        () -> scope.grantFor(administrator).grants(CERTIFICATES));

        // then
        assertThat(granted).isTrue();
    }

    @Test
    void givesNoGrant_outsideABatch() {
        // when
        AllResourcesGrant grant = scope.grantFor(administrator);

        // then
        assertThat(grant).isEqualTo(AllResourcesGrant.NONE);
    }

    @Test
    void givesNoGrant_whenAnotherPrincipalDecidesInsideTheBatch() {
        // given
        PlatformUserDetails otherAdministrator = principal(
                PrincipalFixtures.adminProfile(UUID.randomUUID().toString(), "b"));

        // when
        AllResourcesGrant grant = scope
                .batched(administrator, Resource.CERTIFICATE, List.of(), () -> scope.grantFor(otherAdministrator));

        // then
        assertThat(grant).isEqualTo(AllResourcesGrant.NONE);
    }

    @Test
    void sharesOneAssociationReader_acrossTheBatch() {
        // when
        boolean shared = scope
                .batched(administrator, Resource.CERTIFICATE, List.of(),
                        () -> scope.associationsFor(administrator) == scope.associationsFor(administrator));

        // then
        assertThat(shared).isTrue();
    }

    @Test
    void keepsAnotherPrincipalOffTheBatchsAssociationReader() {
        // given
        PlatformUserDetails operator = principal(PrincipalFixtures.operatorProfile(UUID.randomUUID().toString(), "o"));

        // when
        boolean shared = scope
                .batched(administrator, Resource.CERTIFICATE, List.of(),
                        () -> scope.associationsFor(operator) == scope.associationsFor(administrator));

        // then
        assertThat(shared).isFalse();
    }

    @Test
    void endsTheBatch_whenTheBodyThrows() {
        // given
        ThrowingCallable failingBatch = () -> scope.batched(administrator, Resource.CERTIFICATE, List.of(), () -> {
            throw new IllegalStateException("body failed");
        });
        assertThatThrownBy(failingBatch).isInstanceOf(IllegalStateException.class).hasMessage("body failed");

        // when
        AllResourcesGrant grant = scope.grantFor(administrator);

        // then
        assertThat(grant).isEqualTo(AllResourcesGrant.NONE);
    }

    @Test
    void refusesToStartABatchInsideAnother() {
        // when
        ThrowingCallable nestedBatch = () -> scope
                .batched(administrator, Resource.CERTIFICATE, List.of(),
                        () -> scope.batched(administrator, Resource.CERTIFICATE, List.of(), () -> null));

        // then
        assertThatThrownBy(nestedBatch).isInstanceOf(IllegalStateException.class);
    }

    private static PlatformUserDetails principal(UserProfileDto profile) {
        return PrincipalFixtures.authentication(profile).getPrincipal();
    }
}
