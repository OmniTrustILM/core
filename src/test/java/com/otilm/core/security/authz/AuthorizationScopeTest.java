package com.otilm.core.security.authz;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.core.config.cache.AuthorizationCacheProperties;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.util.PrincipalFixtures;
import jakarta.persistence.EntityManagerFactory;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
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

    PlatformUserDetails administrator = createPrincipal(
            PrincipalFixtures.adminProfile(UUID.randomUUID().toString(), "a"));

    @BeforeEach
    void createScope() {
        scope = createScope(true);
    }

    @Test
    void givesNoGrant_whenTheAuthorizationCacheIsDisabled() {
        // given
        AuthorizationScope uncachedScope = createScope(false);

        // when
        AllResourcesGrant grant = uncachedScope
                .batched(administrator, Resource.CERTIFICATE, List.of(), () -> uncachedScope.grantFor(administrator));

        // then
        assertThat(grant).isEqualTo(AllResourcesGrant.NONE);
    }

    @Test
    void runsASeparateBatch_whenAnotherThreadHoldsOneOpen() throws Exception {
        // given
        CountDownLatch firstBatchOpen = new CountDownLatch(1);
        CountDownLatch secondBatchDone = new CountDownLatch(1);
        CompletableFuture<AssociationReader> firstReader = CompletableFuture
                .supplyAsync(() -> scope.batched(administrator, Resource.CERTIFICATE, List.of(), () -> {
                    firstBatchOpen.countDown();
                    await(secondBatchDone);
                    return scope.associationsFor(administrator);
                }));
        assertThat(firstBatchOpen.await(5, TimeUnit.SECONDS)).isTrue();

        // when
        AssociationReader secondReader;
        boolean secondGranted;
        try {
            secondReader = scope
                    .batched(administrator, Resource.CERTIFICATE, List.of(),
                            () -> scope.associationsFor(administrator));
            secondGranted = scope
                    .batched(administrator, Resource.CERTIFICATE, List.of(),
                            () -> scope.grantFor(administrator).grants(CERTIFICATES));
        } finally {
            secondBatchDone.countDown();
        }

        // then
        assertThat(secondGranted).isTrue();
        assertThat(firstReader.get(5, TimeUnit.SECONDS)).isNotSameAs(secondReader);
    }

    @Test
    void grantsAllResources_whenInsideTheBatchOfAnAllResourcesPrincipal() {
        // given — an administrator allowed all resources, deciding inside their own batch

        // when
        boolean granted = scope
                .batched(administrator, Resource.CERTIFICATE, List.of(),
                        () -> scope.grantFor(administrator).grants(CERTIFICATES));

        // then
        assertThat(granted).isTrue();
    }

    @Test
    void givesNoGrant_whenNoBatchIsActive() {
        // given — no active batch

        // when
        AllResourcesGrant grant = scope.grantFor(administrator);

        // then
        assertThat(grant).isEqualTo(AllResourcesGrant.NONE);
    }

    @Test
    void givesNoGrant_whenAnotherPrincipalDecidesInsideTheBatch() {
        // given
        PlatformUserDetails otherAdministrator = createPrincipal(
                PrincipalFixtures.adminProfile(UUID.randomUUID().toString(), "b"));

        // when
        AllResourcesGrant grant = scope
                .batched(administrator, Resource.CERTIFICATE, List.of(), () -> scope.grantFor(otherAdministrator));

        // then
        assertThat(grant).isEqualTo(AllResourcesGrant.NONE);
    }

    @Test
    void sharesOneAssociationReader_whenAskedTwiceInTheSameBatch() {
        // given — the administrator's batch

        // when
        boolean shared = scope
                .batched(administrator, Resource.CERTIFICATE, List.of(),
                        () -> scope.associationsFor(administrator) == scope.associationsFor(administrator));

        // then
        assertThat(shared).isTrue();
    }

    @Test
    void givesASeparateAssociationReader_whenAnotherPrincipalAsksInsideTheBatch() {
        // given
        PlatformUserDetails operator = createPrincipal(
                PrincipalFixtures.operatorProfile(UUID.randomUUID().toString(), "o"));

        // when
        boolean shared = scope
                .batched(administrator, Resource.CERTIFICATE, List.of(),
                        () -> scope.associationsFor(operator) == scope.associationsFor(administrator));

        // then
        assertThat(shared).isFalse();
    }

    @Test
    void endsTheBatch_whenTheBodyThrows() {
        // given — the administrator's batch, whose body throws

        // when
        ThrowingCallable failingBatch = () -> scope.batched(administrator, Resource.CERTIFICATE, List.of(), () -> {
            throw new IllegalStateException("body failed");
        });

        // then
        assertThatThrownBy(failingBatch).isInstanceOf(IllegalStateException.class).hasMessageContaining("body failed");
        assertThat(scope.grantFor(administrator)).isEqualTo(AllResourcesGrant.NONE);
    }

    @Test
    void refusesToStartABatch_whenAnotherIsActive() {
        // given — the administrator's batch, already active

        // when
        ThrowingCallable nestedBatch = () -> scope
                .batched(administrator, Resource.CERTIFICATE, List.of(),
                        () -> scope.batched(administrator, Resource.CERTIFICATE, List.of(), () -> null));

        // then
        assertThatThrownBy(nestedBatch).isInstanceOf(IllegalStateException.class);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private AuthorizationScope createScope(boolean cacheEnabled) {
        return new AuthorizationScope(entityManagerFactory, new ObjectMapper(),
                new AuthorizationCacheProperties(cacheEnabled, 1, 1, 1));
    }

    private static void await(CountDownLatch latch) {
        try {
            assertThat(latch.await(5, TimeUnit.SECONDS)).isTrue();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException(e);
        }
    }

    private static PlatformUserDetails createPrincipal(UserProfileDto profile) {
        return PrincipalFixtures.authentication(profile).getPrincipal();
    }
}
