package com.otilm.core.config.cache;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class CacheConfigTest {

    private static final AuthCacheProperties AUTHENTICATION_TTL_5 = new AuthCacheProperties(5, 500);

    @Test
    void disabledAuthorizationCacheNeverWarnsAboutItsTtl() {
        AuthorizationCacheProperties disabledWithLongTtl = new AuthorizationCacheProperties(false, 60, 10, 10);

        assertThat(CacheConfig.authorizationTtlExceedsAuthenticationTtl(AUTHENTICATION_TTL_5, disabledWithLongTtl))
                .isFalse();
    }

    @Test
    void enabledAuthorizationCacheWarnsOnlyWhenItsTtlExceedsTheAuthenticationTtl() {
        AuthorizationCacheProperties longer = new AuthorizationCacheProperties(true, 6, 10, 10);
        AuthorizationCacheProperties equal = new AuthorizationCacheProperties(true, 5, 10, 10);

        assertThat(CacheConfig.authorizationTtlExceedsAuthenticationTtl(AUTHENTICATION_TTL_5, longer)).isTrue();
        assertThat(CacheConfig.authorizationTtlExceedsAuthenticationTtl(AUTHENTICATION_TTL_5, equal)).isFalse();
    }
}
