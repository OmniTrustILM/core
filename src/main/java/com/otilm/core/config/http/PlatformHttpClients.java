package com.otilm.core.config.http;

import org.apache.hc.client5.http.impl.DefaultHttpRequestRetryStrategy;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.TimeValue;
import org.apache.hc.core5.util.Timeout;
import org.springframework.boot.http.client.ClientHttpRequestFactoryBuilder;
import org.springframework.boot.http.client.HttpComponentsClientHttpRequestFactoryBuilder;

/**
 * Request factories for the platform's blocking {@code RestClient}s.
 * <p>
 * Apache HttpClient's own defaults are unsuitable for a client held for the lifetime of the process, and
 * {@link ClientHttpRequestFactoryBuilder#detect()} passes them straight through, so every consumer builds from here
 * instead of from the plain builder.
 */
public final class PlatformHttpClients {

    /**
     * Upper bound on connections a single client may hold, per endpoint and in total. Apache's defaults of 5 per route
     * and 25 overall throttle callers well below what the server itself allows — it runs on virtual threads, so request
     * concurrency is not otherwise capped.
     */
    public static final int MAX_CONNECTIONS = 100;

    /**
     * How long a caller waits for a connection from the pool before giving up. Apache's default is three minutes, so a
     * peer that stops responding would not merely block its own callers — it would park every later caller for three
     * minutes behind an exhausted pool.
     */
    private static final Timeout CONNECTION_LEASE_TIMEOUT = Timeout.ofSeconds(5);

    private PlatformHttpClients() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * A builder whose client pools generously, keeps no cookies, and never retries on a status code.
     * <p>
     * Cookies are off because one jar would be shared by every caller in the process, replaying one user's session
     * cookie onto everyone else's requests. Status-code retries are off because Apache honours a {@code Retry-After}
     * header verbatim, which lets a degraded peer decide how long our threads block; the retry after an I/O error is
     * kept, as that is what recovers a pooled connection the peer closed concurrently.
     * <p>
     * Proxy support needs no wiring here: the builder already resolves routes through the JVM default
     * {@code ProxySelector} and answers proxy challenges from the default {@link java.net.Authenticator}, both of which
     * {@code ProxyConfiguration} populates.
     * <p>
     * Connect and read timeouts are deliberately left to each consumer's
     * {@link org.springframework.boot.http.client.HttpClientSettings}: Boot applies the connection-config customizer
     * <em>after</em> mapping those settings, so setting them here would silently overwrite what a consumer passed to
     * {@code build(settings)}. Only the lease timeout, which no setting maps to, is fixed for everyone.
     */
    public static HttpComponentsClientHttpRequestFactoryBuilder requestFactoryBuilder() {
        return ClientHttpRequestFactoryBuilder
                .httpComponents()
                .withConnectionManagerCustomizer(connectionManager -> connectionManager
                        .setMaxConnTotal(MAX_CONNECTIONS)
                        .setMaxConnPerRoute(MAX_CONNECTIONS))
                .withDefaultRequestConfigCustomizer(
                        requestConfig -> requestConfig.setConnectionRequestTimeout(CONNECTION_LEASE_TIMEOUT))
                .withHttpClientCustomizer(httpClient -> httpClient
                        .disableCookieManagement()
                        .setRetryStrategy(new IdempotentIoErrorRetryStrategy()));
    }

    /**
     * Retries an idempotent request once when the connection failed, and never because of the status the peer returned
     * — the response-driven branch is what honours {@code Retry-After}.
     */
    private static final class IdempotentIoErrorRetryStrategy extends DefaultHttpRequestRetryStrategy {

        private IdempotentIoErrorRetryStrategy() {
            super(1, TimeValue.ZERO_MILLISECONDS);
        }

        @Override
        public boolean retryRequest(HttpResponse response, int execCount, HttpContext context) {
            return false;
        }
    }
}
