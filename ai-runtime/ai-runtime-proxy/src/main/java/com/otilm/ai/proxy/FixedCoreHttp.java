package com.otilm.ai.proxy;

import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Objects;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import javax.net.ssl.SSLContext;
import org.apache.hc.client5.http.DnsResolver;
import org.apache.hc.client5.http.config.ConnectionConfig;
import org.apache.hc.client5.http.config.RequestConfig;
import org.apache.hc.client5.http.config.TlsConfig;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.client5.http.impl.io.BasicHttpClientConnectionManager;
import org.apache.hc.client5.http.impl.io.DefaultHttpClientConnectionOperator;
import org.apache.hc.client5.http.impl.io.ManagedHttpClientConnectionFactory;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.client5.http.ssl.DefaultHostnameVerifier;
import org.apache.hc.client5.http.ssl.HostnameVerificationPolicy;
import org.apache.hc.client5.http.ssl.TlsSocketStrategy;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.ClassicHttpResponse;
import org.apache.hc.core5.http.HttpException;
import org.apache.hc.core5.http.HttpHeaders;
import org.apache.hc.core5.http.HttpVersion;
import org.apache.hc.core5.http.config.Http1Config;
import org.apache.hc.core5.http.config.RegistryBuilder;
import org.apache.hc.core5.http.impl.io.HttpRequestExecutor;
import org.apache.hc.core5.http.io.HttpClientConnection;
import org.apache.hc.core5.http.io.HttpResponseInformationCallback;
import org.apache.hc.core5.http.io.SocketConfig;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.util.Timeout;

/** One trusted fixed-Core connection. Owning clients supply only their closed routes and bounded bodies. */
public final class FixedCoreHttp {
    private FixedCoreHttp() {
    }

    public static HttpRequestExecutor singleAttemptExecutor() {
        return new SingleAttemptExecutor();
    }

    static Timeout timeout(long remainingNanos) {
        return Timeout.ofMilliseconds(Math.max(1, TimeUnit.NANOSECONDS.toMillis(remainingNanos)));
    }

    /** Fixed Kubernetes API transport entry; the owner still supplies closed resource operations and authority. */
    public static CloseableHttpClient openKubernetes(CoreEndpoint endpoint, SSLContext sslContext,
            long remainingNanos) {
        Objects.requireNonNull(endpoint);
        if (!endpoint.origin().getRawPath().isEmpty()) {
            throw new IllegalArgumentException("CORE_UNAVAILABLE");
        }
        return open(endpoint, sslContext, remainingNanos, true);
    }

    public static CloseableHttpClient open(CoreEndpoint endpoint, SSLContext sslContext, long remainingNanos) {
        return open(endpoint, sslContext, remainingNanos, false);
    }

    private static CloseableHttpClient open(CoreEndpoint endpoint, SSLContext sslContext, long remainingNanos,
            boolean kubernetesPaths) {
        Objects.requireNonNull(endpoint);
        Objects.requireNonNull(sslContext);
        if (remainingNanos <= 0) {
            throw new IllegalArgumentException("CORE_UNAVAILABLE");
        }
        Timeout timeout = timeout(remainingNanos);
        var http1 = Http1Config
                .custom()
                .setVersion(HttpVersion.HTTP_1_1)
                .setMaxHeaderCount(32)
                .setMaxLineLength(1024)
                .setMaxEmptyLineCount(1)
                .setBufferSize(4096)
                .build();
        var tls = ClientTlsStrategyBuilder
                .create()
                .setSslContext(sslContext)
                .setTlsVersions("TLSv1.3")
                .setHostVerificationPolicy(HostnameVerificationPolicy.BOTH)
                .setHostnameVerifier(new DefaultHostnameVerifier())
                .buildClassic();
        var operator = new DefaultHttpClientConnectionOperator(ignored -> new java.net.Socket(java.net.Proxy.NO_PROXY),
                null, new FixedAddress(endpoint),
                RegistryBuilder.<TlsSocketStrategy>create().register("https", tls).build());
        var manager = new BasicHttpClientConnectionManager(operator,
                ManagedHttpClientConnectionFactory.builder().http1Config(http1).build());
        manager
                .setConnectionConfig(
                        ConnectionConfig.custom().setConnectTimeout(timeout).setSocketTimeout(timeout).build());
        manager.setSocketConfig(SocketConfig.custom().setSoTimeout(timeout).build());
        manager.setTlsConfig(TlsConfig.custom().setHandshakeTimeout(timeout).setSupportedProtocols("TLSv1.3").build());
        var requestConfig = RequestConfig
                .custom()
                .setAuthenticationEnabled(false)
                .setRedirectsEnabled(false)
                .setContentCompressionEnabled(false)
                .setProtocolUpgradeEnabled(false)
                .setExpectContinueEnabled(false)
                .setConnectionRequestTimeout(timeout)
                .setResponseTimeout(timeout)
                .setHardCancellationEnabled(true)
                .build();
        return HttpClients.custom().addExecInterceptorFirst("fixed-core-destination", (request, scope, chain) -> {
            requireFixedDestination(endpoint, kubernetesPaths, request, scope.originalRequest);
            return chain.proceed(request, scope);
        })
                .setConnectionManager(manager)
                .setRequestExecutor(new SingleAttemptExecutor())
                .setRoutePlanner((target, context) -> pinnedRoute(endpoint, requestConfig, target, context))
                .setConnectionReuseStrategy((request, response, context) -> false)
                .disableAutomaticRetries()
                .disableRedirectHandling()
                .disableCookieManagement()
                .disableContentCompression()
                .disableAuthCaching()
                .disableConnectionState()
                .disableDefaultUserAgent()
                .setDefaultRequestConfig(requestConfig)
                .build();
    }

    private record FixedAddress(CoreEndpoint endpoint) implements DnsResolver {
        @Override
        public InetAddress[] resolve(String host) throws UnknownHostException {
            if (!endpoint.origin().getHost().equalsIgnoreCase(host)) {
                throw new UnknownHostException("DESTINATION");
            }
            return new InetAddress[]{endpoint.address()};
        }

        @Override
        public String resolveCanonicalHostname(String host) throws UnknownHostException {
            resolve(host);
            return endpoint.origin().getHost();
        }
    }

    private static void requireFixedDestination(CoreEndpoint endpoint, boolean kubernetesPaths,
            ClassicHttpRequest request, ClassicHttpRequest originalRequest) throws HttpException {
        try {
            var uri = request.getUri();
            var original = originalRequest.getUri();
            var authority = request.getAuthority();
            int expectedPort = endpoint.origin().getPort() < 0 ? 443 : endpoint.origin().getPort();
            String path = uri.getRawPath();
            if (!"https".equalsIgnoreCase(request.getScheme()) || authority == null || authority.getUserInfo() != null
                    || !endpoint.origin().getHost().equalsIgnoreCase(authority.getHostName())
                    || (authority.getPort() < 0 ? 443 : authority.getPort()) != expectedPort
                    || request.containsHeader(HttpHeaders.HOST)
                    || (originalRequest instanceof org.apache.hc.client5.http.config.Configurable configured
                            && configured.getConfig() != null)
                    || original.getRawQuery() != null || original.getRawFragment() != null || uri.getRawQuery() != null
                    || uri.getRawFragment() != null || !path.startsWith(endpoint.origin().getRawPath() + "/")
                    || !path
                            .matches(kubernetesPaths
                                    ? "(?:/[A-Za-z0-9_-]++(?:\\.[A-Za-z0-9_-]++)*+)++"
                                    : "(?:/[A-Za-z0-9_-]++)++")) {
                throw new HttpException("DESTINATION");
            }
        } catch (java.net.URISyntaxException invalid) {
            throw new HttpException("DESTINATION");
        }
    }

    private static org.apache.hc.client5.http.HttpRoute pinnedRoute(CoreEndpoint endpoint, RequestConfig requestConfig,
            org.apache.hc.core5.http.HttpHost target, HttpContext context) throws HttpException {
        int expectedPort = endpoint.origin().getPort() < 0 ? 443 : endpoint.origin().getPort();
        int actualPort = target.getPort() < 0 ? 443 : target.getPort();
        if (!"https".equalsIgnoreCase(target.getSchemeName())
                || !endpoint.origin().getHost().equalsIgnoreCase(target.getHostName()) || expectedPort != actualPort
                || (target.getAddress() != null && !endpoint.address().equals(target.getAddress()))) {
            throw new HttpException("DESTINATION");
        }
        org.apache.hc.client5.http.protocol.HttpClientContext.cast(context).setRequestConfig(requestConfig);
        return new org.apache.hc.client5.http.HttpRoute(new org.apache.hc.core5.http.HttpHost("https",
                endpoint.address(), endpoint.origin().getHost(), expectedPort), (InetAddress) null, true);
    }

    /** Runs before HttpRequestExecutor writes any headers or body, including library follow-ups. */
    private static final class SingleAttemptExecutor extends HttpRequestExecutor {
        private final AtomicBoolean attempted = new AtomicBoolean();

        @Override
        public ClassicHttpResponse execute(ClassicHttpRequest request, HttpClientConnection connection,
                HttpResponseInformationCallback information, HttpContext context) throws IOException, HttpException {
            if (!attempted.compareAndSet(false, true)) {
                throw new IOException("ATTEMPT_LIMIT");
            }
            return super.execute(request, connection, (response, current, currentContext) -> {
                if (response.getCode() == 101) {
                    throw new HttpException("UPGRADE_DISABLED");
                }
                if (information != null) {
                    information.execute(response, current, currentContext);
                }
            }, context);
        }
    }
}
