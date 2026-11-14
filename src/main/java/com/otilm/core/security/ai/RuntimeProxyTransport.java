package com.otilm.core.security.ai;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.GeneralSecurityException;
import java.util.Collections;
import java.util.EnumMap;
import java.util.HashSet;
import java.util.IdentityHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import javax.net.ssl.X509ExtendedKeyManager;
import org.apache.catalina.Context;
import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleState;
import org.apache.catalina.Valve;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.Http11NioProtocol;
import org.apache.tomcat.util.descriptor.web.ErrorPage;
import org.apache.tomcat.util.descriptor.web.FilterDef;
import org.apache.tomcat.util.descriptor.web.FilterMap;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.apache.tomcat.util.net.SSLHostConfigCertificate;
import org.apache.tomcat.util.net.jsse.JSSEImplementation;

/** Dedicated Core listeners; each physical connector binds one fixed authenticated caller role. */
public final class RuntimeProxyTransport {
    private static final ThreadLocal<RuntimePeer> PEER = new ThreadLocal<>();
    private static final String CHANNEL_ATTRIBUTE = RuntimeProxyTransport.class.getName() + ".channel";
    private static final Object RUNTIME_CHANNEL = new Object();
    private final Map<RuntimePeerRole, Connector> connectors;
    private final RuntimeProxyBoundaryValve boundary;
    private final String contextPath;

    public RuntimeProxyTransport(InetAddress address, int port, String contextPath, X509ExtendedKeyManager keys,
            RuntimeProxyTrustManager trust) throws GeneralSecurityException {
        this(contextPath, List.of(new Listener(RuntimePeerRole.RUNNER_PROXY, address, port, keys, trust)));
    }

    private RuntimeProxyTransport(String contextPath, List<Listener> listeners) throws GeneralSecurityException {
        if (contextPath == null || contextPath.length() > 128 || !contextPath.matches("(?:/[A-Za-z0-9_-]++)*+")
                || listeners == null || listeners.isEmpty() || listeners.size() > RuntimePeerRole.values().length) {
            throw new IllegalArgumentException("Invalid runtime transport configuration");
        }
        this.contextPath = contextPath;
        var configurations = new EnumMap<RuntimePeerRole, Listener>(RuntimePeerRole.class);
        var addresses = new HashSet<InetSocketAddress>();
        for (Listener listener : List.copyOf(listeners)) {
            if (listener.port() != 0 && !addresses.add(new InetSocketAddress(listener.address(), listener.port()))) {
                throw new IllegalArgumentException("Duplicate runtime listener address");
            }
            if (configurations.put(listener.role(), listener) != null) {
                throw new IllegalArgumentException("Duplicate runtime listener role");
            }
        }
        var created = new EnumMap<RuntimePeerRole, Connector>(RuntimePeerRole.class);
        var channels = new IdentityHashMap<Connector, RuntimeProxyBoundaryValve.Channel>();
        for (Listener listener : configurations.values()) {
            Connector connector = createConnector(listener);
            created.put(listener.role(), connector);
            channels
                    .put(connector, new RuntimeProxyBoundaryValve.Channel(listener.role(), listener.trust(),
                            CoreRuntimeRoutes.forRole(listener.role(), contextPath)));
        }
        connectors = Collections.unmodifiableMap(created);
        boundary = new RuntimeProxyBoundaryValve(channels, contextPath);
        for (Connector connector : created.values()) {
            connector.addLifecycleListener(event -> {
                if ((Lifecycle.BEFORE_INIT_EVENT.equals(event.getType())
                        || Lifecycle.BEFORE_START_EVENT.equals(event.getType())) && !boundary.installedFor(connector)) {
                    throw new IllegalStateException("Runtime boundary must be installed on the owning engine");
                }
            });
        }
    }

    public static RuntimeProxyTransport forListeners(String contextPath, List<Listener> listeners)
            throws GeneralSecurityException {
        return new RuntimeProxyTransport(contextPath, listeners);
    }

    public Map<RuntimePeerRole, Connector> connectors() {
        return connectors;
    }

    public Connector connector() {
        if (connectors.size() != 1 || !connectors.containsKey(RuntimePeerRole.RUNNER_PROXY)) {
            throw new IllegalStateException("A single runner listener is required");
        }
        return connectors.get(RuntimePeerRole.RUNNER_PROXY);
    }

    public Valve boundary() {
        return boundary;
    }

    /** Denies subsequent native requests permanently for this transport instance. */
    public void disable() {
        boundary.disable();
    }

    boolean disabled() {
        return boundary.disabled();
    }

    private static Connector createConnector(Listener listener) throws GeneralSecurityException {
        var connector = new Connector(Http11NioProtocol.class.getName());
        connector.setPort(listener.port());
        connector.setScheme("https");
        connector.setSecure(true);
        var protocol = (Http11NioProtocol) connector.getProtocolHandler();
        protocol.setAddress(listener.address());
        protocol.setSSLEnabled(true);
        protocol.setSslImplementationName(JSSEImplementation.class.getName());
        protocol.setMaxThreads(16);
        protocol.setMaxConnections(64);
        protocol.setConnectionTimeout(5000);
        protocol.setDisableUploadTimeout(false);
        protocol.setConnectionUploadTimeout(1000);
        protocol.setKeepAliveTimeout(5000);
        protocol.setMaxHttpRequestHeaderSize(8192);
        protocol.setMaxSwallowSize(0);
        var host = new SSLHostConfig();
        host.setProtocols("TLSv1.3");
        host.setCertificateVerification("required");
        var certificate = new SSLHostConfigCertificate(host, SSLHostConfigCertificate.Type.UNDEFINED);
        certificate.setCertificateKeyManager(listener.keys());
        certificate.setSslContext(new RuntimeProxyTlsContext(listener.keys(), listener.trust()));
        host.addCertificate(certificate);
        connector.addSslHostConfig(host);
        return connector;
    }

    /**
     * Requires the owning Engine boundary and registers the servlet guard before context startup. Discard the context
     * after a registration failure; partial registration cannot be retried.
     */
    public synchronized void installDispatchGuard(Context context) {
        String name = RuntimeProxyDispatchFilter.class.getName();
        if ((context.getState() != LifecycleState.NEW && context.getState() != LifecycleState.INITIALIZED)
                || !contextPath.equals(context.getPath()) || context.findFilterDef(name) != null
                || boundary.guardInstalled() || !boundary.installedFor(context)) {
            throw new IllegalArgumentException("Invalid runtime dispatch guard installation");
        }
        var definition = new FilterDef();
        definition.setFilterName(name);
        definition.setFilter(new RuntimeProxyDispatchFilter(boundary));
        definition.setAsyncSupported("true");
        context.addFilterDef(definition);
        var mapping = new FilterMap();
        mapping.setFilterName(name);
        mapping.addURLPattern("/*");
        mapping.addServletName("*");
        for (var dispatcher : jakarta.servlet.DispatcherType.values()) {
            mapping.setDispatcher(dispatcher.name());
        }
        context.addFilterMapBefore(mapping);
        if (context.findFilterMaps()[0] != mapping) {
            throw new IllegalArgumentException("Runtime dispatch guard must be registered first");
        }
        if (context.findErrorPage(0) == null) {
            var error = new ErrorPage();
            error.setErrorCode(0);
            error.setLocation("/error");
            context.addErrorPage(error);
        }
        boundary.bindGuard(context);
    }

    /** Runner-only compatibility view; other authenticated roles cannot be projected through it. */
    public static Optional<RuntimeProxyCertificateClaims> currentPeer() {
        return currentWorkloadPeer()
                .filter(peer -> peer.role() == RuntimePeerRole.RUNNER_PROXY)
                .map(RuntimePeer::subject);
    }

    /** Present only during synchronous processing on the matching authenticated physical connector. */
    public static Optional<RuntimePeer> currentWorkloadPeer() {
        return Optional.ofNullable(PEER.get());
    }

    static void enter(RuntimeProxyCertificateClaims peer) {
        enter(new RuntimePeer(RuntimePeerRole.RUNNER_PROXY, peer));
    }

    static void enter(RuntimePeer peer) {
        PEER.set(Objects.requireNonNull(peer));
    }

    static void clear() {
        PEER.remove();
    }

    static void markChannel(jakarta.servlet.ServletRequest request, boolean runtime) {
        if (runtime) {
            request.setAttribute(CHANNEL_ATTRIBUTE, RUNTIME_CHANNEL);
        } else {
            request.removeAttribute(CHANNEL_ATTRIBUTE);
        }
    }

    static boolean runtimeChannel(jakarta.servlet.ServletRequest request) {
        return request.getAttribute(CHANNEL_ATTRIBUTE) == RUNTIME_CHANNEL;
    }

    public record Listener(RuntimePeerRole role, InetAddress address, int port, X509ExtendedKeyManager keys,
            RuntimeProxyTrustManager trust) {
        public Listener {
            Objects.requireNonNull(role);
            Objects.requireNonNull(address);
            Objects.requireNonNull(keys);
            Objects.requireNonNull(trust);
            if (port < 0 || port > 65535 || role != trust.expectedRole()) {
                throw new IllegalArgumentException("Invalid runtime listener configuration");
            }
        }
    }
}
