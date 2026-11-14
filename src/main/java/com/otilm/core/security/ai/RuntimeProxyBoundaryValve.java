package com.otilm.core.security.ai;

import jakarta.servlet.ServletException;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.IdentityHashMap;
import java.util.Map;
import java.util.UUID;
import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Engine;
import org.apache.catalina.Globals;
import org.apache.catalina.connector.Connector;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.valves.ValveBase;
import org.apache.coyote.ActionCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

final class RuntimeProxyBoundaryValve extends ValveBase {
    private static final Logger LOG = LoggerFactory.getLogger(RuntimeProxyBoundaryValve.class);
    private final Map<Connector, Channel> channels;
    private final String runtimePrefix;
    private final String managementPrefix;
    private volatile Context guardedContext;
    private volatile boolean disabled;

    RuntimeProxyBoundaryValve(Map<Connector, Channel> channels, String contextPath) {
        super(true);
        this.channels = Collections.unmodifiableMap(new IdentityHashMap<>(channels));
        runtimePrefix = contextPath + "/internal/ai-runtime";
        managementPrefix = contextPath + "/internal/ai-management";
    }

    @Override
    public void invoke(Request request, Response response) throws IOException, ServletException {
        RuntimeProxyTransport.clear();
        Channel channel = channels.get(request.getConnector());
        RuntimeProxyTransport.markChannel(request, channel != null);
        try {
            String raw = request.getCoyoteRequest().requestURI().toString();
            String decoded = request.getDecodedRequestURI();
            if (channel == null) {
                if (reserved(raw) || reserved(decoded)) {
                    deny(response);
                    return;
                }
            } else {
                request.setAsyncSupported(false);
                if (disabled || guardedContext == null || request.getContext() != guardedContext
                        || !channel.permits(raw, request.getMethod()) || !request.isSecure() || !raw.equals(decoded)
                        || request.getQueryString() != null) {
                    deny(response);
                    return;
                }
                var nativeRequest = request.getCoyoteRequest();
                nativeRequest.action(ActionCode.REQ_SSL_ATTRIBUTE, null);
                Object presented = nativeRequest.getAttribute(Globals.CERTIFICATES_ATTR);
                if (!(presented instanceof X509Certificate[] certificates)) {
                    deny(response);
                    return;
                }
                try {
                    RuntimePeer peer = channel.trust().verifyWorkloadNativeChain(certificates);
                    if (peer.role() != channel.role()) {
                        deny(response);
                        return;
                    }
                    RuntimeProxyTransport.enter(peer);
                } catch (CertificateException rejected) {
                    deny(response);
                    return;
                }
            }
            getNext().invoke(request, response);
        } finally {
            RuntimeProxyTransport.clear();
        }
    }

    record Channel(RuntimePeerRole role, RuntimeProxyTrustManager trust, Map<String, String> routes) {
        Channel {
            routes = Map.copyOf(routes);
        }

        boolean permits(String path, String method) {
            String expected = routes.get(path);
            return expected != null && expected.equals(method);
        }
    }

    boolean installedFor(Context context) {
        Engine engine = owningEngine();
        for (Container current = context; current != null; current = current.getParent()) {
            if (current == engine) {
                return true;
            }
        }
        return false;
    }

    boolean installedFor(Connector connector) {
        Engine engine = owningEngine();
        return engine != null && connector.getService() != null && engine.getService() == connector.getService();
    }

    private Engine owningEngine() {
        if (getContainer() instanceof Engine engine) {
            for (var valve : engine.getPipeline().getValves()) {
                if (valve == this) {
                    return engine;
                }
            }
        }
        return null;
    }

    boolean reserved(String path) {
        return path != null && (path.startsWith(runtimePrefix) || path.startsWith(managementPrefix));
    }

    boolean guardInstalled() {
        return guardedContext != null;
    }

    void disable() {
        disabled = true;
    }

    boolean disabled() {
        return disabled;
    }

    void bindGuard(Context context) {
        guardedContext = context;
    }

    static void deny(jakarta.servlet.http.HttpServletResponse response) throws IOException {
        UUID correlation = UUID.randomUUID();
        LOG.debug("AI runtime transport operation=request status=denied correlationId={}", correlation);
        byte[] body = ("{\"protocolVersion\":1,\"code\":\"DENIED\",\"correlationId\":\"" + correlation + "\"}")
                .getBytes(StandardCharsets.UTF_8);
        response.setStatus(403);
        response.setContentType("application/json");
        response.setHeader("Cache-Control", "no-store");
        response.setContentLength(body.length);
        response.getOutputStream().write(body);
    }
}
