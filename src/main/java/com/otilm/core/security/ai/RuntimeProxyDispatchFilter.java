package com.otilm.core.security.ai;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.RequestDispatcher;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.apache.catalina.Globals;

final class RuntimeProxyDispatchFilter implements Filter {
    private final RuntimeProxyBoundaryValve boundary;

    RuntimeProxyDispatchFilter(RuntimeProxyBoundaryValve boundary) {
        this.boundary = boundary;
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        if (!(request instanceof HttpServletRequest http) || !(response instanceof HttpServletResponse reply)) {
            throw new ServletException("Runtime transport requires HTTP");
        }
        boolean runtime = RuntimeProxyTransport.runtimeChannel(request);
        String target = http.getRequestURI();
        String context = http.getContextPath();
        String servlet = http.getServletPath();
        String pathInfo = http.getPathInfo();
        if (http.getDispatcherType() == DispatcherType.INCLUDE) {
            target = attribute(http, RequestDispatcher.INCLUDE_REQUEST_URI);
            context = attribute(http, RequestDispatcher.INCLUDE_CONTEXT_PATH);
            servlet = attribute(http, RequestDispatcher.INCLUDE_SERVLET_PATH);
            pathInfo = attribute(http, RequestDispatcher.INCLUDE_PATH_INFO);
        }
        String suffix = pathInfo == null ? "" : pathInfo;
        String mapped = context == null || servlet == null ? null : context + servlet + suffix;
        boolean named = (http.getDispatcherType() == DispatcherType.FORWARD
                || http.getDispatcherType() == DispatcherType.INCLUDE)
                && http.getAttribute(Globals.DISPATCHER_REQUEST_PATH_ATTR) == null;
        boolean denied = runtime
                ? http.getDispatcherType() != DispatcherType.REQUEST
                        || RuntimeProxyTransport.currentWorkloadPeer().isEmpty()
                : named || target == null || mapped == null || boundary.reserved(target) || boundary.reserved(mapped);
        if (denied) {
            if (http.getDispatcherType() == DispatcherType.INCLUDE) {
                throw new ServletException("Runtime transport dispatch rejected");
            }
            RuntimeProxyBoundaryValve.deny(reply);
            return;
        }
        chain.doFilter(request, response);
    }

    private static String attribute(HttpServletRequest request, String name) {
        Object value = request.getAttribute(name);
        return value instanceof String text ? text : null;
    }
}
