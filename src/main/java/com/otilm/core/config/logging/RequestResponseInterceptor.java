package com.otilm.core.config.logging;

import com.otilm.core.config.CustomHttpServletResponseWrapper;
import com.otilm.core.logging.LoggingHelper;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MDC;
import org.springframework.http.HttpMethod;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;
import org.springframework.web.servlet.ModelAndView;

import java.io.IOException;
import java.io.InputStreamReader;
import java.io.Reader;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class RequestResponseInterceptor implements HandlerInterceptor {

    Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler)
            throws Exception {
        LoggingHelper.putSourceInfo(request);

        if (logger.isTraceEnabled()) {
            String body = servletInputStreamToString(request.getInputStream());
            ToStringBuilder traceMessage = new ToStringBuilder(this, ToStringStyle.NO_CLASS_NAME_STYLE)
                    .append("METHOD", request.getMethod())
                    .append("PATH", request.getRequestURI())
                    .append("FROM", request.getRemoteAddr())
                    .append("REQUEST TYPE", request.getContentType())
                    .append("REQUEST HEADERS", Collections.list(request.getHeaderNames()).stream()
                            .map(r -> r + " : " + request.getHeader(r)).collect(Collectors.toList()));
            if (!request.getMethod().equals(HttpMethod.GET.name())) {
                traceMessage.append("REQUEST BODY", body);
            }
            logger.trace("REQUEST DATA: {}", traceMessage);
        }
        return true;
    }

    @Override
    public void postHandle(HttpServletRequest request, HttpServletResponse response, Object handler,
                           @Nullable ModelAndView modelAndView) throws Exception {
        MDC.clear();
        if (logger.isTraceEnabled()) {
            String responseBody;
            try {
                responseBody = getResponseAsString((CustomHttpServletResponseWrapper) response);
            } catch (ClassCastException e) {
                responseBody = "";
            }
            List<String> responseHeaders = response.getHeaderNames().stream()
                    .map(r -> r + " : " + response.getHeaders(r)).collect(Collectors.toList());
            ToStringBuilder traceMessage = new ToStringBuilder(this, ToStringStyle.NO_CLASS_NAME_STYLE)
                    .append("METHOD", request.getMethod())
                    .append("RESPONSE FOR", request.getRequestURI())
                    .append("RESPONSE STATUS", response.getStatus())
                    .append("RESPONSE TYPE", response.getContentType())
                    .append("RESPONSE HEADERS", responseHeaders)
                    .append("RESPONSE BODY", responseBody);
            logger.trace("RESPONSE DATA: {}", traceMessage);
        }
    }

    public String getResponseAsString(CustomHttpServletResponseWrapper wrappedResponse) {
        byte[] data = new byte[wrappedResponse.rawData.size()];
        for (int i = 0; i < data.length; i++) {
            data[i] = wrappedResponse.rawData.get(i);
        }
        String responseBody = new String(data);
        return responseBody;
    }

    private String servletInputStreamToString(ServletInputStream stream) throws IOException {
        int bufferSize = 1024;
        char[] buffer = new char[bufferSize];
        StringBuilder out = new StringBuilder();
        Reader in = new InputStreamReader(stream, StandardCharsets.UTF_8);
        for (int numRead; (numRead = in.read(buffer, 0, buffer.length)) > 0; ) {
            out.append(buffer, 0, numRead);
        }
        return out.toString();
    }
}
