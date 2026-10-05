package com.otilm.core.config.logging;

import com.otilm.core.logging.LogRedaction;
import com.otilm.core.logging.LoggingHelper;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Set;
import org.apache.commons.lang3.builder.ToStringBuilder;
import org.apache.commons.lang3.builder.ToStringStyle;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.lang.Nullable;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

/**
 * Names the source of every request in the MDC and, at TRACE, logs one line when a request arrives and one when its
 * response is done, whether its handler returned or threw. Neither line carries a body, which {@link TraceBodyAdvice}
 * logs, nor a credential a header holds.
 */
@Component
public class RequestResponseInterceptor implements HandlerInterceptor {

    private static final Set<String> SCHEME_CREDENTIAL_HEADERS = Set.of("authorization", "proxy-authorization");
    private static final Set<String> SECRET_HEADERS = Set.of("cookie", "set-cookie", "x-api-key");

    Logger logger = LoggerFactory.getLogger(this.getClass());

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) {
        LoggingHelper.putSourceInfo(request);

        if (logger.isTraceEnabled()) {
            ToStringBuilder traceMessage = new ToStringBuilder(this, ToStringStyle.NO_CLASS_NAME_STYLE)
                    .append("METHOD", request.getMethod())
                    .append("PATH", request.getRequestURI())
                    .append("FROM", request.getRemoteAddr())
                    .append("REQUEST TYPE", request.getContentType())
                    .append("REQUEST HEADERS",
                            Collections
                                    .list(request.getHeaderNames())
                                    .stream()
                                    .map(name -> name + " : " + maskedHeaderValue(name, request.getHeader(name)))
                                    .toList());
            logger.trace("REQUEST DATA: {}", traceMessage);
        }
        return true;
    }

    @Override
    public void afterCompletion(HttpServletRequest request, HttpServletResponse response, Object handler,
            @Nullable Exception ex) {
        if (logger.isTraceEnabled()) {
            List<String> responseHeaders = response
                    .getHeaderNames()
                    .stream()
                    .distinct()
                    .map(name -> name + " : "
                            + response.getHeaders(name).stream().map(value -> maskedHeaderValue(name, value)).toList())
                    .toList();
            ToStringBuilder traceMessage = new ToStringBuilder(this, ToStringStyle.NO_CLASS_NAME_STYLE)
                    .append("METHOD", request.getMethod())
                    .append("RESPONSE FOR", request.getRequestURI())
                    .append("RESPONSE STATUS", response.getStatus())
                    .append("RESPONSE TYPE", response.getContentType())
                    .append("RESPONSE HEADERS", responseHeaders);
            logger.trace("RESPONSE DATA: {}", traceMessage);
        }
    }

    /**
     * A header value as it may be logged: a credential header keeps only its scheme, a header that is a secret as a
     * whole is {@value LogRedaction#REDACTED}, and any other header is logged as it is.
     */
    static String maskedHeaderValue(String name, String value) {
        if (value == null) {
            return null;
        }
        String lowerCaseName = name.toLowerCase(Locale.ROOT);
        if (SCHEME_CREDENTIAL_HEADERS.contains(lowerCaseName)) {
            int schemeEnd = value.indexOf(' ');
            return schemeEnd > 0 ? value.substring(0, schemeEnd) + " " + LogRedaction.REDACTED : LogRedaction.REDACTED;
        }
        return SECRET_HEADERS.contains(lowerCaseName) ? LogRedaction.REDACTED : value;
    }
}
