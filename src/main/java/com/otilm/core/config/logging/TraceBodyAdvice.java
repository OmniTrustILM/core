package com.otilm.core.config.logging;

import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.logging.LogRedaction;
import java.lang.reflect.Type;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.core.MethodParameter;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.AbstractJackson2HttpMessageConverter;
import org.springframework.http.server.ServerHttpRequest;
import org.springframework.http.server.ServerHttpResponse;
import org.springframework.lang.NonNull;
import org.springframework.lang.Nullable;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.servlet.mvc.method.annotation.RequestBodyAdviceAdapter;
import org.springframework.web.servlet.mvc.method.annotation.ResponseBodyAdvice;

/**
 * Logs, at TRACE, the body of every request after Spring has read it and of every response before Spring writes it, as
 * the objects they are: a body read or written by Jackson's JSON converter through {@link LogRedaction#json}, the body
 * of a {@link Sensitive} parameter as {@value LogRedaction#REDACTED}, and any other body as its type and size.
 */
@ControllerAdvice
public class TraceBodyAdvice extends RequestBodyAdviceAdapter implements ResponseBodyAdvice<Object> {

    private static final Logger logger = LoggerFactory.getLogger(TraceBodyAdvice.class);

    @Override
    public boolean supports(@NonNull MethodParameter methodParameter, @NonNull Type targetType,
            @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        return logger.isTraceEnabled();
    }

    @Override
    @NonNull
    public Object afterBodyRead(@NonNull Object body, @NonNull HttpInputMessage inputMessage,
            @NonNull MethodParameter parameter, @NonNull Type targetType,
            @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        if (logger.isTraceEnabled()) {
            logger.trace("REQUEST BODY: {}", requestBody(body, parameter, converterType));
        }
        return body;
    }

    @Override
    public boolean supports(@NonNull MethodParameter returnType,
            @NonNull Class<? extends HttpMessageConverter<?>> converterType) {
        return logger.isTraceEnabled();
    }

    @Override
    public Object beforeBodyWrite(@Nullable Object body, @NonNull MethodParameter returnType,
            @NonNull MediaType selectedContentType,
            @NonNull Class<? extends HttpMessageConverter<?>> selectedConverterType, @NonNull ServerHttpRequest request,
            @NonNull ServerHttpResponse response) {
        if (logger.isTraceEnabled()) {
            logger.trace("RESPONSE BODY: {}", responseBody(body, selectedConverterType));
        }
        return body;
    }

    private static String requestBody(Object body, MethodParameter parameter,
            Class<? extends HttpMessageConverter<?>> converterType) {
        if (parameter.hasParameterAnnotation(Sensitive.class)) {
            return LogRedaction.REDACTED;
        }
        return jsonOrSummary(body, converterType);
    }

    private static String responseBody(Object body, Class<? extends HttpMessageConverter<?>> converterType) {
        return jsonOrSummary(body, converterType);
    }

    /**
     * Core registers no {@code ByteArrayHttpMessageConverter}, so nothing stops a JSON-typed {@code byte[]} or
     * {@link CharSequence} body from reaching a Jackson converter; either would have {@link LogRedaction#json} encode
     * its full content (a reversible base64 string, or the text itself), so both are always summarized instead.
     */
    private static String jsonOrSummary(Object body, Class<? extends HttpMessageConverter<?>> converterType) {
        if (body instanceof byte[] || body instanceof CharSequence) {
            return summary(body);
        }
        return AbstractJackson2HttpMessageConverter.class.isAssignableFrom(converterType)
                ? LogRedaction.json(body)
                : summary(body);
    }

    static String summary(Object body) {
        if (body == null) {
            return "none";
        }
        if (body instanceof byte[] bytes) {
            return "byte[] of %d bytes".formatted(bytes.length);
        }
        if (body instanceof CharSequence text) {
            return "String of %d characters".formatted(text.length());
        }
        if (body instanceof ByteArrayResource resource) {
            return "ByteArrayResource of %d bytes".formatted(resource.contentLength());
        }
        return body.getClass().getSimpleName();
    }
}
