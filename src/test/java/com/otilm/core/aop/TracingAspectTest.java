package com.otilm.core.aop;

import com.otilm.api.model.core.logging.Sensitive;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanBuilder;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The aspect records every traced method parameter's value into a span attribute, so a parameter carrying a
 * secret must be masked. This locks in that a {@link Sensitive} parameter is recorded as {@code ***} while an
 * ordinary parameter keeps its value.
 */
class TracingAspectTest {

    @SuppressWarnings("unused") // reflected as the traced-method fixture
    private void sampleMethod(@Sensitive String secret, String visible) {
    }

    @Test
    void sensitiveParameterIsMaskedInSpanAttributes() throws Throwable {
        Span span = mock(Span.class);
        SpanBuilder builder = mock(SpanBuilder.class);
        when(builder.setSpanKind(Mockito.any())).thenReturn(builder);
        when(builder.startSpan()).thenReturn(span);
        when(span.makeCurrent()).thenReturn(mock(Scope.class));
        Tracer tracer = mock(Tracer.class);
        when(tracer.spanBuilder(anyString())).thenReturn(builder);
        OpenTelemetry openTelemetry = mock(OpenTelemetry.class);
        when(openTelemetry.getTracer("application")).thenReturn(tracer);

        Method method = getClass().getDeclaredMethod("sampleMethod", String.class, String.class);
        MethodSignature signature = mock(MethodSignature.class);
        when(signature.getMethod()).thenReturn(method);
        when(signature.getParameterNames()).thenReturn(new String[]{"secret", "visible"});
        ProceedingJoinPoint joinPoint = mock(ProceedingJoinPoint.class);
        when(joinPoint.getSignature()).thenReturn(signature);
        when(joinPoint.getArgs()).thenReturn(new Object[]{"topSecret", "visibleValue"});
        when(joinPoint.proceed()).thenReturn("result");

        Object result = new TracingAspect(openTelemetry).traceMethod(joinPoint);

        assertEquals("result", result);
        verify(span).setAttribute("function.param.secret", "***");
        verify(span).setAttribute("function.param.visible", "visibleValue");
    }
}
