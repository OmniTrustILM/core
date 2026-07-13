package com.otilm.core.aop;

import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import com.otilm.api.model.core.logging.Sensitive;
import io.opentelemetry.context.Scope;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;
import java.lang.reflect.Parameter;

@Aspect
@Component
@ConditionalOnExpression(
        "!${otel.sdk.disabled:true} && '${otel.traces.exporter:none}' != 'none'"
)
public class TracingAspect {

    private final Tracer tracer;

    public TracingAspect(OpenTelemetry openTelemetry) {
        this.tracer = openTelemetry.getTracer("application");
    }

    // only trace public methods in classes annotated with @Service
    @Around("execution(public * (@org.springframework.stereotype.Service *).*(..))")
    public Object traceMethod(ProceedingJoinPoint joinPoint) throws Throwable {
        MethodSignature signature = (MethodSignature) joinPoint.getSignature();
        Method method = signature.getMethod();

        // Get class name and method name
        String className = method.getDeclaringClass().getSimpleName();
        String methodName = method.getName();

        // Concatenate class name and method name for the span name
        String spanName = className + "." + methodName;

        Span span = tracer.spanBuilder(spanName)
                .setSpanKind(SpanKind.INTERNAL)
                .startSpan();

        // Add class name and method name as span attributes
        span.setAttribute("code.namespace", method.getDeclaringClass().getName());
        span.setAttribute("code.function", methodName);

        try (Scope ignored = span.makeCurrent()) {
            Object result = joinPoint.proceed();

            String[] parameterNames = signature.getParameterNames();
            Object[] parameterValues = joinPoint.getArgs();
            Parameter[] parameters = method.getParameters();

            // Add method parameters as span attributes. parameterNames is null when names are unavailable, and
            // the three arrays can differ in length; only iterate the range all of them cover.
            if (parameterNames != null) {
                int count = Math.min(parameterNames.length, Math.min(parameterValues.length, parameters.length));
                for (int i = 0; i < count; i++) {
                    String paramName = parameterNames[i];
                    // A @Sensitive parameter (e.g. a raw secret) must never be recorded verbatim into a span.
                    if (parameters[i].isAnnotationPresent(Sensitive.class)) {
                        span.setAttribute("function.param." + paramName, "***");
                        continue;
                    }
                    Object paramValue = parameterValues[i];
                    span.setAttribute("function.param."+paramName, paramValue != null ? paramValue.toString() : "null");
                }
            }

            return result;
        } catch (Exception e) {
            span.setStatus(StatusCode.ERROR, "Exception occurred");
            span.recordException(e);
            throw e;
        } finally {
            span.end();
        }
    }
}
