package com.otilm.core.aop;

import com.otilm.core.dao.repository.ai.AiRuntimeRepository;
import com.otilm.core.model.ai.AiRuntimeState.ControlVersion;
import com.otilm.core.model.ai.AiRuntimeState.RunSpec;
import com.otilm.core.service.ai.AiFeatureGate;
import com.otilm.core.service.ai.AiRuntimeKernel;
import com.otilm.core.service.writer.ai.AiRuntimeWriter;
import com.otilm.core.util.AiRuntimeFixture;
import io.opentelemetry.api.OpenTelemetry;
import io.opentelemetry.api.trace.Span;
import io.opentelemetry.api.trace.SpanBuilder;
import io.opentelemetry.api.trace.SpanKind;
import io.opentelemetry.api.trace.StatusCode;
import io.opentelemetry.api.trace.Tracer;
import io.opentelemetry.context.Scope;
import java.lang.reflect.Proxy;
import java.time.Instant;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.aop.aspectj.annotation.AspectJProxyFactory;
import org.springframework.context.annotation.Profile;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.stereotype.Service;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AiRuntimeTracingTest {
    private static final String CONTENT = "synthetic-ai-content-forbidden-in-telemetry";

    @Test
    void jdkProxyUsesTargetAnnotationWithoutSerializingArguments() {
        Telemetry telemetry = new Telemetry();
        RuntimeOperation operation = telemetry.proxy(new MetadataOperation(), false);
        Payload payload = new Payload(true);

        assertThat(Proxy.isProxyClass(operation.getClass())).isTrue();
        assertThat(operation.accept(payload)).isEqualTo("accepted");

        assertThat(payload.serializations).isZero();
        telemetry.assertMetadata("accept");
    }

    @Test
    void classProxyHonorsInheritedMetadataAnnotation() {
        Telemetry telemetry = new Telemetry();
        RuntimeOperation operation = telemetry.proxy(new InheritedMetadataOperation(), true);
        Payload payload = new Payload(true);

        assertThat(Proxy.isProxyClass(operation.getClass())).isFalse();
        assertThat(operation.accept(payload)).isEqualTo("accepted");

        assertThat(payload.serializations).isZero();
        telemetry.assertMetadata("accept");
    }

    @Test
    void metadataFailureRetainsStatusAndPropagatesWithoutExceptionTelemetry() {
        Telemetry telemetry = new Telemetry();
        RuntimeOperation operation = telemetry.proxy(new MetadataOperation(), false);
        Payload payload = new Payload(true);

        assertThatThrownBy(() -> operation.fail(payload)).isSameAs(payload.failure);

        assertThat(payload.serializations).isZero();
        telemetry.assertMetadata("fail");
        assertThat(telemetry.statuses).containsExactly(StatusCode.ERROR);
        assertThat(telemetry.exceptions).isEmpty();
    }

    @Test
    void ordinaryServicesStillRecordArguments() {
        Telemetry telemetry = new Telemetry();
        RuntimeOperation operation = telemetry.proxy(new OrdinaryOperation(), true);
        Payload payload = new Payload(false);

        assertThat(operation.accept(payload)).isEqualTo("accepted");

        assertThat(payload.serializations).isEqualTo(1);
        assertThat(telemetry.attributes).containsEntry("function.param.payload", CONTENT);
        verify(telemetry.span).end();
    }

    @Test
    void ordinaryServiceFailureStillRecordsException() {
        Telemetry telemetry = new Telemetry();
        RuntimeOperation operation = telemetry.proxy(new OrdinaryOperation(), true);
        Payload payload = new Payload(false);

        assertThatThrownBy(() -> operation.fail(payload)).isSameAs(payload.failure);

        assertThat(telemetry.exceptions).containsExactly(payload.failure);
        assertThat(telemetry.statuses).containsExactly(StatusCode.ERROR);
        verify(telemetry.scope).close();
        verify(telemetry.span).end();
    }

    @Test
    void actualKernelCreateOmitsPersistedScopeFromTelemetry() {
        Telemetry telemetry = new Telemetry();
        AiRuntimeKernel kernel = telemetry
                .proxy(new AiRuntimeKernel(mock(AiRuntimeRepository.class), mock(AiRuntimeWriter.class),
                        new AiFeatureGate(true)), true);
        Instant now = Instant.parse("2026-11-04T12:00:00Z");
        var original = AiRuntimeFixture.run(now);
        var run = new RunSpec(original.runId(), original.conversationRef(), original.actorId(), CONTENT,
                original.attemptLimit(), original.podLimit(), original.leaseSeconds(), original.runDeadline());
        var attempt = AiRuntimeFixture.attempt(now);
        var control = new ControlVersion(2);

        assertThat(kernel.create(control, run, attempt)).isNull();

        telemetry.assertMetadata("create");
        assertThat(telemetry.attributes.values()).noneMatch(value -> value.contains(CONTENT));
    }

    @Test
    void actualWriterFailureOmitsPersistenceExceptionFromTelemetry() {
        Telemetry telemetry = new Telemetry();
        AiRuntimeRepository repository = mock(AiRuntimeRepository.class);
        DataAccessResourceFailureException failure = new DataAccessResourceFailureException(CONTENT);
        when(repository.configureTransaction()).thenThrow(failure);
        AiRuntimeWriter writer = telemetry.proxy(new AiRuntimeWriter(repository), true);
        Instant now = Instant.parse("2026-11-04T12:00:00Z");
        var run = AiRuntimeFixture.run(now);
        var attempt = AiRuntimeFixture.attempt(now);
        var control = new ControlVersion(2);

        assertThatThrownBy(() -> writer.create(control, run, attempt)).isSameAs(failure);

        telemetry.assertMetadata("create");
        assertThat(telemetry.statuses).containsExactly(StatusCode.ERROR);
        assertThat(telemetry.exceptions).isEmpty();
    }

    public interface RuntimeOperation {
        String accept(Payload payload);

        String fail(Payload payload);
    }

    @Service
    @Profile("ai-runtime-tracing-fixture")
    @TraceMetadataOnly
    public static class MetadataOperation implements RuntimeOperation {
        @Override
        public String accept(Payload payload) {
            return payload == null ? "empty" : "accepted";
        }

        @Override
        public String fail(Payload payload) {
            throw payload.failure;
        }
    }

    @Service
    @Profile("ai-runtime-tracing-fixture")
    public static class InheritedMetadataOperation extends MetadataOperation {
    }

    @Service
    @Profile("ai-runtime-tracing-fixture")
    public static class OrdinaryOperation implements RuntimeOperation {
        @Override
        public String accept(Payload payload) {
            return payload == null ? "empty" : "accepted";
        }

        @Override
        public String fail(Payload payload) {
            throw payload.failure;
        }
    }

    public static final class Payload {
        private final IllegalStateException failure = new IllegalStateException(CONTENT);
        private final boolean refuseSerialization;
        private int serializations;

        private Payload(boolean refuseSerialization) {
            this.refuseSerialization = refuseSerialization;
        }

        @Override
        public String toString() {
            serializations++;
            if (refuseSerialization) {
                throw new IllegalStateException("Metadata-only arguments must never be serialized");
            }
            return CONTENT;
        }
    }

    private static final class Telemetry {
        private final Span span = mock(Span.class);
        private final Scope scope = mock(Scope.class);
        private final Map<String, String> attributes = new LinkedHashMap<>();
        private final List<Throwable> exceptions = new ArrayList<>();
        private final List<StatusCode> statuses = new ArrayList<>();
        private final OpenTelemetry openTelemetry = mock(OpenTelemetry.class);
        private String spanName;

        private Telemetry() {
            SpanBuilder builder = mock(SpanBuilder.class);
            Tracer tracer = mock(Tracer.class);
            when(openTelemetry.getTracer("application")).thenReturn(tracer);
            when(tracer.spanBuilder(anyString())).thenAnswer(invocation -> {
                spanName = invocation.getArgument(0);
                return builder;
            });
            when(builder.setSpanKind(SpanKind.INTERNAL)).thenReturn(builder);
            when(builder.startSpan()).thenReturn(span);
            when(span.makeCurrent()).thenReturn(scope);
            doAnswer(invocation -> {
                attributes.put(invocation.getArgument(0), invocation.getArgument(1));
                return span;
            }).when(span).setAttribute(anyString(), anyString());
            doAnswer(invocation -> {
                exceptions.add(invocation.getArgument(0));
                return span;
            }).when(span).recordException(any(Throwable.class));
            doAnswer(invocation -> {
                statuses.add(invocation.getArgument(0));
                return span;
            }).when(span).setStatus(any(StatusCode.class), anyString());
        }

        @SuppressWarnings("unchecked")
        private <T> T proxy(T target, boolean classProxy) {
            AspectJProxyFactory factory = new AspectJProxyFactory(target);
            factory.setProxyTargetClass(classProxy);
            factory.addAspect(new TracingAspect(openTelemetry));
            return (T) factory.getProxy();
        }

        private void assertMetadata(String method) {
            assertThat(spanName).endsWith("." + method);
            assertThat(attributes).containsOnlyKeys("code.namespace", "code.function");
            assertThat(attributes).containsEntry("code.function", method);
            assertThat(attributes.get("code.namespace")).isNotBlank();
            verify(scope).close();
            verify(span).end();
        }
    }
}
