package com.otilm.core.service.ai;

import com.otilm.ai.runtime.protocol.ManagementAction;
import com.otilm.core.model.ai.AiModelDispatchState.ConnectionVersion;
import com.otilm.core.model.ai.AiModelManagementSession.Facts;
import com.otilm.core.model.ai.AiModelManagementSession.Request;
import com.otilm.core.model.ai.AiRuntimeState.Status;
import com.otilm.core.model.ai.AiRuntimeState.Transition;
import com.otilm.core.security.ai.AiModelManagementAuthorization;
import com.otilm.core.service.writer.ai.AiModelManagementSessionWriter;
import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.boot.env.YamlPropertySourceLoader;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.FilterType;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;
import org.springframework.core.io.FileSystemResource;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class AiFeatureGateTest {
    private static final UUID ACTOR = UUID.fromString("00000000-0000-4000-8000-000000000001");
    private static final UUID SESSION = UUID.fromString("00000000-0000-4000-8000-000000000002");
    private static final ConnectionVersion MODEL = new ConnectionVersion(
            UUID.fromString("00000000-0000-4000-8000-000000000003"), 2, 3, 4, "lab");
    private static final Request REQUEST = new Request(SESSION, ACTOR, MODEL.id(), ManagementAction.CONNECTION_CHECK,
            Instant.parse("2030-01-01T00:00:00Z"), 1, 32);
    private static final Facts FACTS = new Facts(SESSION, ACTOR, MODEL, REQUEST.action(), REQUEST.expiresAt(), 1, 32, 0,
            0);

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void rejectsSessionCreation_whenFeatureIsNotEnabled(boolean explicitlyDisabled) {
        // given
        var writer = sessionWriter();
        var authority = mock(AiModelManagementAuthorization.class);
        when(writer.create(any(), any())).thenThrow(new AssertionError("DISABLED_FEATURE_REACHED_SESSION_WRITE"));

        ApplicationContextRunner application = context(writer, authority);
        if (explicitlyDisabled) {
            application = application.withPropertyValues("otilm.ai.enabled=false");
        }
        application.run(running -> {
            // when
            ThrowingCallable begin = () -> running
                    .getBean(AiModelManagementSessionService.class)
                    .begin(REQUEST, AiRuntimeOperationBudget.start());

            // then
            assertThatThrownBy(begin).isInstanceOf(AccessDeniedException.class).hasNoCause();
            verifyNoInteractions(writer, authority);
        });
    }

    @Test
    void createsSession_whenFeatureIsExplicitlyEnabled() {
        // given
        var writer = sessionWriter();
        var authority = mock(AiModelManagementAuthorization.class);

        context(writer, authority).withPropertyValues("otilm.ai.enabled=true").run(application -> {
            // when
            Transition<Facts> result = application
                    .getBean(AiModelManagementSessionService.class)
                    .begin(REQUEST, AiRuntimeOperationBudget.start());

            // then
            assertThat(result.status()).isEqualTo(Status.APPLIED);
            assertThat(result.value()).contains(FACTS);
            verify(authority).requireConnect(eq(ACTOR), eq(MODEL.id()), any());
            verify(writer).create(any(), any());
        });
    }

    @ParameterizedTest
    @CsvSource(value = {"missing,false", "false,false", "true,true"}, nullValues = "missing")
    void usesProductionFlagBinding_whenEnvironmentValueIsConfigured(String configured, boolean expected)
            throws IOException {
        // given
        var yaml = new YamlPropertySourceLoader()
                .load("production-application", new FileSystemResource("src/main/resources/application.yml"));
        Map<String, Object> values = configured == null ? Map.of() : Map.of("OTILM_AI_ENABLED", configured);
        var application = new ApplicationContextRunner()
                .withUserConfiguration(AiFeatureGate.class)
                .withInitializer(context -> {
                    var properties = context.getEnvironment().getPropertySources();
                    properties.remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
                    properties.remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
                    properties.addFirst(new MapPropertySource("synthetic-feature-environment", values));
                    yaml.forEach(properties::addLast);
                });

        // when
        application.run(context -> {
            boolean enabled = context.getBean(AiFeatureGate.class).enabled();

            // then
            assertThat(enabled).isEqualTo(expected);
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static AiModelManagementSessionWriter sessionWriter() {
        var writer = mock(AiModelManagementSessionWriter.class);
        when(writer.connection(eq(MODEL.id()), any())).thenReturn(Optional.of(MODEL));
        when(writer.create(any(), any())).thenReturn(Transition.value(Status.APPLIED, FACTS));
        return writer;
    }

    private static ApplicationContextRunner context(AiModelManagementSessionWriter writer,
            AiModelManagementAuthorization authority) {
        return new ApplicationContextRunner().withInitializer(application -> {
            application
                    .getEnvironment()
                    .getPropertySources()
                    .remove(StandardEnvironment.SYSTEM_ENVIRONMENT_PROPERTY_SOURCE_NAME);
            application
                    .getEnvironment()
                    .getPropertySources()
                    .remove(StandardEnvironment.SYSTEM_PROPERTIES_PROPERTY_SOURCE_NAME);
        })
                .withUserConfiguration(Components.class)
                .withBean(AiModelManagementSessionWriter.class, () -> writer)
                .withBean(AiModelManagementAuthorization.class, () -> authority);
    }

    @Configuration(proxyBeanMethods = false)
    @ComponentScan(basePackageClasses = AiModelManagementSessionService.class, useDefaultFilters = false,
            includeFilters = @ComponentScan.Filter(type = FilterType.REGEX,
                    pattern = "com\\.otilm\\.core\\.service\\.ai\\.Ai(?:ModelManagementSessionService|FeatureGate)"))
    static class Components {
    }
}
