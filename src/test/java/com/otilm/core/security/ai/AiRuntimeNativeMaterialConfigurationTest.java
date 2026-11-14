package com.otilm.core.security.ai;

import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiRuntimeNativeStartupWriter;
import java.nio.file.Path;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

class AiRuntimeNativeMaterialConfigurationTest {
    @TempDir
    Path directory;
    private final AiRuntimeNativeStartupWriter startup = mock(AiRuntimeNativeStartupWriter.class);
    private final ApplicationContextRunner context = new ApplicationContextRunner()
            .withUserConfiguration(AiRuntimeNativeMaterialConfiguration.class)
            .withBean("ordinary", String.class, () -> "ordinary");

    @Test
    void absentConfigurationDoesNotTouchTheDatabaseOrCreateNativeMaterial() {
        context.withBean(AiRuntimeNativeStartupWriter.class, () -> startup).run(application -> {
            assertThat(application).hasNotFailed();
            assertThat(application.getBean("ordinary", String.class)).isEqualTo("ordinary");
            assertThat(application.getBeanProvider(RuntimeProxyTransport.class).getIfUnique()).isNull();
            assertThat(application.getBeanProvider(AiRuntimeControllerAuthority.class).getIfUnique()).isNull();
            verifyNoInteractions(startup);
        });
    }

    @Test
    void configuredButMissingFileConfirmsDenialAndPreservesOrdinaryContext() {
        context
                .withBean(AiRuntimeNativeStartupWriter.class, () -> startup)
                .withPropertyValues(missingInput())
                .run(application -> {
                    assertThat(application).hasNotFailed();
                    assertThat(application.getBean("ordinary", String.class)).isEqualTo("ordinary");
                    assertThat(application.getBeanProvider(RuntimeProxyTransport.class).getIfUnique()).isNull();
                    assertThat(application.getBeanProvider(AiRuntimeControllerAuthority.class).getIfUnique()).isNull();
                    verify(startup).disableAndConfirm(any());
                });
    }

    @Test
    void unavailableDisableConfirmationNeverExposesNativeTransport() {
        doThrow(new AiRuntimeOperationBudget.Unavailable(false)).when(startup).disableAndConfirm(any());
        context
                .withBean(AiRuntimeNativeStartupWriter.class, () -> startup)
                .withPropertyValues(missingInput())
                .run(application -> {
                    assertThat(application).hasNotFailed();
                    assertThat(application.getBean("ordinary", String.class)).isEqualTo("ordinary");
                    assertThat(application.getBeanProvider(RuntimeProxyTransport.class).getIfUnique()).isNull();
                    verify(startup).disableAndConfirm(any());
                });
    }

    @Test
    void missingOrAmbiguousDatabaseWriterCannotBecomeAnImplicitConfirmation() {
        context.withPropertyValues(missingInput()).run(application -> {
            assertThat(application).hasNotFailed();
            assertThat(application.getBeanProvider(RuntimeProxyTransport.class).getIfUnique()).isNull();
        });
        var other = mock(AiRuntimeNativeStartupWriter.class);
        context
                .withBean("firstStartup", AiRuntimeNativeStartupWriter.class, () -> startup)
                .withBean("secondStartup", AiRuntimeNativeStartupWriter.class, () -> other)
                .withPropertyValues(missingInput())
                .run(application -> {
                    assertThat(application).hasNotFailed();
                    assertThat(application.getBeanProvider(RuntimeProxyTransport.class).getIfUnique()).isNull();
                    verifyNoInteractions(startup, other);
                });
    }

    private String missingInput() {
        return "otilm.ai.runtime.native-material-file=" + directory.resolve("missing.json");
    }
}
