package com.czertainly.core.util;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.core.task.TaskExecutor;
import org.springframework.http.client.ReactorResourceFactory;

import java.time.Duration;

@TestConfiguration
@Profile("test | messaging-int-test")
class SpringBootTestContext {
    @Bean
    public TaskExecutor taskExecutor() {
        return new SyncTaskExecutor();
    }

    /**
     * Overrides the auto-configured ReactorResourceFactory with a bounded shutdown timeout.
     *
     * <p> Spring's SpringApplicationShutdownHook calls ReactorResourceFactory.stop(), which calls
     * HttpResources.disposeLoopsAndConnectionsLater(...).block(). shutdownQuietPeriod=0 / shutdownTimeout=5s guarantees
     * stop() returns within 5 seconds without affecting how resources are used during the tests themselves.</p>
     */
    @Bean
    public ReactorResourceFactory reactorResourceFactory() {
        ReactorResourceFactory factory = new ReactorResourceFactory();
        factory.setShutdownQuietPeriod(Duration.ZERO);
        factory.setShutdownTimeout(Duration.ofSeconds(5));
        return factory;
    }
}
