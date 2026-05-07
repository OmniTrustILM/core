package com.czertainly.core.util;

import com.czertainly.core.security.authz.opa.OpaClient;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Profile;
import org.springframework.core.task.SyncTaskExecutor;
import org.springframework.core.task.TaskExecutor;
import org.springframework.test.context.bean.override.mockito.MockitoBean;

@TestConfiguration
@Profile("test | messaging-int-test")
class SpringBootTestContext {
    @MockitoBean
    OpaClient opaClient;

    @Bean
    public TaskExecutor taskExecutor() {
        return new SyncTaskExecutor();
    }
}
