package com.otilm.core.util.mockbeans;

import com.otilm.core.service.cmp.message.handler.PollFeature;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;

import static org.mockito.Mockito.mock;

/**
 * Mocks {@link PollFeature} (drives outbound polling in CMP message handlers).
 */
@TestConfiguration
public class PollMocks {

    @Bean
    @Primary
    PollFeature mockPollFeature() {
        return mock(PollFeature.class);
    }
}
