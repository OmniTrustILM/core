package com.otilm.core.feasibility;

import com.otilm.core.security.ai.AiReadInvocation;
import com.otilm.core.service.CertificateExternalService;
import javax.sql.DataSource;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;
import org.springframework.transaction.PlatformTransactionManager;

@TestConfiguration(proxyBeanMethods = false)
public class ConversationStreamProofConfiguration {
    @Bean
    ConversationTimeline conversationTimeline(DataSource dataSource, PlatformTransactionManager transactions) {
        new ResourceDatabasePopulator(new ClassPathResource("ai/conversation-stream/schema.sql")).execute(dataSource);
        return new ConversationTimeline(new JdbcTemplate(dataSource), transactions);
    }

    @Bean
    ConversationStreamAuthorization conversationStreamAuthorization(AiReadInvocation invocation,
            CertificateExternalService service) {
        return new ConversationStreamAuthorization(invocation, service);
    }

    @Bean
    ConversationStreamFixture conversationStreamFixture(ConversationTimeline timeline,
            ConversationStreamAuthorization authorization) {
        return new ConversationStreamFixture(timeline, authorization);
    }
}
