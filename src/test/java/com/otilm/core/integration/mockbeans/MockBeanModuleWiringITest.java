package com.otilm.core.integration.mockbeans;

import com.otilm.core.messaging.jms.producers.ActionProducer;
import com.otilm.core.messaging.jms.producers.EventProducer;
import com.otilm.core.messaging.jms.producers.NotificationProducer;
import com.otilm.core.messaging.jms.producers.ValidationProducer;
import com.otilm.core.security.authn.client.PlatformAuthenticationClient;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.service.cmp.message.handler.PollFeature;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mockbeans.ManagementApiMocks;
import com.otilm.core.util.mockbeans.PollMocks;
import com.otilm.core.util.mockbeans.ProducerMocks;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockingDetails;

@Import({ProducerMocks.class, ManagementApiMocks.class, PollMocks.class})
class MockBeanModuleWiringITest extends BaseSpringBootTest {

    @Autowired NotificationProducer notificationProducer;
    @Autowired ActionProducer actionProducer;
    @Autowired EventProducer eventProducer;
    @Autowired ValidationProducer validationProducer;
    @Autowired UserManagementApiClient userManagementApiClient;
    @Autowired RoleManagementApiClient roleManagementApiClient;
    @Autowired PlatformAuthenticationClient authenticationClient;
    @Autowired PollFeature pollFeature;

    @Test
    void allModuleBeansAreMocks() {
        assertThat(mockingDetails(notificationProducer).isMock()).isTrue();
        assertThat(mockingDetails(actionProducer).isMock()).isTrue();
        assertThat(mockingDetails(eventProducer).isMock()).isTrue();
        assertThat(mockingDetails(validationProducer).isMock()).isTrue();
        assertThat(mockingDetails(userManagementApiClient).isMock()).isTrue();
        assertThat(mockingDetails(roleManagementApiClient).isMock()).isTrue();
        assertThat(mockingDetails(authenticationClient).isMock()).isTrue();
        assertThat(mockingDetails(pollFeature).isMock()).isTrue();
    }
}
