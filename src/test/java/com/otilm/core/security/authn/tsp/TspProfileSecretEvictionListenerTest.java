package com.otilm.core.security.authn.tsp;

import com.otilm.core.events.SecretContentUpdatedEvent;
import com.otilm.core.service.TspProfileBasicCredentialInternalService;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.UUID;

import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class TspProfileSecretEvictionListenerTest {

    @Mock
    private TspProfileBasicCredentialInternalService credentialService;

    @InjectMocks
    private TspProfileSecretEvictionListener listener;

    @Test
    void delegatesEvictionToCredentialService() {
        // given
        UUID secretUuid = UUID.randomUUID();

        // when
        listener.onSecretContentUpdated(new SecretContentUpdatedEvent(secretUuid));

        // then
        verify(credentialService).evictCachesForSecret(secretUuid);
    }
}
