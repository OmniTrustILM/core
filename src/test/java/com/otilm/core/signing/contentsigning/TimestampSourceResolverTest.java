package com.otilm.core.signing.contentsigning;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.core.service.SigningProfileInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class TimestampSourceResolverTest {

    @Mock
    SigningProfileInternalService signingProfileService;

    @Test
    void resolvesTheReferencedProfileName() throws Exception {
        // given
        UUID uuid = UUID.randomUUID();
        NameAndUuidDto reference = new NameAndUuidDto();
        reference.setUuid(uuid.toString());
        reference.setName("internal-tsa");
        when(signingProfileService.getResourceObjectInternal(uuid)).thenReturn(reference);

        // when
        String name = new TimestampSourceResolver(signingProfileService).profileNameFor(uuid);

        // then
        assertThat(name).isEqualTo("internal-tsa");
    }

    @Test
    void reportsAMissingReferenceAsMisconfiguration() throws Exception {
        // given: the operator deleted the referenced profile
        UUID uuid = UUID.randomUUID();
        when(signingProfileService.getResourceObjectInternal(uuid))
                .thenThrow(new NotFoundException("SigningProfile", uuid));

        // when
        SigningEngineException thrown = catchThrowableOfType(
                () -> new TimestampSourceResolver(signingProfileService).profileNameFor(uuid),
                SigningEngineException.class);

        // then: a configuration fault, and the client text says nothing about the platform's internals
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
        assertThat(thrown.operatorMessage()).contains(uuid.toString());
        assertThat(thrown.clientMessage()).doesNotContain(uuid.toString());
    }

    @Test
    void refusesAProfileWithNoTimestampSourceConfigured() {
        // given: the profile permits a level above SIGNED but names no timestamp source
        // when
        SigningEngineException thrown = catchThrowableOfType(
                () -> new TimestampSourceResolver(signingProfileService).profileNameFor(null),
                SigningEngineException.class);

        // then
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
    }
}
