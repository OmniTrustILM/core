package com.otilm.core.events.handlers;

import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.messaging.model.CertificateUploadEventMessageData;
import com.otilm.core.messaging.model.EventMessage;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The async endpoint answers on the request thread, but the certificate and its history event are written later on a
 * JMS listener thread. The event message is the only channel that can carry the uploader across that boundary.
 */
class CertificateUploadedEventHandlerMessageTest {

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void constructedEventMessageCarriesTheActingUser() {
        UUID userUuid = UUID.randomUUID();
        authenticateAs(userUuid, "uploader");

        EventMessage message = CertificateUploadedEventHandler.constructEventMessage(uploadData());

        assertThat(message.getUserUuid()).isEqualTo(userUuid);
    }

    @Test
    void constructedEventMessageHasNoActingUserWhenNobodyIsAuthenticated() {
        EventMessage message = CertificateUploadedEventHandler.constructEventMessage(uploadData());

        assertThat(message.getUserUuid()).isNull();
    }

    private CertificateUploadEventMessageData uploadData() {
        return CertificateUploadEventMessageData
                .builder()
                .certificateContent("cert-content")
                .customAttributes(List.of())
                .build();
    }

    private void authenticateAs(UUID userUuid, String username) {
        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, userUuid.toString(), username,
                List.of());
        SecurityContextHolder
                .getContext()
                .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(info)));
    }
}
