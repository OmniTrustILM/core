package com.otilm.core.security.authn.tsp;

import com.otilm.api.model.connector.secrets.content.BasicAuthSecretContent;
import com.otilm.api.model.core.signing.TspAuthenticationMethod;
import com.otilm.core.model.signing.TspProfileModel;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.SecretsUtil;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class BasicPasswordAuthenticatorTest {

    @Mock
    private AuthHelper authHelper;

    private BasicPasswordAuthenticator authenticator;

    @BeforeEach
    void setUp() {
        authenticator = new BasicPasswordAuthenticator(new TspSecurityContextWriter(authHelper));
    }

    @Test
    void theOldPasswordIsRefusedOnceTheFingerprintChanges() {
        // given
        UUID mappedUser = UUID.randomUUID();
        authenticator.authenticate(basicRequest("alice", "old"), profile(mappedUser, fingerprintOf("old")));

        // when
        boolean authenticated = authenticator
                .authenticate(basicRequest("alice", "old"), profile(mappedUser, fingerprintOf("new")));

        // then
        assertThat(authenticated).isFalse();
    }

    @Test
    void aReassignedCredentialAuthenticatesAsItsCurrentUser() {
        // given
        UUID previousUser = UUID.randomUUID();
        UUID currentUser = UUID.randomUUID();
        authenticator.authenticate(basicRequest("alice", "s3cret"), profile(previousUser, fingerprintOf("s3cret")));

        // when
        authenticator.authenticate(basicRequest("alice", "s3cret"), profile(currentUser, fingerprintOf("s3cret")));

        // then
        verify(authHelper).authenticateAsUser(currentUser);
    }

    private static MockHttpServletRequest basicRequest(String username, String password) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        String credentials = Base64
                .getEncoder()
                .encodeToString((username + ":" + password).getBytes(StandardCharsets.UTF_8));
        request.addHeader(HttpHeaders.AUTHORIZATION, "Basic " + credentials);
        return request;
    }

    private static TspProfileModel profile(UUID mappedUser, String fingerprint) {
        TspProfileModel.BasicCredentialRef credential = new TspProfileModel.BasicCredentialRef("alice", mappedUser,
                fingerprint);
        return new TspProfileModel(UUID.randomUUID(), "p1", null, true, null, null, List.of(),
                List.of(TspAuthenticationMethod.BASIC_PASSWORD), List.of(credential), null);
    }

    private static String fingerprintOf(String password) {
        try {
            return SecretsUtil.calculateSecretContentFingerprint(new BasicAuthSecretContent("alice", password));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
