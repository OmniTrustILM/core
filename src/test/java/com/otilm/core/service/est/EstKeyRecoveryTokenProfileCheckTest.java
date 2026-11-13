package com.otilm.core.service.est;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.attribute.RequestAttributeV2;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.SecretAttributeContentData;
import com.otilm.api.model.common.attribute.v2.content.SecretAttributeContentV2;
import com.otilm.api.model.common.attribute.v2.content.StringAttributeContentV2;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.service.handler.KeyCreationRules;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.TokenInstanceFullModelBuilder.aTokenSnapshot;
import static com.otilm.core.util.builders.TokenProfileFullModelBuilder.aTokenProfileSnapshot;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstKeyRecoveryTokenProfileCheckTest {

    @Mock
    private TokenProfileRepository tokenProfileRepository;

    @Mock
    private KeyCreationRules keyCreationRules;

    private EstKeyRecoveryTokenProfileCheck check;

    private final TokenProfile tokenProfile = tokenProfileOnAToken();

    @BeforeEach
    void createCheck() {
        check = new EstKeyRecoveryTokenProfileCheck(tokenProfileRepository, keyCreationRules);
    }

    @Test
    void asksTheRulesForAKeyPair_whenTheTokenProfileCanSign() throws Exception {
        // given
        TokenProfileFullModel model = aTokenProfileSnapshot().withUsages(KeyUsage.SIGN, KeyUsage.VERIFY).build();
        loads(model);
        List<RequestAttribute> keyAttributes = List.of(stringAttribute("keySize", "2048"));

        // when
        check.check(tokenProfile, keyAttributes);

        // then
        verify(keyCreationRules).requireExportSupport(model, KeyRequestType.KEY_PAIR);
        verify(keyCreationRules).validateAttributes(KeyRequestType.KEY_PAIR, model, keyAttributes);
    }

    @Test
    void throwsValidationBeforeLoadingAnything_whenAnAttributeHoldsSecretContent() {
        // given
        var secretName = "keyPin";
        RequestAttribute pin = new RequestAttributeV2(UUID.randomUUID(), secretName, AttributeContentType.SECRET,
                List.of(new SecretAttributeContentV2(null, new SecretAttributeContentData("1234"))));

        // when
        ThrowingCallable checkSecret = () -> check.check(tokenProfile, List.of(pin));

        // then
        assertThatThrownBy(checkSecret)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("cannot hold secret content: " + secretName);
        verifyNoInteractions(tokenProfileRepository, keyCreationRules);
    }

    @Test
    void throwsValidation_whenTheTokenProfileBelongsToNoToken() {
        // given
        TokenProfile unattached = new TokenProfile();
        unattached.setName("loose-profile");

        // when
        ThrowingCallable checkUnattached = () -> check.check(unattached, List.of());

        // then
        assertThatThrownBy(checkUnattached)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("loose-profile does not belong to a token");
        verifyNoInteractions(keyCreationRules);
    }

    @Test
    void throwsValidation_whenAV2TokenProfileDoesNotAllowSigning() {
        // given
        loads(aTokenProfileSnapshot().withUsages(KeyUsage.VERIFY).build());

        // when
        ThrowingCallable checkUnsigned = () -> check.check(tokenProfile, List.of());

        // then
        assertThatThrownBy(checkUnsigned)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("does not allow the signing usage");
        verifyNoInteractions(keyCreationRules);
    }

    @Test
    void acceptsTheUsages_whenTheTokenIsAV1Token() throws Exception {
        // given — a v1 key is not checked for usages when it signs a request
        TokenProfileFullModel v1Profile = aTokenProfileSnapshot()
                .withTokenInstance(aTokenSnapshot().withoutConnectorInterface().build())
                .build();
        loads(v1Profile);

        // when
        check.check(tokenProfile, List.of());

        // then
        verify(keyCreationRules).requireExportSupport(v1Profile, KeyRequestType.KEY_PAIR);
    }

    @Test
    void throwsValidationWithoutTheConnectorsWords_whenTheConnectorFails() throws Exception {
        // given
        var connectorText = "the HSM at 10.0.0.7 refused";
        loads(aTokenProfileSnapshot().withUsages(KeyUsage.SIGN).build());
        doThrow(new ConnectorException(connectorText)).when(keyCreationRules).requireExportSupport(any(), any());

        // when
        ThrowingCallable checkFailing = () -> check.check(tokenProfile, List.of());

        // then
        assertThatThrownBy(checkFailing)
                .isInstanceOf(ValidationException.class)
                .hasMessageNotContaining(connectorText)
                .hasMessageContaining("could not check its export capability and key attributes");
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void loads(TokenProfileFullModel model) {
        when(tokenProfileRepository
                .findFullModelByUuidAndTokenInstanceReferenceUuid(tokenProfile.getUuid(),
                        tokenProfile.getTokenInstanceReferenceUuid()))
                .thenReturn(Optional.of(model));
    }

    private static TokenProfile tokenProfileOnAToken() {
        TokenProfile profile = new TokenProfile();
        profile.setUuid(UUID.randomUUID());
        profile.setName("recovery-token");
        profile.setTokenInstanceReferenceUuid(UUID.randomUUID());
        return profile;
    }

    private static RequestAttribute stringAttribute(String name, String content) {
        return new RequestAttributeV2(UUID.randomUUID(), name, AttributeContentType.STRING,
                List.of(new StringAttributeContentV2(content)));
    }
}
