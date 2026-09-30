package com.otilm.core.integration.service;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.cryptography.tokenprofile.TokenProfileDto;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.security.authz.opa.dto.OpaObjectAccessResult;
import com.otilm.core.service.TokenProfileExternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mocks.CryptographyProviderV2ConnectorMock;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;

@SpringBootTest
class TokenProfileImportableFilterITest extends BaseSpringBootTest {

    @Autowired
    private V2TokenFixture v2TokenFixture;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private TokenProfileExternalService tokenProfileService;

    private CryptographyProviderV2ConnectorMock connectorMock;

    @AfterEach
    void tearDown() {
        connectorMock.stop();
    }

    @Test
    void listsAProfileWhoseRecordedAnswerHoldsEveryPair() {
        // given
        V2TokenFixture.V2Token v2Token = v2TokenFixture.start();
        connectorMock = v2Token.connectorMock();
        TokenProfile profile = v2Token.profile();
        profile
                .setImportableKeyTypes(
                        List.of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA))));
        tokenProfileRepository.save(profile);

        // when / then
        assertThat(uuidsFor(List.of("keyPair:RSA"))).containsExactly(profile.getUuid().toString());
        assertThat(uuidsFor(List.of("keyPair:ECDSA"))).isEmpty();
        assertThat(uuidsFor(List.of("keyPair:RSA", "keyPair:ECDSA"))).isEmpty();
    }

    @Test
    void listsAProfileWithNoRecordedAnswerWhoseConnectorDeclaresImport() {
        // given
        V2TokenFixture.V2Token v2Token = v2TokenFixture.start();
        connectorMock = v2Token.connectorMock();
        TokenProfile profile = v2Token.profile();

        // when / then
        assertThat(uuidsFor(List.of("keyPair:ECDSA"))).containsExactly(profile.getUuid().toString());
    }

    @Test
    void leavesOutAProfileWhoseConnectorDoesNotDeclareImport() {
        // given
        V2TokenFixture.V2Token v2Token = v2TokenFixture.start();
        connectorMock = v2Token.connectorMock();
        v2TokenFixture.declare(v2Token, FeatureFlag.STATELESS);
        TokenProfile profile = v2Token.profile();

        // when / then
        assertThat(uuidsFor(List.of("keyPair:RSA"))).isEmpty();
        assertThat(uuidsFor(List.of())).containsExactly(profile.getUuid().toString());
    }

    @Test
    void refusesAValueThatIsNotATypeAndAnAlgorithm() {
        // given
        V2TokenFixture.V2Token v2Token = v2TokenFixture.start();
        connectorMock = v2Token.connectorMock();

        List<String> malformed = List.of("keyPair");

        // when / then
        assertThrows(ValidationException.class, () -> uuidsFor(malformed));
    }

    @Test
    void appliesTheEnabledFilterToImportableProfiles() {
        // given
        V2TokenFixture.V2Token v2Token = v2TokenFixture.start();
        connectorMock = v2Token.connectorMock();
        TokenProfile profile = v2Token.profile();

        // when / then
        assertThat(uuidsFor(Optional.of(true), List.of("keyPair:RSA"))).containsExactly(profile.getUuid().toString());

        // and
        profile.setEnabled(false);
        tokenProfileRepository.save(profile);
        assertThat(uuidsFor(Optional.of(true), List.of("keyPair:RSA"))).isEmpty();
        assertThat(uuidsFor(Optional.of(false), List.of("keyPair:RSA"))).containsExactly(profile.getUuid().toString());
    }

    @Test
    void leavesOutAnEligibleProfileTheSecurityFilterHides() {
        // given
        V2TokenFixture.V2Token v2Token = v2TokenFixture.start();
        connectorMock = v2Token.connectorMock();
        TokenProfile visibleProfile = v2Token.profile();
        TokenProfile hiddenProfile = new TokenProfile();
        hiddenProfile.setName("import-profile-" + UUID.randomUUID());
        hiddenProfile.setTokenInstanceReference(v2Token.token());
        hiddenProfile.setTokenInstanceName(v2Token.token().getName());
        hiddenProfile.setEnabled(true);
        hiddenProfile.setUsage(List.of(KeyUsage.SIGN, KeyUsage.VERIFY, KeyUsage.ENCRYPT, KeyUsage.DECRYPT));
        hiddenProfile = tokenProfileRepository.save(hiddenProfile);

        OpaObjectAccessResult hidesOneProfile = new OpaObjectAccessResult();
        hidesOneProfile.setActionAllowedForGroupOfObjects(true);
        hidesOneProfile.setAllowedObjects(List.of());
        hidesOneProfile.setForbiddenObjects(List.of(hiddenProfile.getUuid().toString()));
        when(opaClient
                .checkObjectAccess(Mockito.any(),
                        Mockito
                                .argThat(req -> req != null && req.getProperties() != null
                                        && Resource.TOKEN_PROFILE.getCode().equals(req.getProperties().get("name"))
                                        && ResourceAction.LIST.getCode().equals(req.getProperties().get("action"))),
                        Mockito.any(), Mockito.any()))
                .thenReturn(hidesOneProfile);

        // when / then
        assertThat(uuidsFor(List.of("keyPair:RSA"))).containsExactly(visibleProfile.getUuid().toString());
    }

    private List<String> uuidsFor(List<String> importable) {
        return uuidsFor(Optional.empty(), importable);
    }

    private List<String> uuidsFor(Optional<Boolean> enabled, List<String> importable) {
        return tokenProfileService
                .listTokenProfiles(enabled, importable, SecurityFilter.create())
                .stream()
                .map(TokenProfileDto::getUuid)
                .toList();
    }
}
