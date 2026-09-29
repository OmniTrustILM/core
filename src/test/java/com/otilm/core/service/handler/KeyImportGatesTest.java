package com.otilm.core.service.handler;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.connector.ImmutableConnectorInterface;
import com.otilm.core.model.crypto.ImmutableTokenInstanceFullModel;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.KeyTransfer;
import com.otilm.core.model.crypto.TokenProfileFullModel;
import com.otilm.core.model.crypto.TransferableKeyType;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.service.handler.KeyImportGates.KeyKind;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.service.writer.KeyTransferCapabilityWriter;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InOrder;
import org.springframework.security.access.AccessDeniedException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.entry;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class KeyImportGatesTest {

    private static final Map<KeyRequestType, Set<KeyAlgorithm>> RSA_KEY_PAIRS = Map
            .of(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA));

    private final AuthorizationEnforcer authorizationEnforcer = mock(AuthorizationEnforcer.class);
    private final TokenProfileRepository profiles = mock(TokenProfileRepository.class);
    private final KeyProviderAdapterFactory adapters = mock(KeyProviderAdapterFactory.class);
    private final KeyProviderAdapter adapter = mock(KeyProviderAdapter.class);
    private final KeyTransferCapabilityWriter writer = mock(KeyTransferCapabilityWriter.class);
    private final CryptographicKeyWriter keyWriter = mock(CryptographicKeyWriter.class);
    private final KeyImportGates gates = new KeyImportGates(authorizationEnforcer, profiles,
            new KeyTransferCapabilityService(new ConnectorCapabilityService(), adapters, writer,
                    mock(TokenInstanceReferenceRepository.class), profiles),
            keyWriter);

    @Test
    void notImportableReasons_hasNoneForAKeyTheProfileImports() throws Exception {
        // given
        TokenProfileFullModel profile = profile(importingToken(), true, RSA_KEY_PAIRS);

        // when
        Optional<String> reason = reasonAgainst(profile, KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA);

        // then
        assertThat(reason).isEmpty();
    }

    @Test
    void notImportableReasons_namesADisabledProfileForEveryKindWithoutAskingItsConnector() throws Exception {
        // given
        TokenProfileFullModel profile = profile(importingToken(), false, null);
        Set<KeyKind> kinds = Set
                .of(new KeyKind(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA),
                        new KeyKind(KeyRequestType.SECRET, KeyAlgorithm.AES));

        // when
        Map<KeyKind, Optional<String>> reasons = gates.notImportableReasons(profile, kinds);

        // then
        assertThat(reasons).containsOnlyKeys(kinds);
        assertThat(reasons.values()).containsOnly(Optional.of("Token profile importer is disabled."));
        verifyNoInteractions(adapters);
    }

    @Test
    void notImportableReasons_namesTheTypeForAProfileWhoseProviderImportsNothing() throws Exception {
        // given
        TokenProfileFullModel profile = profile(token(FeatureFlag.STATELESS), true, null);

        // when
        Optional<String> reason = reasonAgainst(profile, KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA);

        // then
        assertThat(reason).contains("Token profile importer does not import a key pair.");
        verifyNoInteractions(adapters);
    }

    @Test
    void notImportableReasons_namesATypeTheProfileDoesNotImport() throws Exception {
        // given
        TokenProfileFullModel profile = profile(importingToken(), true, RSA_KEY_PAIRS);

        // when
        Optional<String> reason = reasonAgainst(profile, KeyRequestType.SECRET, KeyAlgorithm.AES);

        // then
        assertThat(reason).contains("Token profile importer does not import a secret key.");
    }

    @Test
    void notImportableReasons_namesAnAlgorithmTheProfileDoesNotImportForTheType() throws Exception {
        // given
        TokenProfileFullModel profile = profile(importingToken(), true, RSA_KEY_PAIRS);

        // when
        Optional<String> reason = reasonAgainst(profile, KeyRequestType.KEY_PAIR, KeyAlgorithm.ECDSA);

        // then
        assertThat(reason).contains("Token profile importer does not import the ECDSA algorithm for a key pair.");
    }

    @Test
    void notImportableReasons_namesAProfileThatChangedWhileItsConnectorWasAskedForEveryKind() throws Exception {
        // given
        TokenProfileFullModel profile = changingProfile();
        Set<KeyKind> kinds = Set
                .of(new KeyKind(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA),
                        new KeyKind(KeyRequestType.KEY_PAIR, KeyAlgorithm.ECDSA));

        // when
        Map<KeyKind, Optional<String>> reasons = gates.notImportableReasons(profile, kinds);

        // then
        assertThat(reasons).containsOnlyKeys(kinds);
        assertThat(reasons.values())
                .containsOnly(Optional.of("Token profile importer changed while its import was checked. Try again."));
    }

    /** One answer of the connector decides every kind of key, so it is asked once whatever the keys are. */
    @Test
    void notImportableReasons_asksTheConnectorOnceForKeysOfEveryKind() throws Exception {
        // given
        ImmutableTokenInstanceFullModel token = importingToken();
        TokenProfileFullModel profile = profile(token, true, null);
        List<TransferableKeyType> answer = List
                .of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)));
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listImportableKeyTypes(profile)).thenReturn(answer);
        when(writer.recordAnswer(profile.uuid(), profile.keyTypesRevision(), KeyTransfer.IMPORT, answer))
                .thenReturn(Optional.of(profile(token, true, RSA_KEY_PAIRS)));
        KeyKind rsa = new KeyKind(KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA);
        KeyKind ecdsa = new KeyKind(KeyRequestType.KEY_PAIR, KeyAlgorithm.ECDSA);
        KeyKind aes = new KeyKind(KeyRequestType.SECRET, KeyAlgorithm.AES);

        // when
        Map<KeyKind, Optional<String>> reasons = gates.notImportableReasons(profile, Set.of(rsa, ecdsa, aes));

        // then
        assertThat(reasons)
                .containsOnly(entry(rsa, Optional.empty()),
                        entry(ecdsa, Optional
                                .of("Token profile importer does not import the ECDSA algorithm for a key pair.")),
                        entry(aes, Optional.of("Token profile importer does not import a secret key.")));
        verify(adapter).listImportableKeyTypes(profile);
        verify(writer).recordAnswer(profile.uuid(), profile.keyTypesRevision(), KeyTransfer.IMPORT, answer);
    }

    @Test
    void notImportableReasons_asksNothingWhenThereIsNoKeyToAnswerFor() throws Exception {
        // given
        TokenProfileFullModel profile = profile(importingToken(), true, null);

        // when
        Map<KeyKind, Optional<String>> reasons = gates.notImportableReasons(profile, Set.of());

        // then
        assertThat(reasons).isEmpty();
        verifyNoInteractions(adapters, writer);
    }

    @Test
    void requireImportable_answersTheAlgorithmsTheProfileImportsForTheType() throws Exception {
        // given
        TokenProfileFullModel profile = profile(importingToken(), true, RSA_KEY_PAIRS);

        // when
        Set<KeyAlgorithm> algorithms = gates.requireImportable(profile, KeyRequestType.KEY_PAIR);

        // then
        assertThat(algorithms).containsExactly(KeyAlgorithm.RSA);
    }

    /** The import refuses a profile in the words the inspection reports it with. */
    @ParameterizedTest
    @ValueSource(strings = {"disabled", "importing nothing", "importing secret keys", "changing while checked"})
    void requireImportable_refusesWithTheReasonTheInspectionReports(String profileThatImportsNoKeyPair)
            throws Exception {
        // given
        TokenProfileFullModel profile = profileThatImportsNoKeyPair(profileThatImportsNoKeyPair);
        String reported = reasonAgainst(profile, KeyRequestType.KEY_PAIR, KeyAlgorithm.RSA).orElseThrow();

        // when
        ValidationException refusal = assertThrows(ValidationException.class,
                () -> gates.requireImportable(profile, KeyRequestType.KEY_PAIR));

        // then
        assertThat(refusal.getMessage()).isEqualTo(reported);
    }

    @Test
    void requireAccess_checksTheProfileAndItsTokenForAProfileNamedWithoutItsToken() throws Exception {
        // given
        TokenProfileFullModel profile = profile(importingToken(), true, RSA_KEY_PAIRS);
        UUID tokenUuid = profile.tokenInstanceReferenceUuid();
        TokenProfile entity = new TokenProfile();
        entity.setUuid(profile.uuid());
        entity.setTokenInstanceReferenceUuid(tokenUuid);
        when(profiles.findByUuid(profile.uuid())).thenReturn(Optional.of(entity));
        when(profiles.findFullModelByUuidAndTokenInstanceReferenceUuid(profile.uuid(), tokenUuid))
                .thenReturn(Optional.of(profile));

        // when
        TokenProfileFullModel found = gates.requireAccess(profile.uuid());

        // then
        assertThat(found).isSameAs(profile);
        InOrder checks = inOrder(authorizationEnforcer);
        checks
                .verify(authorizationEnforcer)
                .enforce(eq(Resource.TOKEN_PROFILE), eq(ResourceAction.DETAIL), secured(profile.uuid()));
        checks.verify(authorizationEnforcer).enforce(eq(Resource.TOKEN), eq(ResourceAction.DETAIL), secured(tokenUuid));
        checks
                .verify(authorizationEnforcer)
                .enforce(eq(Resource.TOKEN), eq(ResourceAction.MEMBERS), secured(tokenUuid));
        checks.verifyNoMoreInteractions();
    }

    @Test
    void requireAccess_answersNotFoundForAnUnknownProfile() {
        // given
        UUID unknown = UUID.randomUUID();
        when(profiles.findByUuid(unknown)).thenReturn(Optional.empty());

        // when
        assertThrows(NotFoundException.class, () -> gates.requireAccess(unknown));

        // then
        verifyNoInteractions(authorizationEnforcer);
    }

    @Test
    void requireUpdatable_letsACallerWhoMayUpdateTheRecordAdoptIt() {
        // given
        UUID recordUuid = UUID.randomUUID();

        // when
        gates.requireUpdatable(recordUuid);

        // then
        verify(authorizationEnforcer)
                .enforce(eq(Resource.CRYPTOGRAPHIC_KEY), eq(ResourceAction.UPDATE), secured(recordUuid));
    }

    /** The refusal is the one a key held otherwise gets, so it says nothing of whose the record is. */
    @Test
    void requireUpdatable_refusesACallerWhoMayNotUpdateTheRecordInNeutralWords() {
        // given
        UUID recordUuid = UUID.randomUUID();
        doThrow(new AccessDeniedException("denied"))
                .when(authorizationEnforcer)
                .enforce(eq(Resource.CRYPTOGRAPHIC_KEY), eq(ResourceAction.UPDATE), secured(recordUuid));

        // when
        ValidationException refused = assertThrows(ValidationException.class, () -> gates.requireUpdatable(recordUuid));

        // then
        assertThat(refused.getMessage()).isEqualTo(CryptographicKeyWriter.KEY_ALREADY_HELD);
    }

    /** The right is checked as the requester, so it holds where nobody is signed in, as in the reconciliation. */
    @Test
    void adoptableBy_answersTheRecordItsRequesterMayUpdate() {
        // given
        UUID requester = UUID.randomUUID();
        UUID recordUuid = UUID.randomUUID();
        when(keyWriter.adoptableRecord("fingerprint")).thenReturn(Optional.of(recordUuid));
        when(authorizationEnforcer
                .isAuthorizedAs(eq(requester), eq(Resource.CRYPTOGRAPHIC_KEY), eq(ResourceAction.UPDATE),
                        secured(recordUuid)))
                .thenReturn(true);

        // when
        Optional<UUID> adoptable = gates
                .adoptableBy(new NameAndUuidDto(requester.toString(), "requester"), "fingerprint");

        // then
        assertThat(adoptable).contains(recordUuid);
    }

    @Test
    void adoptableBy_refusesARecordItsRequesterMayNotUpdate() {
        // given
        NameAndUuidDto requester = new NameAndUuidDto(UUID.randomUUID().toString(), "requester");
        when(keyWriter.adoptableRecord("fingerprint")).thenReturn(Optional.of(UUID.randomUUID()));

        // when
        ValidationException refused = assertThrows(ValidationException.class,
                () -> gates.adoptableBy(requester, "fingerprint"));

        // then
        assertThat(refused.getMessage()).isEqualTo(CryptographicKeyWriter.KEY_ALREADY_HELD);
    }

    /**
     * No record the registration may adopt holds the public key: the platform does not hold it, or holds it otherwise,
     * as a key of its own that a concurrent request may have registered for the same attempt. The registration decides
     * that under the attempt's lock, so nothing is vouched for or refused here.
     */
    @Test
    void adoptableBy_leavesAPublicKeyNoRecordHoldsToTheRegistration() {
        // given
        NameAndUuidDto requester = new NameAndUuidDto(UUID.randomUUID().toString(), "requester");
        when(keyWriter.adoptableRecord("fingerprint")).thenReturn(Optional.empty());

        // when
        Optional<UUID> adoptable = gates.adoptableBy(requester, "fingerprint");

        // then
        assertThat(adoptable).isEmpty();
        verify(keyWriter).adoptableRecord("fingerprint");
        verifyNoInteractions(authorizationEnforcer);
    }

    /** A secret key has no public key, so no record holds it. */
    @Test
    void adoptableBy_answersNothingForASecretKey() {
        // given
        NameAndUuidDto requester = new NameAndUuidDto(UUID.randomUUID().toString(), "requester");

        // when
        // then
        assertThat(gates.adoptableBy(requester, null)).isEmpty();
        verifyNoInteractions(keyWriter, authorizationEnforcer);
    }

    /** The reason the profile gives against the one kind of key. */
    private Optional<String> reasonAgainst(TokenProfileFullModel profile, KeyRequestType type, KeyAlgorithm algorithm)
            throws Exception {
        KeyKind kind = new KeyKind(type, algorithm);
        Map<KeyKind, Optional<String>> reasons = gates.notImportableReasons(profile, Set.of(kind));
        assertThat(reasons).containsOnlyKeys(kind);
        return reasons.get(kind);
    }

    private TokenProfileFullModel profileThatImportsNoKeyPair(String name) throws Exception {
        return switch (name) {
            case "disabled" -> profile(importingToken(), false, null);
            case "importing nothing" -> profile(token(FeatureFlag.STATELESS), true, null);
            case "importing secret keys" ->
                profile(importingToken(), true, Map.of(KeyRequestType.SECRET, Set.of(KeyAlgorithm.AES)));
            default -> changingProfile();
        };
    }

    /** A profile without a recorded answer, which changes while its connector is asked what it imports. */
    private TokenProfileFullModel changingProfile() throws Exception {
        ImmutableTokenInstanceFullModel token = importingToken();
        TokenProfileFullModel profile = profile(token, true, null);
        List<TransferableKeyType> answer = List
                .of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(KeyAlgorithm.RSA)));
        when(adapters.forToken(token)).thenReturn(adapter);
        when(adapter.listImportableKeyTypes(profile)).thenReturn(answer);
        when(writer.recordAnswer(profile.uuid(), profile.keyTypesRevision(), KeyTransfer.IMPORT, answer))
                .thenReturn(Optional.empty());
        return profile;
    }

    /** Matches the secured form of the UUID, which compares by identity. */
    private static SecuredUUID secured(UUID uuid) {
        return argThat(secured -> secured != null && uuid.equals(secured.getValue()));
    }

    private static ImmutableTokenInstanceFullModel importingToken() {
        return token(FeatureFlag.STATELESS, FeatureFlag.KEY_IMPORT);
    }

    private static ImmutableTokenInstanceFullModel token(FeatureFlag... features) {
        ImmutableConnectorInterface connectorInterface = new ImmutableConnectorInterface(UUID.randomUUID(),
                ConnectorInterface.CRYPTOGRAPHY, "v2", List.of(features));
        return new ImmutableTokenInstanceFullModel(UUID.randomUUID(), UUID.randomUUID().toString(), "token",
                TokenInstanceStatus.ACTIVATED, null, UUID.randomUUID(), "connector", connectorInterface.uuid(),
                connectorInterface, Set.of());
    }

    private static TokenProfileFullModel profile(ImmutableTokenInstanceFullModel token, boolean enabled,
            Map<KeyRequestType, Set<KeyAlgorithm>> importableKeyTypes) {
        return new ImmutableTokenProfileFullModel(UUID.randomUUID(), "importer", null, token.name(), token.uuid(),
                enabled, List.of(), token, token.connectorUuid(), null, importableKeyTypes, 0);
    }
}
