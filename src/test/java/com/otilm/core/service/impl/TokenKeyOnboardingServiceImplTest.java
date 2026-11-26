package com.otilm.core.service.impl;

import com.otilm.api.model.client.cryptography.key.OnboardTokenKeysRequestDto;
import com.otilm.api.model.client.cryptography.key.TokenKeySelectionDto;
import com.otilm.api.model.connector.cryptography.v2.key.KeyEntryStatus;
import com.otilm.api.model.core.cryptography.key.TokenKeyOnboardingOutcome;
import com.otilm.api.model.core.cryptography.key.TokenKeyOnboardingResultDto;
import com.otilm.api.model.core.cryptography.key.TokenKeyStatus;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.dao.repository.CryptographicKeyRepository;
import com.otilm.core.dao.repository.KeyImportRepository;
import com.otilm.core.model.crypto.ImmutableTokenProfileFullModel;
import com.otilm.core.model.crypto.ProviderKeyEntry;
import com.otilm.core.model.crypto.ProviderKeyEntryPage;
import com.otilm.core.model.crypto.ProviderKeyPair;
import com.otilm.core.model.crypto.PublicKeyHolder.Holding;
import com.otilm.core.model.crypto.PublicKeyHolderSummary;
import com.otilm.core.service.handler.KeyImportGates;
import com.otilm.core.service.handler.KeyListGates;
import com.otilm.core.service.handler.key.KeyProviderAdapter;
import com.otilm.core.service.handler.key.KeyProviderAdapterFactory;
import com.otilm.core.service.writer.CryptographicKeyWriter;
import com.otilm.core.util.CryptographyUtil;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.dao.DuplicateKeyException;

import static com.otilm.core.util.builders.ProviderKeyPairBuilder.aProviderKeyPair;
import static com.otilm.core.util.builders.TokenProfileFullModelBuilder.aTokenProfileSnapshot;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Drives the service with answers only a mocked adapter or writer gives, such as a listed invalid handle. */
@ExtendWith(MockitoExtension.class)
class TokenKeyOnboardingServiceImplTest {

    private final ImmutableTokenProfileFullModel profile = aTokenProfileSnapshot().build();

    @Mock
    private KeyListGates keyListGates;
    @Mock
    private KeyImportGates keyImportGates;
    @Mock
    private KeyProviderAdapterFactory keyProviderAdapterFactory;
    @Mock
    private KeyProviderAdapter keyProviderAdapter;
    @Mock
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Mock
    private KeyImportRepository keyImportRepository;
    @Mock
    private CryptographicKeyWriter cryptographicKeyWriter;
    @Mock
    private AttributeEngine attributeEngine;

    @InjectMocks
    private TokenKeyOnboardingServiceImpl service;

    @BeforeEach
    void stubTheTokensAdapter() throws Exception {
        when(keyListGates.requireListable(profile.tokenInstanceReferenceUuid(), profile.uuid())).thenReturn(profile);
        when(keyProviderAdapterFactory.forToken(profile.tokenInstance())).thenReturn(keyProviderAdapter);
    }

    // ── ListTokenKeys ─────────────────────────────────────────────────────────

    @Nested
    class ListTokenKeys {

        @Test
        void throwsNamingTheResolutionOnlyStatus_whenTheConnectorListsAnInvalidHandle() throws Exception {
            // given
            var invalidHandle = new ProviderKeyEntry(KeyEntryStatus.INVALID_HANDLE, null, null, null, null, null);
            when(keyProviderAdapter.listKeyPairs(profile, 0, 10))
                    .thenReturn(new ProviderKeyEntryPage(List.of(invalidHandle), 1));

            // when
            ThrowingCallable listTokenKeys = () -> service
                    .listTokenKeys(profile.tokenInstanceReferenceUuid(), profile.uuid(), 1, 10);

            // then
            assertThatThrownBy(listTokenKeys)
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("which only a resolution reports");
        }
    }

    // ── OnboardTokenKeys ──────────────────────────────────────────────────────

    @Nested
    class OnboardTokenKeys {

        @Test
        void blocksTheKeyPairAsImportInProgress_whenAnImportOpensBeforeItIsWrittenAsAKeyOfItsOwn() throws Exception {
            // given
            ProviderKeyPair pair = aProviderKeyPair().build();
            resolves(pair);
            when(cryptographicKeyWriter
                    .onboardUnlessImporting(any(), eq(profile), eq(fingerprintOf(pair)), any(), any(), any()))
                    .thenReturn(Optional.empty());

            // when
            TokenKeyOnboardingResultDto result = onboard(pair);

            // then
            assertImportInProgress(result);
            verify(cryptographicKeyWriter)
                    .onboardUnlessImporting(any(), eq(profile), eq(fingerprintOf(pair)), any(), any(), any());
        }

        @Test
        void blocksTheKeyPairAsImportInProgress_whenAnImportOpensBeforeItsPrivateKeyJoinsTheRecord() throws Exception {
            // given
            ProviderKeyPair pair = aProviderKeyPair().build();
            var recordUuid = UUID.randomUUID();
            var publicKeyRecord = new PublicKeyHolderSummary(recordUuid, "certKey_signer", null,
                    Holding.PUBLIC_KEY_ONLY, true);
            resolves(pair);
            when(cryptographicKeyWriter.holdersOf(any())).thenReturn(Map.of(fingerprintOf(pair), publicKeyRecord));
            when(cryptographicKeyWriter
                    .onboardIntoRecordUnlessImporting(eq(recordUuid), eq(profile), eq(fingerprintOf(pair)), any()))
                    .thenReturn(Optional.empty());

            // when
            TokenKeyOnboardingResultDto result = onboard(pair);

            // then
            assertImportInProgress(result);
            verify(cryptographicKeyWriter)
                    .onboardIntoRecordUnlessImporting(eq(recordUuid), eq(profile), eq(fingerprintOf(pair)), any());
        }

        @Test
        void blocksWithoutNamingTheKey_whenTheCallerMayNotSeeTheKeyThatWonTheRace() throws Exception {
            // given
            ProviderKeyPair pair = aProviderKeyPair().build();
            var winnerUuid = UUID.randomUUID();
            var winnerTokenUuid = UUID.randomUUID();
            var hiddenWinner = new PublicKeyHolderSummary(winnerUuid, "winner", winnerTokenUuid, Holding.KEY_PAIR,
                    true);
            resolves(pair);
            when(cryptographicKeyWriter.holdersOf(any()))
                    .thenReturn(Map.of(), Map.of(fingerprintOf(pair), hiddenWinner));
            when(cryptographicKeyWriter
                    .onboardUnlessImporting(any(), eq(profile), eq(fingerprintOf(pair)), any(), any(), any()))
                    .thenThrow(new DuplicateKeyException("public key fingerprint taken"));
            when(keyImportGates.maySeeInDetail(winnerUuid, winnerTokenUuid)).thenReturn(false);

            // when
            TokenKeyOnboardingResultDto result = onboard(pair);

            // then
            assertThat(result)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getStatus,
                            TokenKeyOnboardingResultDto::getReason, TokenKeyOnboardingResultDto::getKeyUuid,
                            TokenKeyOnboardingResultDto::getKeyName)
                    .containsExactly(TokenKeyOnboardingOutcome.BLOCKED, TokenKeyStatus.IN_INVENTORY,
                            TokenKeyOnboardingServiceImpl.HELD_MEANWHILE, null, null);
        }

        @Test
        void blocksThePrivateKeyAloneAsImportInProgress_whenAKeyPairImportOpensBeforeItIsWritten() throws Exception {
            // given
            ProviderKeyPair pair = aProviderKeyPair().withoutPublicKey().build();
            resolves(pair);
            when(cryptographicKeyWriter.onboardUnlessImporting(any(), eq(profile), eq(null), any(), any(), any()))
                    .thenReturn(Optional.empty());

            // when
            TokenKeyOnboardingResultDto result = onboard(pair);

            // then
            assertThat(result)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getStatus,
                            TokenKeyOnboardingResultDto::getReason)
                    .containsExactly(TokenKeyOnboardingOutcome.BLOCKED, TokenKeyStatus.IMPORT_IN_PROGRESS,
                            TokenKeyOnboardingServiceImpl.IMPORTING_ON_TOKEN);
        }

        @Test
        void failsThePrivateKeyAlone_whenTheKeyThatTookItsHandleIsGoneBeforeTheRetryLooks() throws Exception {
            // given
            ProviderKeyPair pair = aProviderKeyPair().withoutPublicKey().build();
            resolves(pair);
            when(cryptographicKeyWriter.onboardUnlessImporting(any(), eq(profile), eq(null), any(), any(), any()))
                    .thenThrow(new DuplicateKeyException("handle digest taken"));

            // when
            TokenKeyOnboardingResultDto result = onboard(pair);

            // then
            assertThat(result)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getReason)
                    .containsExactly(TokenKeyOnboardingOutcome.FAILED, TokenKeyOnboardingServiceImpl.ONBOARDING_FAILED);
            verify(cryptographicKeyWriter, times(2))
                    .holdersOfHandles(profile.tokenInstanceReferenceUuid(), Set.of(pair.privateKey().handleDigest()));
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private void resolves(ProviderKeyPair pair) throws Exception {
            var available = new ProviderKeyEntry(KeyEntryStatus.AVAILABLE, null, "signer", pair, null, null);
            when(keyProviderAdapter.resolveKeyPairs(profile, List.of(pair.keyPairMeta())))
                    .thenReturn(List.of(available));
        }

        private TokenKeyOnboardingResultDto onboard(ProviderKeyPair pair) throws Exception {
            var selection = new TokenKeySelectionDto(pair.keyPairMeta(), null);
            return service
                    .onboardTokenKeys(profile.tokenInstanceReferenceUuid(), profile.uuid(),
                            new OnboardTokenKeysRequestDto(List.of(selection), null))
                    .getResults()
                    .getFirst();
        }

        private static String fingerprintOf(ProviderKeyPair pair) {
            return CryptographyUtil.calculateKeyFingerprint(pair.publicKey().material());
        }

        private static void assertImportInProgress(TokenKeyOnboardingResultDto result) {
            assertThat(result)
                    .extracting(TokenKeyOnboardingResultDto::getOutcome, TokenKeyOnboardingResultDto::getStatus,
                            TokenKeyOnboardingResultDto::getReason)
                    .containsExactly(TokenKeyOnboardingOutcome.BLOCKED, TokenKeyStatus.IMPORT_IN_PROGRESS,
                            TokenKeyOnboardingServiceImpl.IMPORTING);
        }
    }
}
