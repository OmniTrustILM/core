package com.otilm.core.signing.rawsigning;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.OneTimeKeyManagedSigningRequestDto;
import com.otilm.api.model.client.signing.profile.workflow.SigningWorkflowType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RawSigningProfileRulesTest {

    // ── RefuseOneTimeKey ──────────────────────────────────────────────────────

    @Nested
    class RefuseOneTimeKey {

        @Test
        void refusesOneTimeKey_whenWorkflowIsRaw() {
            // given
            var oneTimeKeyScheme = new OneTimeKeyManagedSigningRequestDto();

            // when
            ThrowingCallable refuse = () -> RawSigningProfileRules.refuseOneTimeKey(oneTimeKeyScheme);

            // then
            assertThatThrownBy(refuse)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(ManagedSigningType.ONE_TIME_KEY.name());
        }
    }

    // ── RequireDataDigestSigning ───────────────────────────────────────────────

    @Nested
    class RequireDataDigestSigning {

        @Test
        void refusesSignatureAlgorithm_whenOutsideTheBound() {
            // given
            var signsItsOwnMessage = SignatureAlgorithm.ML_DSA_65;

            // when
            ThrowingCallable require = () -> RawSigningProfileRules.requireDataDigestSigning(signsItsOwnMessage);

            // then
            assertThatThrownBy(require)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(signsItsOwnMessage.getCode());
        }

        @Test
        void refusesSignatureAlgorithm_whenNoneIsGiven() {
            // given
            SignatureAlgorithm noSignatureAlgorithm = null;

            // when
            ThrowingCallable require = () -> RawSigningProfileRules.requireDataDigestSigning(noSignatureAlgorithm);

            // then
            assertThatThrownBy(require)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining("cannot sign a data digest");
        }

        @ParameterizedTest
        @EnumSource(value = SignatureAlgorithm.class,
                names = {"SHA256_WITH_RSA", "SHA384_WITH_RSA_PSS", "SHA512_WITH_ECDSA"})
        void admitsSignatureAlgorithm_whenRsaRsaPssOrEcdsa(SignatureAlgorithm signsAGivenDigest) {
            // given — an algorithm that signs a digest it is handed

            // when
            ThrowingCallable require = () -> RawSigningProfileRules.requireDataDigestSigning(signsAGivenDigest);

            // then
            assertThatCode(require).doesNotThrowAnyException();
        }
    }

    // ── ConflictingWorkflows ──────────────────────────────────────────────────

    @Nested
    class ConflictingWorkflows {

        @Test
        void returnsContentSigningAndTimestamping_whenWorkflowIsRaw() {
            // given
            var raw = SigningWorkflowType.RAW_SIGNING;

            // when
            Set<SigningWorkflowType> conflicting = RawSigningProfileRules.conflictingWorkflows(raw);

            // then
            assertThat(conflicting)
                    .containsExactlyInAnyOrder(SigningWorkflowType.CONTENT_SIGNING, SigningWorkflowType.TIMESTAMPING);
        }

        @ParameterizedTest
        @EnumSource(value = SigningWorkflowType.class, names = {"CONTENT_SIGNING", "TIMESTAMPING"})
        void returnsRawSigningOnly_whenWorkflowIsNotRaw(SigningWorkflowType notRaw) {
            // given — a workflow that signs only what it formats itself

            // when
            Set<SigningWorkflowType> conflicting = RawSigningProfileRules.conflictingWorkflows(notRaw);

            // then
            assertThat(conflicting).containsExactly(SigningWorkflowType.RAW_SIGNING);
        }
    }

    // ── RefuseSharedSigningKey ────────────────────────────────────────────────

    @Nested
    class RefuseSharedSigningKey {

        @Test
        void namesProfilesOfAnotherWorkflow_whenSavingARawProfile() {
            // given
            var certificateUuid = UUID.randomUUID();
            var contentAndTimestampingProfiles = List.of("content-signing-profile", "timestamping-profile");

            // when
            ThrowingCallable refuse = () -> RawSigningProfileRules
                    .refuseSharedSigningKey(SigningWorkflowType.RAW_SIGNING, certificateUuid,
                            contentAndTimestampingProfiles);

            // then
            assertThatThrownBy(refuse)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(certificateUuid.toString())
                    .hasMessageContaining("signs, or has signed, for Signing Profile(s) of another workflow")
                    .hasMessageContaining(String.join(", ", contentAndTimestampingProfiles));
        }

        @ParameterizedTest
        @EnumSource(value = SigningWorkflowType.class, names = {"CONTENT_SIGNING", "TIMESTAMPING"})
        void namesRawProfiles_whenSavingAProfileOfAnotherWorkflow(SigningWorkflowType notRaw) {
            // given
            var certificateUuid = UUID.randomUUID();
            var rawProfiles = List.of("raw-signing-profile");

            // when
            ThrowingCallable refuse = () -> RawSigningProfileRules
                    .refuseSharedSigningKey(notRaw, certificateUuid, rawProfiles);

            // then
            assertThatThrownBy(refuse)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(certificateUuid.toString())
                    .hasMessageContaining(
                            "signs, or has signed, raw digests for Signing Profile(s): raw-signing-profile");
        }

        @Test
        void admitsKey_whenNoConflictingProfileSignsWithIt() {
            // given — no profile of a conflicting workflow signs with the key
            var certificateUuid = UUID.randomUUID();
            List<String> noConflictingProfiles = List.of();

            // when
            ThrowingCallable refuse = () -> RawSigningProfileRules
                    .refuseSharedSigningKey(SigningWorkflowType.RAW_SIGNING, certificateUuid, noConflictingProfiles);

            // then
            assertThatCode(refuse).doesNotThrowAnyException();
        }
    }
}
