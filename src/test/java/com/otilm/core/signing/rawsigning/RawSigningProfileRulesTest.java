package com.otilm.core.signing.rawsigning;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.profile.scheme.ManagedSigningType;
import com.otilm.api.model.client.signing.profile.scheme.OneTimeKeyManagedSigningRequestDto;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import java.util.List;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

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

    // ── RequirePrehashedSigning ───────────────────────────────────────────────

    @Nested
    class RequirePrehashedSigning {

        @Test
        void refusesSignatureAlgorithm_whenOutsideTheBound() {
            // given
            var signsItsOwnMessage = SignatureAlgorithm.ML_DSA_65;

            // when
            ThrowingCallable require = () -> RawSigningProfileRules.requirePrehashedSigning(signsItsOwnMessage);

            // then
            assertThatThrownBy(require)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(signsItsOwnMessage.getCode());
        }

        @ParameterizedTest
        @EnumSource(value = SignatureAlgorithm.class,
                names = {"SHA256_WITH_RSA", "SHA384_WITH_RSA_PSS", "SHA512_WITH_ECDSA"})
        void admitsSignatureAlgorithm_whenRsaRsaPssOrEcdsa(SignatureAlgorithm signsAGivenDigest) {
            // given — an algorithm that signs a digest it is handed

            // when
            ThrowingCallable require = () -> RawSigningProfileRules.requirePrehashedSigning(signsAGivenDigest);

            // then
            assertThatCode(require).doesNotThrowAnyException();
        }
    }

    // ── RefuseCertificateHeldByAnotherWorkflow ────────────────────────────────

    @Nested
    class RefuseCertificateHeldByAnotherWorkflow {

        @Test
        void refusesCertificate_whenProfilesOfAnotherWorkflowHoldIt() {
            // given
            var certificateUuid = UUID.randomUUID();
            var holders = List.of("content-signing-profile", "timestamping-profile");

            // when
            ThrowingCallable refuse = () -> RawSigningProfileRules
                    .refuseCertificateHeldByAnotherWorkflow(certificateUuid, holders);

            // then
            assertThatThrownBy(refuse)
                    .isInstanceOf(ValidationException.class)
                    .hasMessageContaining(certificateUuid.toString())
                    .hasMessageContaining("content-signing-profile, timestamping-profile");
        }

        @Test
        void admitsCertificate_whenNoProfileOfAnotherWorkflowHoldsIt() {
            // given — no profile of another workflow holds the certificate
            var certificateUuid = UUID.randomUUID();
            List<String> noHolders = List.of();

            // when
            ThrowingCallable refuse = () -> RawSigningProfileRules
                    .refuseCertificateHeldByAnotherWorkflow(certificateUuid, noHolders);

            // then
            assertThatCode(refuse).doesNotThrowAnyException();
        }
    }
}
