package com.otilm.core.signing.engine.signer;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.params.provider.EnumSource.Mode.EXCLUDE;

class PrehashedSigningTest {

    // ── Admits ────────────────────────────────────────────────────────────────

    @Nested
    class Admits {

        @ParameterizedTest
        @EnumSource(value = SignatureAlgorithm.class,
                names = {
                        "SHA256_WITH_RSA",
                        "SHA384_WITH_RSA",
                        "SHA512_WITH_RSA",
                        "SHA256_WITH_RSA_PSS",
                        "SHA384_WITH_RSA_PSS",
                        "SHA512_WITH_RSA_PSS",
                        "SHA256_WITH_ECDSA",
                        "SHA384_WITH_ECDSA",
                        "SHA512_WITH_ECDSA"})
        void returnsTrue_whenTheCodeIsInTheBound(SignatureAlgorithm algorithm) {
            // given — a code in the bound

            // when
            boolean admitted = PrehashedSigning.admits(algorithm);

            // then
            assertThat(admitted).isTrue();
        }

        @ParameterizedTest
        @EnumSource(value = SignatureAlgorithm.class, mode = EXCLUDE,
                names = {
                        "SHA256_WITH_RSA",
                        "SHA384_WITH_RSA",
                        "SHA512_WITH_RSA",
                        "SHA256_WITH_RSA_PSS",
                        "SHA384_WITH_RSA_PSS",
                        "SHA512_WITH_RSA_PSS",
                        "SHA256_WITH_ECDSA",
                        "SHA384_WITH_ECDSA",
                        "SHA512_WITH_ECDSA"})
        void returnsFalse_whenTheCodeIsOutsideTheBound(SignatureAlgorithm algorithm) {
            // given — a code outside the bound

            // when
            boolean admitted = PrehashedSigning.admits(algorithm);

            // then
            assertThat(admitted).isFalse();
        }

        @Test
        void returnsFalse_whenTheAlgorithmIsNull() {
            // given — no algorithm

            // when
            boolean admitted = PrehashedSigning.admits(null);

            // then
            assertThat(admitted).isFalse();
        }
    }

    // ── DigestAlgorithmLookup ─────────────────────────────────────────────────

    @Nested
    class DigestAlgorithmLookup {

        @ParameterizedTest
        @EnumSource(value = SignatureAlgorithm.class,
                names = {"SHA256_WITH_ECDSA", "SHA384_WITH_RSA_PSS", "SHA512_WITH_RSA"})
        void returnsTheHashOfTheCode(SignatureAlgorithm algorithm) {
            // given
            var expected = switch (algorithm) {
                case SHA256_WITH_ECDSA -> DigestAlgorithm.SHA_256;
                case SHA384_WITH_RSA_PSS -> DigestAlgorithm.SHA_384;
                default -> DigestAlgorithm.SHA_512;
            };

            // when
            DigestAlgorithm digest = PrehashedSigning.digestAlgorithm(algorithm);

            // then
            assertThat(digest).isEqualTo(expected);
        }

        @Test
        void throwsIllegalArgument_whenTheCodeIsOutsideTheBound() {
            // given
            var outsideTheBound = SignatureAlgorithm.ML_DSA_65;

            // when
            ThrowingCallable digestOf = () -> PrehashedSigning.digestAlgorithm(outsideTheBound);

            // then
            assertThatThrownBy(digestOf).isInstanceOf(IllegalArgumentException.class);
        }
    }
}
