package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class SignatureDigestCoherenceTest {

    @Test
    void acceptsTheDigestTheAlgorithmSigns() {
        // given
        var signsSha256 = SignatureAlgorithm.SHA256_WITH_RSA;

        // when
        ThrowingCallable check = () -> SignatureDigestCoherence.requireCoherent(signsSha256, DigestAlgorithm.SHA_256);

        // then
        assertThatCode(check).doesNotThrowAnyException();
    }

    @Test
    void acceptsAnAlgorithmWhoseDigestItsNameDoesNotSpell() {
        // given
        var signsSha512 = SignatureAlgorithm.ML_DSA_65;

        // when
        ThrowingCallable check = () -> SignatureDigestCoherence.requireCoherent(signsSha512, DigestAlgorithm.SHA_512);

        // then
        assertThatCode(check).doesNotThrowAnyException();
    }

    /**
     * The case the check exists for: without it the run reaches {@code computeDtbs}, and the connector's echo of the
     * only digest the request lets it produce is then reported as a connector fault.
     */
    @Test
    void refusesAsInvalidInput_whenTheDigestIsNotTheOneTheAlgorithmSigns() {
        // given
        var signsSha512 = SignatureAlgorithm.SHA512_WITH_RSA;

        // when
        ThrowingCallable check = () -> SignatureDigestCoherence.requireCoherent(signsSha512, DigestAlgorithm.SHA_256);

        // then
        assertThatThrownBy(check).isInstanceOfSatisfying(SigningEngineException.class, e -> {
            assertThat(e.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            assertThat(e.operatorMessage()).contains("SHA-256", "SHA512withRSA", "SHA-512");
            assertThat(e.clientMessage()).contains("SHA-256", "SHA-512");
        });
    }

    /**
     * Ed448 signs a SHAKE256 digest, which is no {@code DigestAlgorithm}, so it can never fill the echo the binding
     * gate compares. That makes it unusable for content signing whatever the caller sends.
     */
    @Test
    void refusesAsMisconfigured_whenTheAlgorithmCommitsToADigestThePlatformCannotName() {
        // given
        var signsShake256 = SignatureAlgorithm.ED448;

        // when
        ThrowingCallable check = () -> SignatureDigestCoherence.requireCoherent(signsShake256, DigestAlgorithm.SHA_512);

        // then
        assertThatThrownBy(check).isInstanceOfSatisfying(SigningEngineException.class, e -> {
            assertThat(e.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            assertThat(e.operatorMessage()).contains("Ed448", "OID");
            assertThat(e.clientMessage()).contains("Ed448");
        });
    }

    /** Ed448 is the one algorithm refused as misconfigured. */
    @ParameterizedTest
    @EnumSource(value = SignatureAlgorithm.class, names = "ED448", mode = EnumSource.Mode.EXCLUDE)
    void acceptsEveryOtherAlgorithmOverItsOwnDigest(SignatureAlgorithm algorithm) {
        // given
        DigestAlgorithm committed = DigestAlgorithm
                .findByOid(algorithm.getDigestAlgorithmIdentifier().getAlgorithm().getId());

        // when
        ThrowingCallable check = () -> SignatureDigestCoherence.requireCoherent(algorithm, committed);

        // then
        assertThatCode(check).doesNotThrowAnyException();
    }
}
