package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.connector.signatures.contentsigning.common.DigestOnlyDocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.InlineDocumentTransferDto;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.InstanceOfAssertFactories.type;

class SignatureDigestCoherenceTest {

    private static final byte[] DOCUMENT = "content".getBytes();

    @Test
    void acceptsAnInlineTransferWhoseAuthorizedDigestIsTheOneTheAlgorithmSigns() {
        assertThatCode(() -> SignatureDigestCoherence
                .requireCoherent(SignatureAlgorithm.SHA256_WITH_RSA, digest(DigestAlgorithm.SHA_256), inline()))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsADigestOnlyTransferUnderTheAlgorithmsOwnDigest() {
        assertThatCode(() -> SignatureDigestCoherence
                .requireCoherent(SignatureAlgorithm.SHA512_WITH_ECDSA, digest(DigestAlgorithm.SHA_512),
                        digestOnly(DigestAlgorithm.SHA_512)))
                .doesNotThrowAnyException();
    }

    @Test
    void acceptsAnAlgorithmWhoseDigestItsNameDoesNotSpell() {
        assertThatCode(() -> SignatureDigestCoherence
                .requireCoherent(SignatureAlgorithm.ML_DSA_65, digest(DigestAlgorithm.SHA_512), inline()))
                .doesNotThrowAnyException();
    }

    /**
     * The case the check exists for: without it the run reaches {@code computeDtbs}, and the connector's echo of the
     * only digest the request lets it produce is then reported as a connector fault.
     */
    @Test
    void refusesAsInvalidInput_whenTheAuthorizedDigestIsNotTheOneTheAlgorithmSigns() {
        assertThatThrownBy(() -> SignatureDigestCoherence
                .requireCoherent(SignatureAlgorithm.SHA512_WITH_RSA, digest(DigestAlgorithm.SHA_256), inline()))
                .asInstanceOf(type(SigningEngineException.class))
                .satisfies(e -> {
                    assertThat(e.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
                    assertThat(e.operatorMessage()).contains("SHA-256", "SHA512withRSA", "SHA-512");
                    assertThat(e.clientMessage()).contains("SHA-256", "SHA-512");
                });
    }

    /** The submitted digest is checked in its own right, not against whatever the authorized digest was. */
    @Test
    void refusesAsInvalidInput_whenOnlyTheSubmittedDigestDisagrees() {
        assertThatThrownBy(() -> SignatureDigestCoherence
                .requireCoherent(SignatureAlgorithm.SHA256_WITH_RSA_PSS, digest(DigestAlgorithm.SHA_256),
                        digestOnly(DigestAlgorithm.SHA3_256)))
                .asInstanceOf(type(SigningEngineException.class))
                .satisfies(e -> {
                    assertThat(e.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
                    assertThat(e.operatorMessage()).contains("submitted document digest", "SHA3-256", "SHA-256");
                });
    }

    /** A digest-only transfer that names no algorithm is a caller's malformed request, not a platform defect. */
    @Test
    void refusesAsInvalidInput_whenTheSubmittedDigestNamesNoAlgorithm() {
        assertThatThrownBy(() -> SignatureDigestCoherence
                .requireCoherent(SignatureAlgorithm.SHA256_WITH_RSA, digest(DigestAlgorithm.SHA_256),
                        new DigestOnlyDocumentTransferDto(new byte[32], null)))
                .asInstanceOf(type(SigningEngineException.class))
                .satisfies(e -> {
                    assertThat(e.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
                    assertThat(e.operatorMessage()).contains("submitted document digest", "names no digest algorithm");
                    assertThat(e.clientMessage()).contains("SHA-256");
                });
    }

    /**
     * Ed448 signs a SHAKE256 digest, which is no {@code DigestAlgorithm}, so it can never fill the echo the binding
     * gate compares. That makes it unusable for content signing whatever the caller sends.
     */
    @Test
    void refusesAsMisconfigured_whenTheAlgorithmCommitsToADigestThePlatformCannotName() {
        assertThatThrownBy(() -> SignatureDigestCoherence
                .requireCoherent(SignatureAlgorithm.ED448, digest(DigestAlgorithm.SHA_512), inline()))
                .asInstanceOf(type(SigningEngineException.class))
                .satisfies(e -> {
                    assertThat(e.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
                    assertThat(e.operatorMessage()).contains("Ed448", "OID");
                    assertThat(e.clientMessage()).contains("Ed448");
                });
    }

    /** Ed448 is the only pre-flight refusal. */
    @Test
    void everyOtherAlgorithmCommitsToADigestThePlatformCanName() {
        for (SignatureAlgorithm algorithm : SignatureAlgorithm.values()) {
            if (algorithm == SignatureAlgorithm.ED448) {
                continue;
            }
            DigestAlgorithm committed = DigestAlgorithm
                    .findByOid(algorithm.getDigestAlgorithmIdentifier().getAlgorithm().getId());
            assertThatCode(() -> SignatureDigestCoherence.requireCoherent(algorithm, digest(committed), inline()))
                    .as("%s over its own %s digest", algorithm.getCode(), committed.getCode())
                    .doesNotThrowAnyException();
        }
    }

    private static DocumentDigest digest(DigestAlgorithm algorithm) {
        return new DocumentDigest(algorithm, new byte[algorithm.getDigestSizeBytes()]);
    }

    private static DocumentTransferDto inline() {
        return new InlineDocumentTransferDto(DOCUMENT);
    }

    private static DocumentTransferDto digestOnly(DigestAlgorithm algorithm) {
        return new DigestOnlyDocumentTransferDto(new byte[algorithm.getDigestSizeBytes()], algorithm);
    }
}
