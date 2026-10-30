package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class DocumentDigestTest {

    private static final byte[] VALUE = new byte[]{0x0a, 0x0b};

    @Test
    void comparesTheDigestByValueRatherThanByArrayIdentity() {
        // given
        DocumentDigest digest = new DocumentDigest(DigestAlgorithm.SHA_256, VALUE);
        DocumentDigest equalDigest = new DocumentDigest(DigestAlgorithm.SHA_256, VALUE.clone());

        // when / then
        assertThat(digest).isEqualTo(equalDigest).hasSameHashCodeAs(equalDigest);
    }

    @Test
    void tellsDigestsApartByValueAndByAlgorithm() {
        // given
        DocumentDigest digest = new DocumentDigest(DigestAlgorithm.SHA_256, VALUE);
        Object notADigest = "not a digest";

        // when / then
        assertThat(digest)
                .isNotEqualTo(new DocumentDigest(DigestAlgorithm.SHA_256, new byte[]{0x0a, 0x0c}))
                .isNotEqualTo(new DocumentDigest(DigestAlgorithm.SHA_512, VALUE))
                .isNotEqualTo(notADigest)
                .isEqualTo(digest);
    }

    @Test
    void rendersTheDigestLegiblyForALogLine() {
        // when / then
        assertThat(new DocumentDigest(DigestAlgorithm.SHA_256, VALUE).toString()).contains("SHA-256", "0a0b");
    }

    @Test
    void recognisesADigestOfItsAlgorithmsLength() {
        // when / then
        assertThat(new DocumentDigest(DigestAlgorithm.SHA_256, new byte[32]).hasLengthOfItsAlgorithm()).isTrue();
        assertThat(new DocumentDigest(DigestAlgorithm.SHA_256, VALUE).hasLengthOfItsAlgorithm()).isFalse();
    }

    @Test
    void reportsItsLengthWithoutCopyingTheDigest() {
        // when / then
        assertThat(new DocumentDigest(DigestAlgorithm.SHA_256, VALUE).length()).isEqualTo(VALUE.length);
    }

    @Test
    void refusesToExistWithoutBothHalves() {
        // when / then
        assertThatNullPointerException().isThrownBy(() -> new DocumentDigest(null, VALUE));
        assertThatNullPointerException().isThrownBy(() -> new DocumentDigest(DigestAlgorithm.SHA_256, null));
    }

    /** The authorized digest is a security boundary, so a caller reusing its buffer must not be able to move it. */
    @Test
    void survivesMutationOfTheArrayItWasBuiltFrom() {
        // given
        byte[] source = VALUE.clone();
        DocumentDigest digest = new DocumentDigest(DigestAlgorithm.SHA_256, source);

        // when
        source[0] = 0x7f;

        // then
        assertThat(digest.value()).containsExactly(VALUE);
    }

    @Test
    void survivesMutationThroughItsOwnAccessor() {
        // given
        DocumentDigest digest = new DocumentDigest(DigestAlgorithm.SHA_256, VALUE);

        // when
        digest.value()[0] = 0x7f;

        // then
        assertThat(digest.value()).containsExactly(VALUE);
    }
}
