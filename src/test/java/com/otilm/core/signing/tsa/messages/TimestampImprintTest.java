package com.otilm.core.signing.tsa.messages;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class TimestampImprintTest {

    private static final byte[] VALUE = new byte[]{0x0a, 0x0b};

    /** A record's generated equality would compare the array by identity, so two equal digests would differ. */
    @Test
    void comparesTheImprintByValueRatherThanByArrayIdentity() {
        // given
        TimestampImprint imprint = new TimestampImprint(DigestAlgorithm.SHA_256, VALUE);
        TimestampImprint equalImprint = new TimestampImprint(DigestAlgorithm.SHA_256, VALUE.clone());

        // when / then
        assertThat(imprint).isEqualTo(equalImprint).hasSameHashCodeAs(equalImprint);
    }

    @Test
    void tellsImprintsApartByValueAndByAlgorithm() {
        // given
        TimestampImprint imprint = new TimestampImprint(DigestAlgorithm.SHA_256, VALUE);
        Object notAnImprint = "not an imprint";

        // when / then
        assertThat(imprint)
                .isNotEqualTo(new TimestampImprint(DigestAlgorithm.SHA_256, new byte[]{0x0a, 0x0c}))
                .isNotEqualTo(new TimestampImprint(DigestAlgorithm.SHA_512, VALUE))
                .isNotEqualTo(notAnImprint)
                .isEqualTo(imprint);
    }

    @Test
    void rendersTheImprintLegiblyForALogLine() {
        // when / then
        assertThat(new TimestampImprint(DigestAlgorithm.SHA_256, VALUE)).hasToString("TimestampImprint[SHA-256:0a0b]");
    }

    @Test
    void refusesToExistWithoutBothHalves() {
        // when / then
        assertThatNullPointerException().isThrownBy(() -> new TimestampImprint(null, VALUE));
        assertThatNullPointerException().isThrownBy(() -> new TimestampImprint(DigestAlgorithm.SHA_256, null));
    }

    /** A digest that is not as long as its algorithm produces came from no document. */
    @Test
    void knowsWhetherItIsAsLongAsItsAlgorithmProduces() {
        // given
        byte[] full = new byte[32];
        TimestampImprint wellFormed = new TimestampImprint(DigestAlgorithm.SHA_256, full);
        TimestampImprint tooShort = new TimestampImprint(DigestAlgorithm.SHA_256, VALUE);

        // when / then
        assertThat(wellFormed.hasLengthOfItsAlgorithm()).isTrue();
        assertThat(tooShort.hasLengthOfItsAlgorithm()).isFalse();
    }

    @Test
    void reportsItsLengthWithoutCopyingTheDigest() {
        // when / then
        assertThat(new TimestampImprint(DigestAlgorithm.SHA_256, VALUE).length()).isEqualTo(2);
    }

    @Test
    void survivesMutationOfTheArrayItWasBuiltFrom() {
        // given
        byte[] source = VALUE.clone();
        TimestampImprint imprint = new TimestampImprint(DigestAlgorithm.SHA_256, source);

        // when
        source[0] = 0x7f;

        // then
        assertThat(imprint.value()).containsExactly(VALUE);
    }

    @Test
    void survivesMutationThroughItsOwnAccessor() {
        // given
        TimestampImprint imprint = new TimestampImprint(DigestAlgorithm.SHA_256, VALUE);

        // when
        imprint.value()[0] = 0x7f;

        // then
        assertThat(imprint.value()).containsExactly(VALUE);
    }
}
