package com.otilm.core.signing.tsa.messages;

import java.math.BigInteger;
import java.time.Instant;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class IssuedTimestampTest {

    private static final byte[] TOKEN = new byte[]{0x0a, 0x0b};

    private static final BigInteger SERIAL = BigInteger.valueOf(255);

    private static final Instant GEN_TIME = Instant.parse("2026-08-19T10:15:30Z");

    @Test
    void comparesTheTokenByValueRatherThanByArrayIdentity() {
        // given
        IssuedTimestamp issued = new IssuedTimestamp(TOKEN, SERIAL, GEN_TIME);
        IssuedTimestamp equalIssued = new IssuedTimestamp(TOKEN.clone(), SERIAL, GEN_TIME);

        // when / then
        assertThat(issued).isEqualTo(equalIssued).hasSameHashCodeAs(equalIssued);
    }

    @Test
    void tellsIssuedTimestampsApartByEveryComponent() {
        // given
        IssuedTimestamp issued = new IssuedTimestamp(TOKEN, SERIAL, GEN_TIME);
        Object notAnIssuedTimestamp = "not an issued timestamp";

        // when / then
        assertThat(issued)
                .isNotEqualTo(new IssuedTimestamp(new byte[]{0x0a, 0x0c}, SERIAL, GEN_TIME))
                .isNotEqualTo(new IssuedTimestamp(TOKEN, BigInteger.ONE, GEN_TIME))
                .isNotEqualTo(new IssuedTimestamp(TOKEN, SERIAL, GEN_TIME.plusSeconds(1)))
                .isNotEqualTo(notAnIssuedTimestamp)
                .isEqualTo(issued);
    }

    /** The token is far too long to belong in a log line, so only its length is rendered. */
    @Test
    void rendersTheSerialAndGenerationTimeButNotTheToken() {
        // when / then
        assertThat(new IssuedTimestamp(TOKEN, SERIAL, GEN_TIME))
                .hasToString("IssuedTimestamp[serialNumber=ff, genTime=2026-08-19T10:15:30Z, encoded=2 bytes]");
    }

    @Test
    void refusesToExistWithoutAllThreeComponents() {
        // when / then
        assertThatNullPointerException().isThrownBy(() -> new IssuedTimestamp(null, SERIAL, GEN_TIME));
        assertThatNullPointerException().isThrownBy(() -> new IssuedTimestamp(TOKEN, null, GEN_TIME));
        assertThatNullPointerException().isThrownBy(() -> new IssuedTimestamp(TOKEN, SERIAL, null));
    }

    @Test
    void survivesMutationOfTheArrayItWasBuiltFrom() {
        // given
        byte[] source = TOKEN.clone();
        IssuedTimestamp issued = new IssuedTimestamp(source, SERIAL, GEN_TIME);

        // when
        source[0] = 0x7f;

        // then
        assertThat(issued.encoded()).containsExactly(TOKEN);
    }

    @Test
    void survivesMutationThroughItsOwnAccessor() {
        // given
        IssuedTimestamp issued = new IssuedTimestamp(TOKEN, SERIAL, GEN_TIME);

        // when
        issued.encoded()[0] = 0x7f;

        // then
        assertThat(issued.encoded()).containsExactly(TOKEN);
    }
}
