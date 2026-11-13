package com.otilm.core.signing.rawsigning;

import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RawSignedItemTest {

    private static final String IDENTIFIER = "doc-1";

    private static final UUID RECORD_UUID = UUID.fromString("00000000-0000-0000-0000-0000000000a1");

    @Test
    void keepsItsSignature_whenTheCallerChangesTheArrayItPassedIn() {
        // given
        byte[] callerBuffer = aSignature();
        var item = new RawSignedItem(IDENTIFIER, callerBuffer, RECORD_UUID);

        // when
        callerBuffer[0] ^= 0x01;

        // then
        assertThat(item.signature()).isEqualTo(aSignature());
    }

    @Test
    void keepsItsSignature_whenAConsumerChangesTheArrayItReadOut() {
        // given
        var item = new RawSignedItem(IDENTIFIER, aSignature(), RECORD_UUID);

        // when
        item.signature()[0] ^= 0x01;

        // then
        assertThat(item.signature()).isEqualTo(aSignature());
    }

    @Test
    void equalsWithTheSameHashCode_whenEveryComponentMatches() {
        // given
        var item = new RawSignedItem(IDENTIFIER, aSignature(), RECORD_UUID);
        var sameContentInAnotherArray = new RawSignedItem(IDENTIFIER, aSignature(), RECORD_UUID);

        // when
        boolean equal = item.equals(sameContentInAnotherArray);

        // then
        assertThat(equal).isTrue();
        assertThat(item.hashCode()).isEqualTo(sameContentInAnotherArray.hashCode());
    }

    @Test
    void differs_whenSignatureContentDiffers() {
        // given
        byte[] otherSignature = aSignature();
        otherSignature[63] ^= 0x01;
        var item = new RawSignedItem(IDENTIFIER, aSignature(), RECORD_UUID);

        // when
        boolean equal = item.equals(new RawSignedItem(IDENTIFIER, otherSignature, RECORD_UUID));

        // then
        assertThat(equal).isFalse();
    }

    @Test
    void differs_whenOnlyOneCarriesARecord() {
        // given
        UUID noRecord = null;
        var recorded = new RawSignedItem(IDENTIFIER, aSignature(), RECORD_UUID);

        // when
        boolean equal = recorded.equals(new RawSignedItem(IDENTIFIER, aSignature(), noRecord));

        // then
        assertThat(equal).isFalse();
    }

    @Test
    void printsTheSignatureLengthOnly_whenRendered() {
        // given
        byte[] signature = aSignature();
        var item = new RawSignedItem(IDENTIFIER, signature, RECORD_UUID);

        // when
        String printed = item.toString();

        // then
        assertThat(printed)
                .contains(IDENTIFIER)
                .contains(signature.length + " bytes")
                .contains(RECORD_UUID.toString())
                .doesNotContain(HexFormat.of().formatHex(signature))
                .doesNotContain(Base64.getEncoder().encodeToString(signature))
                .doesNotContain(Arrays.toString(signature));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] aSignature() {
        byte[] signature = new byte[64];
        Arrays.fill(signature, (byte) 0x3C);
        return signature;
    }
}
