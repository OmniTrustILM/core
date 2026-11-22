package com.otilm.core.signing.rawsigning;

import java.util.Arrays;
import java.util.Base64;
import java.util.HexFormat;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class RawSigningItemTest {

    private static final String IDENTIFIER = "doc-1";

    @Test
    void keepsItsDigest_whenTheCallerChangesTheArrayItPassedIn() {
        // given
        byte[] callerBuffer = buildSha256SizedDigest();
        var item = new RawSigningItem(IDENTIFIER, callerBuffer);

        // when
        callerBuffer[0] ^= 0x01;

        // then
        assertThat(item.digest()).isEqualTo(buildSha256SizedDigest());
    }

    @Test
    void keepsItsDigest_whenAConsumerChangesTheArrayItReadOut() {
        // given
        var item = new RawSigningItem(IDENTIFIER, buildSha256SizedDigest());

        // when
        item.digest()[0] ^= 0x01;

        // then
        assertThat(item.digest()).isEqualTo(buildSha256SizedDigest());
    }

    @Test
    void equalsWithTheSameHashCode_whenIdentifierAndDigestContentMatch() {
        // given
        var item = new RawSigningItem(IDENTIFIER, buildSha256SizedDigest());
        var sameContentInAnotherArray = new RawSigningItem(IDENTIFIER, buildSha256SizedDigest());

        // when
        boolean equal = item.equals(sameContentInAnotherArray);

        // then
        assertThat(equal).isTrue();
        assertThat(item.hashCode()).isEqualTo(sameContentInAnotherArray.hashCode());
    }

    @Test
    void differs_whenDigestContentDiffers() {
        // given
        byte[] otherDigest = buildSha256SizedDigest();
        otherDigest[31] ^= 0x01;
        var item = new RawSigningItem(IDENTIFIER, buildSha256SizedDigest());

        // when
        boolean equal = item.equals(new RawSigningItem(IDENTIFIER, otherDigest));

        // then
        assertThat(equal).isFalse();
    }

    @Test
    void printsTheDigestLengthOnly_whenRendered() {
        // given
        byte[] digest = buildSha256SizedDigest();
        var item = new RawSigningItem(IDENTIFIER, digest);

        // when
        String printed = item.toString();

        // then
        assertThat(printed)
                .contains(IDENTIFIER)
                .contains(digest.length + " bytes")
                .doesNotContain(HexFormat.of().formatHex(digest))
                .doesNotContain(Base64.getEncoder().encodeToString(digest))
                .doesNotContain(Arrays.toString(digest));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static byte[] buildSha256SizedDigest() {
        byte[] digest = new byte[32];
        Arrays.fill(digest, (byte) 0x5A);
        return digest;
    }
}
