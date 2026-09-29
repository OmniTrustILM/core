package com.otilm.core.key.normalization;

import java.io.IOException;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.BERSequence;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import static org.assertj.core.api.Assertions.assertThat;

class NestingDepthTest {

    @ParameterizedTest
    @CsvSource({"32, true", "33, false"})
    void within_allowsNestingUpToTheMaximumOnly(int depth, boolean expected) throws IOException {
        // given
        byte[] encoding = nested(depth, false);

        // when
        boolean within = NestingDepth.within(encoding, 32);

        // then
        assertThat(within).isEqualTo(expected);
    }

    @ParameterizedTest
    @CsvSource({"32, true", "33, false"})
    void within_followsIndefiniteLengths(int depth, boolean expected) throws IOException {
        // given
        byte[] encoding = nested(depth, true);

        // when
        boolean within = NestingDepth.within(encoding, 32);

        // then
        assertThat(within).isEqualTo(expected);
    }

    @Test
    void within_doesNotAddUpSiblings() throws IOException {
        // given
        ASN1EncodableVector siblings = new ASN1EncodableVector();
        for (int sibling = 0; sibling < 40; sibling++) {
            siblings.add(new DERSequence(DERNull.INSTANCE));
        }
        byte[] encoding = new DERSequence(siblings).getEncoded(ASN1Encoding.DER);

        // when
        boolean within = NestingDepth.within(encoding, 2);

        // then
        assertThat(within).isTrue();
    }

    @ParameterizedTest
    @CsvSource({"2, true", "1, false"})
    void within_readsHighTagNumbersAndLongFormLengths(int maximum, boolean expected) throws IOException {
        // given
        byte[] encoding = new DERSequence(new DERTaggedObject(true, 200, new DEROctetString(new byte[300])))
                .getEncoded(ASN1Encoding.DER);

        // when
        boolean within = NestingDepth.within(encoding, maximum);

        // then
        assertThat(within).isEqualTo(expected);
    }

    @Test
    void within_leavesATruncatedEncodingToTheParser() {
        // when
        boolean within = NestingDepth.within(new byte[]{0x30, 0x10, 0x30}, 1);

        // then
        assertThat(within).isTrue();
    }

    private static byte[] nested(int depth, boolean indefinite) throws IOException {
        ASN1Encodable value = DERNull.INSTANCE;
        for (int level = 0; level < depth; level++) {
            value = indefinite ? new BERSequence(value) : new DERSequence(value);
        }
        return value.toASN1Primitive().getEncoded(indefinite ? ASN1Encoding.BER : ASN1Encoding.DER);
    }
}
