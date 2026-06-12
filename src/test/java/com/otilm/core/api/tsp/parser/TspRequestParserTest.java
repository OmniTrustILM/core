package com.otilm.core.api.tsp.parser;

import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.core.signing.tsa.messages.TspRequest;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.tsp.TSPAlgorithms;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.math.BigInteger;

import static com.otilm.core.util.builders.RawTspRequestBuilder.aRawTspRequest;
import static org.junit.jupiter.api.Assertions.*;

class TspRequestParserTest {

    // ── happy path ──────────────────────────────────────────────────────────────

    @Test
    void parse_returnsRequest_forValidSha256Request() throws Exception {
        // given
        var sha256Digest = new byte[32];
        var body = aRawTspRequest()
                .withDigestAlgorithmOid(TSPAlgorithms.SHA256)
                .withHashedMessage(sha256Digest)
                .build();

        // when
        TspRequest parsed = TspRequestParser.parse(body);

        // then
        assertEquals(DigestAlgorithm.SHA_256, parsed.hashAlgorithm());
        assertArrayEquals(sha256Digest, parsed.hashedMessage());
        assertTrue(parsed.policy().isEmpty());
        assertTrue(parsed.nonce().isEmpty());
        assertFalse(parsed.includeSignerCertificate());
    }

    @Test
    void parse_returnsSha512Algorithm_forSha512Request() throws Exception {
        // given
        var sha512Digest = new byte[64];
        var body = aRawTspRequest()
                .withDigestAlgorithmOid(TSPAlgorithms.SHA512)
                .withHashedMessage(sha512Digest)
                .build();

        // when
        TspRequest parsed = TspRequestParser.parse(body);

        // then
        assertEquals(DigestAlgorithm.SHA_512, parsed.hashAlgorithm());
    }

    @Test
    void parse_capturesCertReq_whenCertificateRequested() throws Exception {
        // given
        var certReq = true;
        var body = aRawTspRequest().withCertReq(certReq).build();

        // when
        TspRequest parsed = TspRequestParser.parse(body);

        // then
        assertTrue(parsed.includeSignerCertificate());
    }

    @Test
    void parse_capturesPolicy_whenPolicyRequested() throws Exception {
        // given
        var requestedPolicyOid = "1.2.3.4.5";
        var body = aRawTspRequest().withPolicyOid(requestedPolicyOid).build();

        // when
        TspRequest parsed = TspRequestParser.parse(body);

        // then
        assertEquals(requestedPolicyOid, parsed.policy().orElseThrow());
    }

    @Test
    void parse_capturesNonce_whenNonceRequested() throws Exception {
        // given
        var requestedNonce = BigInteger.valueOf(987654321L);
        var body = aRawTspRequest().withNonce(requestedNonce).build();

        // when
        TspRequest parsed = TspRequestParser.parse(body);

        // then
        assertEquals(requestedNonce, parsed.nonce().orElseThrow());
    }

    @Test
    void parse_returnsNullForExtensions_whenRequestHasNoExtensions() throws Exception {
        // given
        var body = aRawTspRequest().build();

        // when
        TspRequest parsed = TspRequestParser.parse(body);

        // then
        assertNull(parsed.requestExtensions());
    }

    @Test
    void parse_carriesExtension_whenRequestContainsWellFormedExtension() throws Exception {
        // given — extnValue must be well-formed DER; DERNull is the minimal valid encoding
        var extensionOid = "1.3.6.1.5.5.7.48.1.2";
        var wellFormedDerValue = DERNull.INSTANCE.getEncoded();
        var body = aRawTspRequest()
                .withExtension(extensionOid, wellFormedDerValue)
                .build();

        // when
        TspRequest parsed = TspRequestParser.parse(body);

        // then
        assertNotNull(parsed.requestExtensions().getExtension(new ASN1ObjectIdentifier(extensionOid)));
    }

    @Test
    void parse_throwsBadDataFormat_forExtensionWithMalformedValue() {
        // given — a SEQUENCE tag declaring 5 content bytes but carrying none is not decodable DER
        var malformedDerValue = new byte[]{0x30, 0x05};
        var body = aRawTspRequest()
                .withExtension("1.3.6.1.5.5.7.48.1.2", malformedDerValue)
                .build();

        // when
        Executable parse = () -> TspRequestParser.parse(body);

        // then
        var ex = assertThrows(TspRequestParsingException.class, parse);
        assertEquals(TspFailureInfo.BAD_DATA_FORMAT, ex.getFailureInfo());
    }

    @Test
    void parse_throwsBadAlg_forUnknownDigestAlgorithmOid() {
        // given — an OID that maps to no known DigestAlgorithm
        var unknownDigestOid = new ASN1ObjectIdentifier("1.2.3.4.5");
        var body = aRawTspRequest()
                .withDigestAlgorithmOid(unknownDigestOid)
                .build();

        // when
        Executable parse = () -> TspRequestParser.parse(body);

        // then
        var ex = assertThrows(TspRequestParsingException.class, parse);
        assertEquals(TspFailureInfo.BAD_ALG, ex.getFailureInfo());
    }

    @Test
    void parse_throwsBadDataFormat_whenHashLengthDoesNotMatchAlgorithm() {
        // given — SHA-256 expects 32 bytes; a 16-byte digest is the wrong length
        var tooShortForSha256 = new byte[16];
        var body = aRawTspRequest()
                .withDigestAlgorithmOid(TSPAlgorithms.SHA256)
                .withHashedMessage(tooShortForSha256)
                .build();

        // when
        Executable parse = () -> TspRequestParser.parse(body);

        // then
        var ex = assertThrows(TspRequestParsingException.class, parse);
        assertEquals(TspFailureInfo.BAD_DATA_FORMAT, ex.getFailureInfo());
    }

    @Test
    void parse_throwsBadRequest_forMalformedRequestBytes() {
        // given — bytes that are not a DER-encoded TimeStampRequest
        var notATimeStampRequest = new byte[]{0x00, 0x01, 0x02, 0x03};

        // when
        Executable parse = () -> TspRequestParser.parse(notATimeStampRequest);

        // then
        var ex = assertThrows(TspRequestParsingException.class, parse);
        assertEquals(TspFailureInfo.BAD_REQUEST, ex.getFailureInfo());
    }
}
