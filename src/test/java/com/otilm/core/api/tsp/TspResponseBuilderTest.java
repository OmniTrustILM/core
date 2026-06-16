package com.otilm.core.api.tsp;

import com.otilm.api.interfaces.core.tsp.error.TspFailureInfo;
import com.otilm.core.signing.tsa.messages.TspResponse;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIStatus;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.asn1.tsp.TimeStampResp;
import org.bouncycastle.tsp.TimeStampResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.params.provider.Arguments.arguments;

class TspResponseBuilderTest {

    @Test
    void fromEngineResponse_granted_wrapsTokenWithGrantedStatus() throws Exception {
        // given
        var timestampToken = contentInfoBytes();

        // when
        byte[] response = TspResponseBuilder.fromEngineResponse(TspResponse.granted(timestampToken));

        // then
        TimeStampResp decoded = TimeStampResp.getInstance(response);
        assertEquals(PKIStatus.GRANTED, decoded.getStatus().getStatus().intValueExact());
        assertNotNull(decoded.getTimeStampToken(), "granted response must carry the timestamp token");
        assertArrayEquals(timestampToken, decoded.getTimeStampToken().getEncoded("DER"));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("failureInfoBitMappings")
    void fromEngineResponse_rejected_encodesCorrectFailureInfoBit(TspFailureInfo failureInfo, int expectedBcFailInfoBit) {
        // given
        var rejected = TspResponse.rejected(failureInfo, "policy rejected");

        // when
        byte[] response = TspResponseBuilder.fromEngineResponse(rejected);

        // then
        TimeStampResponse decoded = decodeResponse(response);
        assertEquals(PKIStatus.REJECTION, decoded.getStatus());
        assertNotNull(decoded.getFailInfo(), "rejection must carry a PKIFailureInfo");
        assertEquals(expectedBcFailInfoBit, decoded.getFailInfo().intValue(),
                () -> "RFC 3161 bit position " + failureInfo.getBitPosition()
                        + " must encode to BouncyCastle bit " + expectedBcFailInfoBit);
    }

    static Stream<Arguments> failureInfoBitMappings() {
        return Stream.of(
                arguments(TspFailureInfo.BAD_ALG, PKIFailureInfo.badAlg),
                arguments(TspFailureInfo.BAD_REQUEST, PKIFailureInfo.badRequest),
                arguments(TspFailureInfo.BAD_DATA_FORMAT, PKIFailureInfo.badDataFormat),
                arguments(TspFailureInfo.TIME_NOT_AVAILABLE, PKIFailureInfo.timeNotAvailable),
                arguments(TspFailureInfo.UNACCEPTED_POLICY, PKIFailureInfo.unacceptedPolicy),
                arguments(TspFailureInfo.UNACCEPTED_EXTENSION, PKIFailureInfo.unacceptedExtension),
                arguments(TspFailureInfo.ADD_INFO_NOT_AVAILABLE, PKIFailureInfo.addInfoNotAvailable),
                arguments(TspFailureInfo.SYSTEM_FAILURE, PKIFailureInfo.systemFailure));
    }

    @Test
    void buildRejection_nullStatusString_yieldsEmptyFreeText() {
        // given
        var failureInfo = TspFailureInfo.SYSTEM_FAILURE;
        String noStatusString = null;

        // when
        byte[] response = TspResponseBuilder.buildRejection(failureInfo, noStatusString);

        // then
        TimeStampResponse decoded = decodeResponse(response);
        assertEquals(PKIStatus.REJECTION, decoded.getStatus());
        String statusString = decoded.getStatusString();
        assertTrue(statusString == null || statusString.isEmpty(),
                "null status string must yield an empty PKIFreeText, got: " + statusString);
    }

    @Test
    void buildRejection_statusString_echoedInFreeText() {
        // given
        var failureInfo = TspFailureInfo.BAD_REQUEST;
        var statusString = "request not permitted";

        // when
        byte[] response = TspResponseBuilder.buildRejection(failureInfo, statusString);

        // then
        TimeStampResponse decoded = decodeResponse(response);
        assertEquals(statusString, decoded.getStatusString());
    }

    @Test
    void fromEngineResponse_grantedWithMalformedToken_throwsIllegalState() {
        // given
        var malformedToken = new byte[]{0x01, 0x02, 0x03};

        // when
        Executable build = () -> TspResponseBuilder.fromEngineResponse(TspResponse.granted(malformedToken));

        // then
        assertThrows(IllegalStateException.class, build);
    }

    /**
     * Minimal well-formed CMS {@link ContentInfo} standing in for a timestamp token. The granted branch
     * only re-wraps these bytes — it never inspects the token content — so a real signed SignedData/TSTInfo
     * (exercised end-to-end by {@code TspProtocolFlowITest}) is unnecessary here.
     */
    private static byte[] contentInfoBytes() throws Exception {
        var content = new DEROctetString(new byte[]{1, 2, 3});
        return new ContentInfo(CMSObjectIdentifiers.signedData, content).getEncoded("DER");
    }

    private static TimeStampResponse decodeResponse(byte[] body) {
        try {
            return new TimeStampResponse(body);
        } catch (Exception e) {
            throw new IllegalStateException("Response is not a valid RFC 3161 TimeStampResp", e);
        }
    }
}
