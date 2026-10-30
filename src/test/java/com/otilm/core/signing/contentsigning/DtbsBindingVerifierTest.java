package com.otilm.core.signing.contentsigning;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsResponseDto;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import java.util.Arrays;
import java.util.List;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.catchThrowableOfType;

class DtbsBindingVerifierTest {

    private static final byte[] AUTHORIZED_VALUE = digestOfLength(32, (byte) 0x11);

    private static final DocumentDigest AUTHORIZED = new DocumentDigest(DigestAlgorithm.SHA_256, AUTHORIZED_VALUE);

    private static final DocumentDigest DIFFERENT_DOCUMENT = new DocumentDigest(DigestAlgorithm.SHA_256,
            digestOfLength(32, (byte) 0x22));

    private static final DocumentDigest UNUSABLE_ECHO = new DocumentDigest(DigestAlgorithm.SHA_512,
            digestOfLength(64, (byte) 0x11));

    @Test
    void acceptsAnEchoOfTheAuthorizedDocument() {
        // given a connector echoing an equal array rather than the very same one
        DocumentDigest echoed = new DocumentDigest(DigestAlgorithm.SHA_256, AUTHORIZED_VALUE.clone());

        // when / then
        assertThatCode(() -> DtbsBindingVerifier.verifyEcho(AUTHORIZED, echoed)).doesNotThrowAnyException();
    }

    @Test
    void refusesAnEchoOfADifferentDocument() {
        // when / then
        SigningEngineException thrown = catchVerifyEcho(AUTHORIZED, DIFFERENT_DOCUMENT);
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.BINDING_VIOLATION);
        assertThat(thrown.step()).isEqualTo("computeDtbs");
        assertThat(thrown.operatorMessage()).contains("2222", "1111");
    }

    @Test
    void refusesAnEchoDifferingInASingleBit() {
        // given
        byte[] almost = AUTHORIZED_VALUE.clone();
        almost[31] ^= 0x01;

        // when / then
        assertThat(catchVerifyEcho(AUTHORIZED, new DocumentDigest(DigestAlgorithm.SHA_256, almost)).failure())
                .isEqualTo(SigningEngineFailure.BINDING_VIOLATION);
    }

    @Test
    void refusesAMissingEcho() {
        // when / then
        SigningEngineException thrown = catchVerifyEcho(AUTHORIZED, null);
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
        assertThat(thrown.operatorMessage()).contains("echoed no documentDigest");
    }

    /** Digests of different algorithms are incomparable, so the platform refuses instead of re-deriving one. */
    @Test
    void refusesAnEchoUnderADifferentAlgorithm() {
        // when / then
        assertThat(catchVerifyEcho(AUTHORIZED, UNUSABLE_ECHO).operatorMessage()).contains("SHA-512", "SHA-256");
    }

    @Test
    void refusesAnEchoTooShortForItsAlgorithm() {
        // given
        DocumentDigest echoed = new DocumentDigest(DigestAlgorithm.SHA_256, digestOfLength(16, (byte) 0x11));

        // when / then
        assertThat(catchVerifyEcho(AUTHORIZED, echoed).operatorMessage()).contains("16-byte", "never produces");
    }

    /** A platform-side digest no algorithm could have produced would mismatch every echo, so it is not a violation. */
    @Test
    void refusesAMalformedAuthorizedDigest() {
        // given
        DocumentDigest malformed = new DocumentDigest(DigestAlgorithm.SHA_256, digestOfLength(16, (byte) 0x11));

        // when / then
        assertThatIllegalArgumentException()
                .isThrownBy(() -> DtbsBindingVerifier
                        .verifyEcho(malformed, new DocumentDigest(DigestAlgorithm.SHA_256, AUTHORIZED_VALUE)))
                .withMessageContaining("16 bytes")
                .withMessageContaining("SHA-256");
    }

    /** A broken connector must not be reported to the client as an unauthorized document. */
    @Test
    void tellsABrokenEchoApartFromAMismatchOnTheWire() {
        // when / then
        assertThat(catchVerifyEcho(AUTHORIZED, DIFFERENT_DOCUMENT).clientMessage())
                .isNotEqualTo(catchVerifyEcho(AUTHORIZED, UNUSABLE_ECHO).clientMessage());
    }

    /** Records and alerting key off the failure value, so the security event must not collapse into a fault. */
    @Test
    void classifiesAMismatchApartFromABrokenEcho() {
        // when / then
        assertThat(catchVerifyEcho(AUTHORIZED, DIFFERENT_DOCUMENT).failure())
                .isEqualTo(SigningEngineFailure.BINDING_VIOLATION);
        assertThat(catchVerifyEcho(AUTHORIZED, UNUSABLE_ECHO).failure())
                .isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
    }

    @Test
    void keepsDigestsOutOfTheClientMessage() {
        // when / then
        assertThat(catchVerifyEcho(AUTHORIZED, DIFFERENT_DOCUMENT).clientMessage()).doesNotContain("1111", "2222");
    }

    @Test
    void acceptsAnEchoReadOffAComputeDtbsResponse() {
        // when / then
        assertThatCode(
                () -> DtbsBindingVerifier.verify(AUTHORIZED, response(DigestAlgorithm.SHA_256, AUTHORIZED_VALUE)))
                .doesNotThrowAnyException();
    }

    @Test
    void refusesAnEchoReadOffAComputeDtbsResponseThatNamesAnotherDocument() {
        // when / then
        assertThat(catchVerify(AUTHORIZED, response(DigestAlgorithm.SHA_256, DIFFERENT_DOCUMENT.value())).failure())
                .isEqualTo(SigningEngineFailure.BINDING_VIOLATION);
    }

    @Test
    void treatsAResponseCarryingNeitherHalfOfTheEchoAsNoEcho() {
        // when / then
        SigningEngineException thrown = catchVerify(AUTHORIZED, response(null, null));
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
        assertThat(thrown.operatorMessage()).contains("echoed no documentDigest");
    }

    /** Naming the missing half sends whoever debugs the connector to the field that is actually at fault. */
    @Test
    void namesTheMissingDigestWhenTheConnectorEchoedOnlyItsAlgorithm() {
        // when / then
        SigningEngineException thrown = catchVerify(AUTHORIZED, response(DigestAlgorithm.SHA_256, null));
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
        assertThat(thrown.operatorMessage()).contains("SHA-256 documentDigestAlgorithm but no documentDigest");
    }

    @Test
    void namesTheMissingAlgorithmWhenTheConnectorEchoedOnlyTheDigest() {
        // when / then
        SigningEngineException thrown = catchVerify(AUTHORIZED, response(null, AUTHORIZED_VALUE));
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
        assertThat(thrown.operatorMessage()).contains("32-byte documentDigest but no documentDigestAlgorithm");
    }

    /** A connector that delivered nothing at all is the same fault as one that echoed no digest. */
    @Test
    void treatsAMissingResponseAsAConnectorFault() {
        // when / then
        SigningEngineException thrown = catchVerify(AUTHORIZED, null);
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
        assertThat(thrown.operatorMessage()).contains("returned no computeDtbs response");
    }

    @Test
    void verifiesEveryDocumentOfAMultiDocumentOperation() {
        // given
        DocumentDigest second = new DocumentDigest(DigestAlgorithm.SHA_256, digestOfLength(32, (byte) 0x33));

        // when / then
        assertThatCode(() -> DtbsBindingVerifier
                .verifyAll(List.of(AUTHORIZED, second),
                        List
                                .of(response(DigestAlgorithm.SHA_256, AUTHORIZED_VALUE),
                                        response(DigestAlgorithm.SHA_256, second.value()))))
                .doesNotThrowAnyException();
    }

    /** Each document answers for itself: a set of echoes matching as a set is not a binding. */
    @Test
    void refusesSwappedEchoesInAMultiDocumentOperation() {
        // given
        DocumentDigest second = new DocumentDigest(DigestAlgorithm.SHA_256, digestOfLength(32, (byte) 0x33));
        List<ComputeDtbsResponseDto> swapped = List
                .of(response(DigestAlgorithm.SHA_256, second.value()),
                        response(DigestAlgorithm.SHA_256, AUTHORIZED_VALUE));

        // when / then
        SigningEngineException thrown = catchThrowableOfType(SigningEngineException.class,
                () -> DtbsBindingVerifier.verifyAll(List.of(AUTHORIZED, second), swapped));
        assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.BINDING_VIOLATION);
        assertThat(thrown.operatorMessage()).contains("3333", "1111");
    }

    @Test
    void refusesToPairListsOfDifferentLengths() {
        // when / then
        assertThatIllegalArgumentException()
                .isThrownBy(() -> DtbsBindingVerifier
                        .verifyAll(List.of(AUTHORIZED),
                                List
                                        .of(response(DigestAlgorithm.SHA_256, AUTHORIZED_VALUE),
                                                response(DigestAlgorithm.SHA_256, AUTHORIZED_VALUE))))
                .withMessageContaining("Cannot pair 1 authorized digests with 2");
    }

    /** An operation covering no document would satisfy the gate by having nothing to check. */
    @Test
    void refusesAMultiDocumentOperationWithNothingToCheck() {
        // when / then
        assertThatIllegalArgumentException()
                .isThrownBy(() -> DtbsBindingVerifier.verifyAll(List.of(), List.of()))
                .withMessageContaining("no authorized digest");
    }

    @Test
    void holdsTheAuthorizedDigestAgainstMutationOfItsSourceArray() {
        // given
        byte[] source = digestOfLength(32, (byte) 0x11);
        DocumentDigest authorized = new DocumentDigest(DigestAlgorithm.SHA_256, source);

        // when
        Arrays.fill(source, (byte) 0x22);

        // then
        assertThatCode(() -> DtbsBindingVerifier
                .verifyEcho(authorized, new DocumentDigest(DigestAlgorithm.SHA_256, digestOfLength(32, (byte) 0x11))))
                .doesNotThrowAnyException();
        assertThat(catchVerifyEcho(authorized, new DocumentDigest(DigestAlgorithm.SHA_256, source)).failure())
                .isEqualTo(SigningEngineFailure.BINDING_VIOLATION);
    }

    private static SigningEngineException catchVerifyEcho(DocumentDigest authorized, DocumentDigest echoed) {
        return catchThrowableOfType(SigningEngineException.class,
                () -> DtbsBindingVerifier.verifyEcho(authorized, echoed));
    }

    private static SigningEngineException catchVerify(DocumentDigest authorized, ComputeDtbsResponseDto response) {
        return catchThrowableOfType(SigningEngineException.class,
                () -> DtbsBindingVerifier.verify(authorized, response));
    }

    private static ComputeDtbsResponseDto response(DigestAlgorithm algorithm, byte[] digest) {
        ComputeDtbsResponseDto response = new ComputeDtbsResponseDto();
        response.setDocumentDigestAlgorithm(algorithm);
        response.setDocumentDigest(digest);
        return response;
    }

    private static byte[] digestOfLength(int length, byte fill) {
        byte[] digest = new byte[length];
        Arrays.fill(digest, fill);
        return digest;
    }
}
