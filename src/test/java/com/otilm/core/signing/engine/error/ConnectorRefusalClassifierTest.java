package com.otilm.core.signing.engine.error;

import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.core.signing.engine.error.ConnectorRefusalClassifier.Classification;
import java.util.stream.Stream;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpStatus;
import org.springframework.util.unit.DataSize;

import static com.otilm.core.util.ConnectorFailureFixtures.oversizedResponse;
import static com.otilm.core.util.ConnectorFailureFixtures.problemRefusal;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;

class ConnectorRefusalClassifierTest {

    private static final Classification UNCLASSIFIED = new Classification(SigningEngineFailure.SIGNER_FAULT,
            "Internal signing error");
    private static final DataSize READ_LIMIT = DataSize.ofMegabytes(16);

    // ── Classify ──────────────────────────────────────────────────────────────

    @Nested
    class Classify {

        @Test
        void returnsMalformedInput_whenTheDocumentCannotBeParsed() {
            // given
            var malformedDocument = problemRefusal(ErrorCode.DOCUMENT_MALFORMED);

            // when
            Classification classification = ConnectorRefusalClassifier.classify(malformedDocument, UNCLASSIFIED);

            // then
            assertThat(classification)
                    .isEqualTo(new Classification(SigningEngineFailure.MALFORMED_INPUT,
                            ErrorCode.DOCUMENT_MALFORMED.getTitle()));
        }

        @ParameterizedTest
        @EnumSource(value = ErrorCode.class,
                names = {"SIGNATURE_PLACEMENT_REJECTED", "DOCUMENT_SIGNING_FORBIDDEN", "SIGNATURE_NOT_FOUND"})
        void returnsInvalidInput_whenTheDocumentBreaksARule(ErrorCode documentRule) {
            // given
            var brokenRule = problemRefusal(documentRule);

            // when
            Classification classification = ConnectorRefusalClassifier.classify(brokenRule, UNCLASSIFIED);

            // then
            assertThat(classification)
                    .isEqualTo(new Classification(SigningEngineFailure.INVALID_INPUT, documentRule.getTitle()));
        }

        @Test
        void returnsMisconfigured_whenTheConnectorDoesNotSupportAParameter() {
            // given
            var unsupportedParameter = problemRefusal(ErrorCode.PARAMETER_UNSUPPORTED);

            // when
            Classification classification = ConnectorRefusalClassifier.classify(unsupportedParameter, UNCLASSIFIED);

            // then
            assertThat(classification)
                    .isEqualTo(new Classification(SigningEngineFailure.MISCONFIGURED,
                            ErrorCode.PARAMETER_UNSUPPORTED.getTitle()));
        }

        @ParameterizedTest
        @MethodSource("refusalsWithoutACode")
        void returnsMisconfigured_whenA422CarriesNoCode(Exception refusalWithoutACode) {
            // given — a refusal without an errorCode

            // when
            Classification classification = ConnectorRefusalClassifier.classify(refusalWithoutACode, UNCLASSIFIED);

            // then
            assertThat(classification)
                    .isEqualTo(new Classification(SigningEngineFailure.MISCONFIGURED,
                            "Signing configuration is not supported."));
        }

        @ParameterizedTest
        @EnumSource(value = ErrorCode.class, names = {"VALIDATION_FAILED", "CONTEXT_MISMATCH"})
        void returnsConnectorFault_whenCoreSentABodyTheContractForbids(ErrorCode contractBreach) {
            // given
            var refusedBody = problemRefusal(contractBreach);

            // when
            Classification classification = ConnectorRefusalClassifier.classify(refusedBody, UNCLASSIFIED);

            // then
            assertThat(classification)
                    .isEqualTo(new Classification(SigningEngineFailure.CONNECTOR_FAULT, UNCLASSIFIED.clientMessage()));
        }

        @ParameterizedTest
        @MethodSource("failuresWithoutAClassifyingCode")
        void returnsTheUnclassifiedFailure_whenNothingSaysWhoseMistakeItWas(Exception failure) {
            // given — a failure outside the code table

            // when
            Classification classification = ConnectorRefusalClassifier.classify(failure, UNCLASSIFIED);

            // then
            assertThat(classification).isEqualTo(UNCLASSIFIED);
        }

        @Test
        void returnsTheUnclassifiedFailure_whenAResponseExceedsTheReadLimit() {
            // given
            var oversizedResponse = oversizedResponse();

            // when
            Classification classification = ConnectorRefusalClassifier.classify(oversizedResponse, UNCLASSIFIED);

            // then
            assertThat(classification).isEqualTo(UNCLASSIFIED);
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static Stream<Named<Exception>> refusalsWithoutACode() {
            return Stream
                    .of(named("legacy 422 body", new ValidationException("Signature attribute is not supported")),
                            named("problem document without a code",
                                    problemRefusal(null, HttpStatus.UNPROCESSABLE_CONTENT.value())),
                            named("empty problem document",
                                    new ConnectorClientException(
                                            "Connector returned 422 with an empty application/problem+json body",
                                            HttpStatus.UNPROCESSABLE_CONTENT)));
        }

        private static Stream<Named<Exception>> failuresWithoutAClassifyingCode() {
            return Stream
                    .of(named("upstream error", problemRefusal(ErrorCode.UPSTREAM_ERROR)),
                            named("status outside HttpStatus without a code", problemRefusal(null, 499)),
                            named("400 without a body",
                                    new ConnectorClientException("Bad request", HttpStatus.BAD_REQUEST)),
                            named("body-less 2xx", new IllegalStateException("No response received from connector")));
        }
    }

    // ── ClassifyDocumentCall ──────────────────────────────────────────────────

    @Nested
    class ClassifyDocumentCall {

        @Test
        void returnsInvalidInputNamingTheLimit_whenTheResponseExceedsTheReadLimit() {
            // given
            var oversizedResponse = oversizedResponse();

            // when
            Classification classification = ConnectorRefusalClassifier
                    .classifyDocumentCall(oversizedResponse, READ_LIMIT, UNCLASSIFIED);

            // then
            assertThat(classification.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            assertThat(classification.clientMessage()).contains("16MB");
        }

        @Test
        void classifiesARefusalByItsCode_whenTheResponseFitsTheReadLimit() {
            // given
            var malformedDocument = problemRefusal(ErrorCode.DOCUMENT_MALFORMED);

            // when
            Classification classification = ConnectorRefusalClassifier
                    .classifyDocumentCall(malformedDocument, READ_LIMIT, UNCLASSIFIED);

            // then
            assertThat(classification.failure()).isEqualTo(SigningEngineFailure.MALFORMED_INPUT);
        }
    }
}
