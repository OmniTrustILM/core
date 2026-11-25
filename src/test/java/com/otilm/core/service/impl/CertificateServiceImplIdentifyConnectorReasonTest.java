package com.otilm.core.service.impl;

import com.otilm.api.exception.ConnectorEntityNotFoundException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorProblemException;
import com.otilm.api.model.common.error.ErrorCode;
import com.otilm.api.model.common.error.ProblemDetailExtended;
import java.util.stream.Stream;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Named.named;

class CertificateServiceImplIdentifyConnectorReasonTest {

    @Test
    void returnsDetail_whenProblemDocumentExplainsTheFailure() {
        // given
        var connectorReason = "its issuing CA certificate could not be obtained; add it to the authority";
        var problem = problemWithDetail("  " + connectorReason + "\n");

        // when
        String reason = CertificateServiceImpl.identifyConnectorReason(problem);

        // then
        assertThat(reason).isEqualTo(connectorReason);
    }

    @ParameterizedTest
    @MethodSource("failuresWithoutReason")
    void returnsNull_whenConnectorGaveNoReason(ConnectorException failure) {
        // given — a connector failure that carries no problem detail

        // when
        String reason = CertificateServiceImpl.identifyConnectorReason(failure);

        // then
        assertThat(reason).isNull();
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Arguments> failuresWithoutReason() {
        return Stream
                .of(Arguments
                        .of(named("plain 404 body",
                                new ConnectorEntityNotFoundException(
                                        "{\"message\": \"Certificate not identified.\"}"))),
                        Arguments.of(named("problem document without detail", problemWithDetail(null))),
                        Arguments.of(named("problem document with blank detail", problemWithDetail("  "))));
    }

    private static ConnectorProblemException problemWithDetail(String detail) {
        var problem = ProblemDetailExtended.fromErrorCode(ErrorCode.RESOURCE_NOT_FOUND, detail, null, null);
        return new ConnectorProblemException(problem);
    }
}
