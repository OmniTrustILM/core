package com.otilm.core.service.est.enrollment;

import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.core.certificate.type.UnsupportedCertificateTypeException;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.est.EstRoute;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class EstAnswersTest {

    @Mock
    private CertificateRepository certificateRepository;

    @Test
    void answersAcceptedWithTheRetryAfterOfTheEstProfile_whenTheCertificateIsNotReady() {
        // given
        var retryAfterSeconds = 7;
        var route = new EstRoute(anEstProfile().withRetryAfter(retryAfterSeconds).build(), null, false, "devices");
        List<String> outcomes = new ArrayList<>();

        // when
        ResponseEntity<byte[]> response = new EstAnswers(certificateRepository).pending(route, outcomes::add);

        // then
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.ACCEPTED);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("7");
        assertThat(outcomes).containsExactly(EstEnrollmentAudit.PENDING);
    }

    @Test
    void rejectsTheRequestWithTheRefusalAsDetail_whenTheTypeCannotBeEnrolledThroughEst() {
        // given
        var route = new EstRoute(anEstProfile().build(), null, false, "devices");
        var refusal = UnsupportedCertificateTypeException
                .unsupportedOperation(CertificateType.X509.getCode(), CertificateOperation.ENROLL_EST);

        // when
        EstException answer = new EstAnswers(certificateRepository)
                .submissionFailed(route, null, "The issue of an EST request", refusal);

        // then
        assertThat(answer.error()).isEqualTo(EstError.REQUEST_REJECTED);
        assertThat(answer.detail()).contains(refusal.getMessage());
    }
}
