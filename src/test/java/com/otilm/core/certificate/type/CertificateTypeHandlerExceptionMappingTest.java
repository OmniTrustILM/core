package com.otilm.core.certificate.type;

import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.ErrorMessageDto;
import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.core.api.ExceptionHandlingAdvice;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import static com.otilm.core.util.builders.ConnectorBuilder.aConnector;
import static org.assertj.core.api.Assertions.assertThat;

class CertificateTypeHandlerExceptionMappingTest {

    private final ExceptionHandlingAdvice advice = new ExceptionHandlingAdvice();

    @Test
    void answersWithTheMessage_whenAHandlerRefusesTheContent() {
        // given
        var refusal = new CertificateTypeHandlerException("The content is not a valid stub certificate");

        // when
        List<String> body = advice.handleValidationException(refusal);

        // then
        assertThat(body).containsExactly("The content is not a valid stub certificate");
    }

    @Test
    void namesTheTypeAndOperation_whenAnOperationIsNotSupported() {
        // given
        var refusal = UnsupportedCertificateTypeException.unsupportedOperation("STUB", CertificateOperation.REVOKE);

        // when
        List<String> body = advice.handleValidationException(refusal);

        // then
        assertThat(body).singleElement().asString().contains("STUB").contains("REVOKE");
    }

    @Test
    void answersWithUnprocessableContent_whenAHandlerExceptionIsRaised() throws Exception {
        // given
        var handlerMethod = ExceptionHandlingAdvice.class
                .getMethod("handleValidationException", ValidationException.class);

        // when
        HttpStatus status = handlerMethod.getAnnotation(ResponseStatus.class).value();

        // then
        assertThat(status).isEqualTo(HttpStatus.UNPROCESSABLE_CONTENT);
    }

    @Test
    void answersWithBadGatewayNamingTheRaProfileAndConnector_whenTheCertificateTypesCannotBeRead() throws Exception {
        // given
        var raProfileName = "ssh-profile";
        var connector = aConnector().withName("ssh-connector").build();
        var connectorText = "text written by the connector";
        var unavailable = new CertificateTypesUnavailableException(raProfileName, connector,
                new ConnectorException(connectorText));
        var handlerMethod = ExceptionHandlingAdvice.class
                .getMethod("handleCertificateTypesUnavailableException", CertificateTypesUnavailableException.class);

        // when
        ErrorMessageDto body = advice.handleCertificateTypesUnavailableException(unavailable);

        // then
        assertThat(body.getMessage())
                .contains(raProfileName, connector.getName(), connector.getUuid().toString())
                .doesNotContain(connectorText);
        assertThat(handlerMethod.getAnnotation(ResponseStatus.class).value()).isEqualTo(HttpStatus.BAD_GATEWAY);
    }
}
