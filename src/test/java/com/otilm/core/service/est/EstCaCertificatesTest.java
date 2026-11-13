package com.otilm.core.service.est;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.clients.ApiClientConnectorInfo;
import com.otilm.api.exception.ConnectorClientException;
import com.otilm.api.exception.ConnectorCommunicationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ConnectorServerException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.exception.UnsupportedAuthorityVersionException;
import com.otilm.core.helpers.CertificateGeneratorHelper;
import com.otilm.core.service.est.message.EstError;
import com.otilm.core.service.est.message.EstException;
import com.otilm.core.service.handler.authority.AdapterOperationResult;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapter;
import com.otilm.core.service.handler.authority.AuthorityProviderAdapterFactory;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;

import static com.otilm.core.util.ConnectorFailureFixtures.decodeFailure;
import static com.otilm.core.util.ConnectorFailureFixtures.requestFailure;
import static com.otilm.core.util.builders.EstProfileBuilder.anEstProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class EstCaCertificatesTest {

    private static final String LABEL = "devices";
    private static final UUID RA_PROFILE_UUID = UUID.fromString("5d0f7c52-3a41-4c5e-9d0b-5f1d2a8e7b64");
    private static final String CONNECTOR_TEXT = "connector says: token=hunter2 expired";

    @Mock
    private AuthorityProviderAdapterFactory adapterFactory;

    @Mock
    private AuthorityProviderAdapter adapter;

    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final Logger caCertificatesLogger = (Logger) LoggerFactory.getLogger(EstCaCertificates.class);
    private boolean previousAdditive;

    private EstCaCertificates caCertificates;
    private AuthorityInstanceReference authority;
    private RaProfile raProfile;
    private EstRoute route;

    /** The logger is a process-wide singleton, so what is set on it here is taken off again after each test. */
    @BeforeEach
    void createCaCertificatesAndCaptureTheLog() {
        authority = new AuthorityInstanceReference();
        raProfile = new RaProfile();
        raProfile.setUuid(RA_PROFILE_UUID);
        raProfile.setName("devices-ra");
        raProfile.setAuthorityInstanceReference(authority);
        route = new EstRoute(anEstProfile().build(), raProfile, false, LABEL);
        when(adapterFactory.forAuthority(authority)).thenReturn(adapter);
        caCertificates = new EstCaCertificates(adapterFactory);
        previousAdditive = caCertificatesLogger.isAdditive();
        caCertificatesLogger.setAdditive(false);
        logged.start();
        caCertificatesLogger.addAppender(logged);
    }

    @AfterEach
    void releaseTheLog() {
        caCertificatesLogger.detachAppender(logged);
        logged.stop();
        caCertificatesLogger.setAdditive(previousAdditive);
    }

    @Test
    void returnsTheCertificatesOfTheAuthorityInConnectorOrder_whenItAnswers() throws Exception {
        // given
        X509Certificate issuingCa = CertificateGeneratorHelper.generateCACertificate(null, "CN=Issuing CA");
        X509Certificate rootCa = CertificateGeneratorHelper.generateCACertificate(null, "CN=Root CA");
        when(adapter.getCaCertificates(authority, raProfile))
                .thenReturn(List.of(chainEntry(issuingCa), chainEntry(rootCa)));

        // when
        List<X509Certificate> chain = caCertificates.fetch(route);

        // then
        assertThat(chain).containsExactly(issuingCa, rootCa);
    }

    @ParameterizedTest
    @MethodSource("connectorFailures")
    void throwsServiceUnavailableWithTheRealm_whenConnectorFails(Exception connectorFailure) throws Exception {
        // given
        when(adapter.getCaCertificates(authority, raProfile)).thenThrow(connectorFailure);

        // when
        ThrowingCallable fetch = () -> caCertificates.fetch(route);

        // then
        assertThatThrownBy(fetch)
                .isInstanceOf(EstException.class)
                .hasMessageContaining(EstError.SERVICE_UNAVAILABLE.text())
                .satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE, LABEL));
    }

    @ParameterizedTest
    @MethodSource("connectorFailures")
    void logsErrorWithTheClassNameOnly_whenConnectorFails(Exception connectorFailure) throws Exception {
        // given
        when(adapter.getCaCertificates(authority, raProfile)).thenThrow(connectorFailure);

        // when
        ThrowingCallable fetch = () -> caCertificates.fetch(route);

        // then
        assertThatThrownBy(fetch).isInstanceOf(EstException.class);
        assertThat(logged.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getFormattedMessage())
                    .contains(RA_PROFILE_UUID.toString())
                    .contains(connectorFailure.getClass().getName());
            assertThat(event.getThrowableProxy()).isNull();
        });
    }

    @ParameterizedTest
    @MethodSource("connectorFailures")
    void logsNoTextOfTheConnector_whenConnectorFails(Exception connectorFailure) throws Exception {
        // given
        when(adapter.getCaCertificates(authority, raProfile)).thenThrow(connectorFailure);

        // when
        ThrowingCallable fetch = () -> caCertificates.fetch(route);

        // then
        assertThatThrownBy(fetch).isInstanceOf(EstException.class);
        assertThat(logged.list).isNotEmpty().noneSatisfy(event -> assertThat(textOf(event)).contains(CONNECTOR_TEXT));
    }

    @ParameterizedTest
    @MethodSource("otherFetchFailures")
    void throwsServiceUnavailableWithTheRealm_whenTheFetchFailsInAnyOtherWay(RuntimeException failure)
            throws Exception {
        // given
        when(adapter.getCaCertificates(authority, raProfile)).thenThrow(failure);

        // when
        ThrowingCallable fetch = () -> caCertificates.fetch(route);

        // then
        assertThatThrownBy(fetch)
                .isInstanceOf(EstException.class)
                .hasMessageContaining(EstError.SERVICE_UNAVAILABLE.text())
                .satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE, LABEL));
    }

    @ParameterizedTest
    @MethodSource("otherFetchFailures")
    void logsErrorWithTheException_whenTheFetchFailsInAnyOtherWay(RuntimeException failure) throws Exception {
        // given
        when(adapter.getCaCertificates(authority, raProfile)).thenThrow(failure);

        // when
        ThrowingCallable fetch = () -> caCertificates.fetch(route);

        // then
        assertThatThrownBy(fetch).isInstanceOf(EstException.class);
        assertThat(logged.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getFormattedMessage()).contains(RA_PROFILE_UUID.toString());
            assertThat(event.getThrowableProxy().getClassName()).isEqualTo(failure.getClass().getName());
        });
    }

    @Test
    void throwsServiceUnavailableWithTheRealm_whenNoAdapterServesTheAuthority() {
        // given
        UnsupportedAuthorityVersionException unsupported = new UnsupportedAuthorityVersionException(
                "Unsupported authority connector interface version: v9");
        when(adapterFactory.forAuthority(authority)).thenThrow(unsupported);

        // when
        ThrowingCallable fetch = () -> caCertificates.fetch(route);

        // then
        assertThatThrownBy(fetch)
                .isInstanceOf(EstException.class)
                .satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE, LABEL));
        assertThat(logged.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getThrowableProxy().getClassName()).isEqualTo(unsupported.getClass().getName());
        });
    }

    @Test
    void throwsServiceUnavailable_whenAuthorityReturnsNoCertificates() throws Exception {
        // given
        when(adapter.getCaCertificates(authority, raProfile)).thenReturn(List.of());

        // when
        ThrowingCallable fetch = () -> caCertificates.fetch(route);

        // then
        assertThatThrownBy(fetch)
                .isInstanceOf(EstException.class)
                .satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE, LABEL));
        assertThat(logged.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getFormattedMessage()).contains(RA_PROFILE_UUID.toString());
        });
    }

    @ParameterizedTest
    @MethodSource("unusableCertificateData")
    void throwsServiceUnavailable_whenACertificateOfTheChainCannotBeParsed(String certificateData) throws Exception {
        // given
        X509Certificate rootCa = CertificateGeneratorHelper.generateCACertificate(null, "CN=Root CA");
        when(adapter.getCaCertificates(authority, raProfile))
                .thenReturn(List.of(chainEntry(rootCa), entryWithData(certificateData)));

        // when
        ThrowingCallable fetch = () -> caCertificates.fetch(route);

        // then
        assertThatThrownBy(fetch)
                .isInstanceOf(EstException.class)
                .satisfies(thrown -> assertRefusal(thrown, EstError.SERVICE_UNAVAILABLE, LABEL));
        assertThat(logged.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getFormattedMessage()).contains(RA_PROFILE_UUID.toString());
        });
    }

    @Test
    void logsErrorWithTheException_whenACertificateOfTheChainCannotBeParsed() throws Exception {
        // given
        when(adapter.getCaCertificates(authority, raProfile)).thenReturn(List.of(entryWithData("AAAA")));

        // when
        ThrowingCallable fetch = () -> caCertificates.fetch(route);

        // then
        assertThatThrownBy(fetch).isInstanceOf(EstException.class);
        assertThat(logged.list).singleElement().satisfies(event -> {
            assertThat(event.getLevel()).isEqualTo(Level.ERROR);
            assertThat(event.getThrowableProxy()).isNotNull();
        });
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    static Stream<Arguments> connectorFailures() {
        return Stream
                .of(arguments(named("a connector error", new ConnectorException(CONNECTOR_TEXT))),
                        arguments(named("a server error of the connector",
                                new ConnectorServerException(CONNECTOR_TEXT, HttpStatus.INTERNAL_SERVER_ERROR))),
                        arguments(named("a server error whose cause carries the text too",
                                new ConnectorServerException(CONNECTOR_TEXT, new IllegalStateException(CONNECTOR_TEXT),
                                        HttpStatus.INTERNAL_SERVER_ERROR))),
                        arguments(named("a client error of the connector",
                                new ConnectorClientException(CONNECTOR_TEXT, HttpStatus.BAD_REQUEST))),
                        arguments(named("a connector that cannot be reached",
                                new ConnectorCommunicationException(CONNECTOR_TEXT, (ApiClientConnectorInfo) null))),
                        arguments(named("a refusal of the connector", new ValidationException(CONNECTOR_TEXT))),
                        arguments(named("an answer that cannot be decoded", decodeFailure(CONNECTOR_TEXT))),
                        arguments(named("a request that gets no answer", requestFailure(CONNECTOR_TEXT))));
    }

    static Stream<Arguments> otherFetchFailures() {
        return Stream
                .of(arguments(
                        named("an answer without a body, as the v2 adapter reads it", new NullPointerException())),
                        arguments(named("an answer without a body, as the v3 client reads it",
                                new IllegalStateException("The response has no body."))));
    }

    static Stream<Arguments> unusableCertificateData() {
        return Stream
                .of(arguments(named("base64 text that is not a certificate", "AAAA")),
                        arguments(named("text that is not base64", "!!!not-base64!!!")),
                        arguments(named("a blank", "   ")), arguments(named("no content", null)));
    }

    private static void assertRefusal(Throwable thrown, EstError error, String realm) {
        assertThat(thrown).isInstanceOfSatisfying(EstException.class, refusal -> {
            assertThat(refusal.error()).isEqualTo(error);
            assertThat(refusal.realm()).contains(realm);
        });
    }

    /** Everything a log event shows: its message and, when it carries an exception, the exception with its causes. */
    private static String textOf(ILoggingEvent event) {
        String text = event.getFormattedMessage();
        if (event.getThrowableProxy() != null) {
            text += ThrowableProxyUtil.asString(event.getThrowableProxy());
        }
        return text;
    }

    private static AdapterOperationResult chainEntry(X509Certificate certificate) throws CertificateEncodingException {
        return entryWithData(Base64.getEncoder().encodeToString(certificate.getEncoded()));
    }

    private static AdapterOperationResult entryWithData(String certificateData) {
        return AdapterOperationResult.syncOk(certificateData, List.of(), CertificateType.X509);
    }
}
