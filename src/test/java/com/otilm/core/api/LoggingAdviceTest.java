package com.otilm.core.api;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.classic.spi.ThrowableProxyUtil;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.exception.CertificateOperationException;
import com.otilm.api.exception.ConnectorException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.logging.Sensitive;
import com.otilm.core.util.SecretLeakProbe;
import java.lang.reflect.Method;
import java.util.List;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * At TRACE, {@code logAround} must not print a {@link Sensitive} argument verbatim, and a result with no
 * {@code toString()} of its own must not be dumped reflectively (which would ignore Lombok's own exclusions).
 */
class LoggingAdviceTest {

    private final Logger adviceLogger = (Logger) LoggerFactory.getLogger(LoggingAdvice.class);
    private final ListAppender<ILoggingEvent> logged = new ListAppender<>();
    private final LoggingAdvice advice = new LoggingAdvice();
    private Level previousLevel;

    @BeforeEach
    void setUp() {
        previousLevel = adviceLogger.getLevel();
        adviceLogger.setLevel(Level.TRACE);
        logged.start();
        adviceLogger.addAppender(logged);
    }

    @AfterEach
    void tearDown() {
        adviceLogger.detachAppender(logged);
        adviceLogger.setLevel(previousLevel);
    }

    @Test
    void aSensitiveArgument_logsAsRedacted() throws Throwable {
        // when
        advice.logAround(fixtureJoinPoint(new Object[]{"topSecret", "visibleValue"}, "result"));

        // then
        String line = firstLine("Entering");
        assertThat(line).contains("arguments [***, visibleValue]").doesNotContain("topSecret");
    }

    @Test
    void aResultWithoutToString_logsAsItsSimpleClassName() throws Throwable {
        // when
        advice.logAround(fixtureJoinPoint(new Object[]{"a", "b"}, new NoToString()));

        // then
        assertThat(firstLine("result:")).endsWith("result: NoToString");
    }

    @Test
    void logsTheFailureWithoutTheConnectorsText_whenAConnectorWrotePartOfItsChain() throws Throwable {
        // given
        var echoedSecret = "passphrase-the-connector-echoed";
        var shapedFailure = new CertificateOperationException("Failed to submit certificate request");
        shapedFailure.initCause(new ConnectorException(echoedSecret));
        ProceedingJoinPoint joinPoint = fixtureJoinPoint(new Object[]{"a", "b"}, null);
        when(joinPoint.proceed()).thenThrow(shapedFailure);

        // when
        catchThrowable(() -> advice.logAround(joinPoint));

        // then
        List<String> lines = renderLogged();
        SecretLeakProbe.assertNoneReveals(lines, echoedSecret);
        assertThat(lines).anyMatch(line -> line.contains(ConnectorException.class.getName()));
    }

    @Test
    void logsAValidationFailureWithoutItsText_whenAConnectorMayHaveWrittenIt() throws Throwable {
        // given — a connector's refusal reaches the controller as a ValidationException carrying its own sentences
        var echoedSecret = "passphrase-the-connector-echoed";
        ProceedingJoinPoint joinPoint = fixtureJoinPoint(new Object[]{"a", "b"}, null);
        when(joinPoint.proceed()).thenThrow(new ValidationException(echoedSecret));

        // when
        catchThrowable(() -> advice.logAround(joinPoint));

        // then
        List<String> lines = renderLogged();
        SecretLeakProbe.assertNoneReveals(lines, echoedSecret);
        assertThat(lines).anyMatch(line -> line.contains("ValidationException when calling"));
    }

    // Invoked only reflectively as the traced-method fixture (the advice reads its parameter annotations).
    @SuppressWarnings("unused")
    private String sampleMethod(@Sensitive String secret, String visible) {
        return visible + secret;
    }

    private ProceedingJoinPoint fixtureJoinPoint(Object[] args, Object result) throws Throwable {
        Method method = getClass().getDeclaredMethod("sampleMethod", String.class, String.class);
        MethodSignature signature = mock(MethodSignature.class);
        when(signature.getDeclaringTypeName()).thenReturn(getClass().getName());
        when(signature.getName()).thenReturn("sampleMethod");
        when(signature.getMethod()).thenReturn(method);
        ProceedingJoinPoint joinPoint = mock(ProceedingJoinPoint.class);
        when(joinPoint.getSignature()).thenReturn(signature);
        when(joinPoint.getArgs()).thenReturn(args);
        when(joinPoint.proceed()).thenReturn(result);
        return joinPoint;
    }

    private String firstLine(String containing) {
        return logged.list
                .stream()
                .map(ILoggingEvent::getFormattedMessage)
                .filter(message -> message.contains(containing))
                .findFirst()
                .orElseThrow();
    }

    /** Every logged line, with the stack trace of any throwable it carried. */
    private List<String> renderLogged() {
        return logged.list
                .stream()
                .map(event -> event.getFormattedMessage() + (event.getThrowableProxy() == null
                        ? ""
                        : ThrowableProxyUtil.asString(event.getThrowableProxy())))
                .toList();
    }

    static final class NoToString {
    }
}
