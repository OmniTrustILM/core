package com.otilm.core.api;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.model.core.logging.Sensitive;
import java.lang.reflect.Method;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.reflect.MethodSignature;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;
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

    static final class NoToString {
    }
}
