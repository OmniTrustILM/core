package com.otilm.core.logging;

import ch.qos.logback.core.boolex.PropertyConditionBase;
import io.opentelemetry.instrumentation.spring.autoconfigure.internal.EarlyConfig;
import org.springframework.core.env.Environment;

/**
 * Holds when the OpenTelemetry starter installs its SDK into the logback appender. An appender the SDK is never
 * installed into keeps the first 1000 events and then prints a plain-text warning to stderr, so logback-spring.xml
 * attaches it only when this holds.
 *
 * <p>
 * The decision is the starter's own {@link EarlyConfig}, which reads legacy and declarative configuration alike;
 * copying its properties would drift from it. EarlyConfig sits in the starter's internal package, so an upgrade that
 * changes it fails to compile here rather than changing behaviour unnoticed.
 */
public class OpenTelemetryAppenderCondition extends PropertyConditionBase {

    @Override
    public boolean evaluate() {
        Environment environment = (Environment) getContext().getObject(Environment.class.getName());
        return environment != null && EarlyConfig.otelEnabled(environment)
                && EarlyConfig.isInstrumentationEnabled(environment, "logback-appender", true);
    }
}
