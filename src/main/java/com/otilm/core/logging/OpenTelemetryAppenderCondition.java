package com.otilm.core.logging;

import ch.qos.logback.core.boolex.PropertyConditionBase;
import org.springframework.core.env.Environment;

/**
 * Holds when the OpenTelemetry starter installs its SDK into the logback appender: OpenTelemetry is not disabled and
 * the logback-appender instrumentation is on, read from the same properties, with the same defaults, as the starter's
 * own condition. An appender the SDK is never installed into keeps the first 1000 events and then prints a plain-text
 * warning to stderr, so logback-spring.xml attaches it only when this holds.
 */
public class OpenTelemetryAppenderCondition extends PropertyConditionBase {

    @Override
    public boolean evaluate() {
        Environment environment = (Environment) getContext().getObject(Environment.class.getName());
        if (environment == null) {
            return false;
        }
        boolean sdkDisabled = environment.getProperty("otel.sdk.disabled", Boolean.class, false);
        Boolean appenderEnabled = environment
                .getProperty("otel.instrumentation.logback-appender.enabled", Boolean.class);
        if (appenderEnabled == null) {
            appenderEnabled = environment
                    .getProperty("otel.instrumentation.common.default-enabled", Boolean.class, true);
        }
        return !sdkDisabled && appenderEnabled;
    }
}
