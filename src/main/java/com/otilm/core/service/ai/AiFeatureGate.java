package com.otilm.core.service.ai;

import com.otilm.core.aop.TraceMetadataOnly;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Component;

/** Deployment switch for new AI operations; it grants no runtime readiness or business permissions. */
@Component
@TraceMetadataOnly
public class AiFeatureGate {
    private static final Logger LOG = LoggerFactory.getLogger(AiFeatureGate.class);
    private final boolean enabled;

    public AiFeatureGate(@Value("${otilm.ai.enabled:false}") boolean enabled) {
        this.enabled = enabled;
    }

    public boolean enabled() {
        return enabled;
    }

    public void requireEnabled() {
        if (!enabled) {
            LOG.debug("AI feature operation=admission code=DENIED");
            throw new AccessDeniedException("AI execution is disabled");
        }
    }
}
