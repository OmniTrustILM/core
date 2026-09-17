package com.otilm.core.cbom.sync;

import jakarta.annotation.PostConstruct;
import java.util.List;
import java.util.function.UnaryOperator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * Says so, once at startup, when a deployment still sets an environment variable the CBOM sync no longer reads.
 *
 * <p>
 * Seven tunables were deploy-time until core#2265 and core#2268 moved them into the platform settings, and a deployment
 * that had set one keeps setting it: no chart templates these variables, so only a hand-added environment entry ever
 * set one, and nothing seeds a settings row from it. The value is then simply ignored, and the platform runs on the
 * setting's default instead -- which for {@code CBOM_SYNC_ASSET_INGEST_ENABLED=false} means asset ingest is <b>on</b>
 * after the upgrade. That is the one this exists for; the rest are performance tuning, and this reports them for the
 * same reason.
 *
 * <p>
 * A warning rather than a refusal to start: the variable is inert, not wrong, and a platform that will not boot until
 * an operator edits a deployment is a worse answer to a value that has a working default.
 */
@Component
public class RetiredCbomSyncEnvironment {

    /** Every {@code cbom.sync.*} override that once existed, in the order the yml block listed them. */
    static final List<String> RETIRED_VARIABLES = List
            .of("CBOM_SYNC_PAGE_SIZE", "CBOM_SYNC_OVERLAP", "CBOM_SYNC_SKIPPED_RETRY_RUNS",
                    "CBOM_SYNC_ASSET_INGEST_ENABLED", "CBOM_SYNC_ASSET_BATCH_SIZE", "CBOM_SYNC_MAX_INGEST_DOCUMENTS",
                    "CBOM_SYNC_INGEST_RETRY_AFTER");

    private static final Logger logger = LoggerFactory.getLogger(RetiredCbomSyncEnvironment.class);

    /** Which of them this environment still sets. A pure function of the lookup, so it is testable without one. */
    static List<String> stillSet(UnaryOperator<String> environment) {
        return RETIRED_VARIABLES.stream().filter(name -> {
            String value = environment.apply(name);
            return value != null && !value.isBlank();
        }).toList();
    }

    @PostConstruct
    void reportRetiredVariables() {
        List<String> set = stillSet(System::getenv);
        if (set.isEmpty()) {
            return;
        }
        logger
                .warn("{} no longer configures the CBOM sync and is ignored; the sync runs on the platform settings (Settings, the utils section). Set the value there, and drop the variable from the deployment",
                        String.join(", ", set));
    }
}
