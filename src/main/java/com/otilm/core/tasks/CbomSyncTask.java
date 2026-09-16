package com.otilm.core.tasks;

import com.otilm.api.exception.CbomRepositoryException;
import org.springframework.stereotype.Component;

/**
 * The hourly pass: everything the repository has listed since the last successful run of <em>this</em> job, less the
 * configured overlap.
 *
 * <p>
 * The watermark is read from this job's own history, so a reconciliation run neither advances it nor holds it back --
 * see {@link CbomReconcileTask} for the pass that reaches behind it.
 */
@Component
public class CbomSyncTask extends AbstractCbomFeedTask {

    public static final String NAME = "CbomSyncTask";
    private static final String CRON_EXPRESSION = "0 0 * ? * *";

    public CbomSyncTask() {
        super(NAME, CRON_EXPRESSION);
    }

    @Override
    protected String runPass() throws CbomRepositoryException {
        return cbomService().sync();
    }
}
