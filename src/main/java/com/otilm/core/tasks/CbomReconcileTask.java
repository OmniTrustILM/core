package com.otilm.core.tasks;

import com.otilm.api.exception.CbomRepositoryException;
import org.springframework.stereotype.Component;

/**
 * The weekly pass: the repository's whole listing, not the window since the last hourly run.
 *
 * <p>
 * <b>What the hourly pass cannot recover.</b> {@code cbom.sync.overlap} and the {@code cbom_sync_skip} retry budget
 * together cover an entry the feed <em>offered</em> and Core then failed on -- clock skew against the object store, an
 * in-flight upload, a document that could not be read for a moment. Neither covers an entry the feed never offered
 * inside any window Core asked for: a run that recorded SUCCESS after the listing had already moved past an entry, a
 * repository that back-dated one, an entry written off as permanently skipped while its listing window closed behind
 * it. Those are invisible to a pass that only ever looks forward from a watermark, and this is the pass that sees them.
 *
 * <p>
 * <b>It cannot resurrect what an operator deleted.</b> Deletion in Core is not deletion in the repository, so the whole
 * listing still offers every deleted document; the feed pass tests {@code cbom_tombstone} before storing an entry,
 * which is what makes a full re-list safe to run at all.
 *
 * <p>
 * <b>Sunday 02:30, and it occupies the same listener as every other scheduled job</b> -- a full listing over a large
 * estate is the longest CBOM job a deployment runs, and while it holds that thread the jobs behind it wait. The hour is
 * chosen to miss the hourly sync (:00) and the PQC sweep (:30 hourly is the same minute, but this fires on one day of
 * the week and the sweep's work is bounded by its batch budget).
 */
@Component
public class CbomReconcileTask extends AbstractCbomFeedTask {

    public static final String NAME = "CbomReconcileTask";

    /** Sundays at 02:30, off the hourly sync's minute and outside the working week's load. */
    private static final String CRON_EXPRESSION = "0 30 2 ? * SUN";

    public CbomReconcileTask() {
        super(NAME, CRON_EXPRESSION);
    }

    @Override
    protected String runPass() throws CbomRepositoryException {
        return cbomService().reconcile();
    }
}
