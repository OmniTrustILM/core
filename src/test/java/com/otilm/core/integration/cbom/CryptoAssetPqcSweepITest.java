package com.otilm.core.integration.cbom;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.AssetRowKeys;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.pqc.PqcRuleset;
import com.otilm.core.cbom.pqc.PqcVerdictSweeper;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.support.TransactionTemplate;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The re-evaluation sweep against real PostgreSQL.
 *
 * <p>
 * What it proves is the orchestration, not the SQL: the two-timestamp semantics are already pinned by
 * {@link CryptoAssetInventoryITest#aReEvaluationAdvancesEvaluatedAtButNotDecidedAt} and re-proving them here would only
 * assert that the same statement still does what that test says. What is new is the parts that can only be wrong in a
 * database -- the keyset cursor advancing across batches, the per-sweep cap, the staleness guard refusing to overwrite
 * a fresher verdict, and the advisory lock admitting one sweeper.
 */
class CryptoAssetPqcSweepITest extends BaseSpringBootTest {

    private static final int AWAIT_TIMEOUT_SECONDS = 10;

    @Autowired
    private CryptoAssetRepository assetRepository;

    @Autowired
    private CryptoAssetWriter assetWriter;

    @Autowired
    private PqcVerdictSweeper sweeper;

    @Autowired
    private ClusterOperationSynchronizer synchronizer;

    @Autowired
    private PlatformTransactionManager transactionManager;

    private final ExecutorService lockHolderThread = Executors.newSingleThreadExecutor();

    @AfterEach
    void stopLockHolder() {
        lockHolderThread.shutdownNow();
    }

    @Test
    void aSweepRestampsEveryRowThatCarriesNoVerdictYet() {
        UUID rsa = upsert("RSA", "rsa", "2048");
        UUID aes = upsert("AES", "aes", "256");

        PqcVerdictSweeper.SweepOutcome outcome = sweeper.sweep();

        assertThat(outcome.ran()).isTrue();
        assertThat(outcome.evaluated()).isGreaterThanOrEqualTo(2);
        assertThat(verdictOf(rsa)).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(verdictOf(aes)).isEqualTo(PqcVerdict.READY);
        assertThat(asset(rsa).getPqcRulesetVersion()).isEqualTo(PqcRuleset.VERSION);
        assertThat(asset(rsa).getPqcEvaluatedAt()).isNotNull();
        assertThat(asset(rsa).getPqcDecidedAt()).isNotNull();
    }

    @Test
    void aSweepLeavesNoStaleRowBehind() {
        for (int i = 0; i < 12; i++) {
            upsert("RSA-" + i, "rsa", String.valueOf(2048 + i));
        }

        sweeper.sweep();

        assertThat(assetRepository
                .findStaleVerdictRows(PqcRuleset.VERSION, new UUID(0L, 0L),
                        org.springframework.data.domain.PageRequest.of(0, 100)))
                .describedAs("after a successful sweep, nothing may still carry a verdict below the shipped generation")
                .isEmpty();
    }

    /**
     * A verdict is not an identity: the sweep must leave the keying columns and their generation exactly as it found
     * them, or a re-evaluation would look like a re-keying to every consumer of {@code ruleset_version}.
     */
    @Test
    void aSweepTouchesNoIdentityColumn() {
        UUID uuid = upsert("RSA", "rsa", "2048");
        CryptoAsset before = asset(uuid);

        sweeper.sweep();

        CryptoAsset after = asset(uuid);
        assertThat(after.getIdentityKey()).isEqualTo(before.getIdentityKey());
        assertThat(after.getRulesetVersion()).isEqualTo(before.getRulesetVersion());
        assertThat(after.getAlgorithmFamily()).isEqualTo(before.getAlgorithmFamily());
    }

    /**
     * The window between the sweep's read and its write. Ingest can land a current-generation verdict in it, and the
     * guard is what stops the sweep overwriting that with one computed from the columns it read earlier -- a row that
     * would then look freshly evaluated and be wrong until the next generation bump, which is the shape of failure
     * nothing would find.
     */
    @Test
    void afresherVerdictIsNotOverwritten() {
        UUID uuid = upsert("RSA", "rsa", "2048");
        assetWriter
                .applyPqcVerdict(uuid, PqcVerdict.READY, "INGEST-WON", "written by ingest", PqcRuleset.VERSION, null);

        sweeper.sweep();

        assertThat(asset(uuid).getPqcRuleId())
                .describedAs("the sweep must not overwrite a verdict already at the shipped generation")
                .isEqualTo("INGEST-WON");
        assertThat(verdictOf(uuid)).isEqualTo(PqcVerdict.READY);
    }

    /** The advisory lock admits one sweeper; a contended run skips rather than blocking or double-writing. */
    @Test
    void aContendedSweepSkipsRatherThanWaiting() throws Exception {
        upsert("RSA", "rsa", "2048");

        CountDownLatch release = new CountDownLatch(1);
        CompletableFuture<Boolean> acquired = new CompletableFuture<>();
        lockHolderThread.submit(() -> new TransactionTemplate(transactionManager).execute(status -> {
            acquired.complete(synchronizer.tryLock(ClusterOperationSynchronizer.Operation.CRYPTO_ASSET_PQC_SWEEP));
            try {
                release.await(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            return null;
        }));
        assertThat(acquired.get(AWAIT_TIMEOUT_SECONDS, TimeUnit.SECONDS)).isTrue();

        try {
            PqcVerdictSweeper.SweepOutcome contended = sweeper.sweep();
            assertThat(contended.ran()).describedAs("contended sweep must skip, not block").isFalse();
            assertThat(contended.written()).isZero();
        } finally {
            release.countDown();
        }

        assertThat(sweeper.sweep().ran()).describedAs("the released lock frees the next sweep").isTrue();
    }

    /**
     * The cursor, not an offset. A written row leaves the work list, so an offset would skip exactly as many unread
     * rows as the previous batch wrote -- this seeds more rows than one batch holds and asserts none was missed.
     */
    @Test
    void theSweepAdvancesAcrossBatchesWithoutSkippingARow() {
        for (int i = 0; i < 25; i++) {
            upsert("RSA-batch-" + i, "rsa", String.valueOf(1024 + i));
        }

        PqcVerdictSweeper.SweepOutcome outcome = sweeper.sweep();

        assertThat(outcome.evaluated()).isGreaterThanOrEqualTo(25);
        assertThat(assetRepository
                .findStaleVerdictRows(PqcRuleset.VERSION, new UUID(0L, 0L),
                        org.springframework.data.domain.PageRequest.of(0, 100)))
                .isEmpty();
    }

    private UUID upsert(String name, String family, String parameterSet) {
        CryptoAssetIdentityFields fields = new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, name, null,
                family, "signature", parameterSet, null, null, null, null);
        return assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, null);
    }

    private CryptoAsset asset(UUID uuid) {
        return assetRepository.findById(uuid).orElseThrow();
    }

    private PqcVerdict verdictOf(UUID uuid) {
        return asset(uuid).getPqcVerdict();
    }
}
