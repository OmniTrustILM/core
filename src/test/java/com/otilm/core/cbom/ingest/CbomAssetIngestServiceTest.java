package com.otilm.core.cbom.ingest;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.cbom.CbomAssetSyncState;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.CbomAssetExtractor;
import com.otilm.core.cbom.asset.identity.CryptoAssetIdentity;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import com.otilm.core.cbom.pqc.PqcEvaluator;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.events.transaction.TransactionHandler;
import com.otilm.core.model.cbom.PqcStaleVerdictRow;
import com.otilm.core.service.writer.cbom.CbomAssetSyncStateWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetAliasWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.springframework.dao.DataIntegrityViolationException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * The unit of work's control flow, without a database.
 *
 * <p>
 * What is asserted here is what a CBOM row says after each way an ingest can end, and the one ordering that a database
 * would only reveal as an intermittent deadlock: the alias advisory lock is taken before the first asset row lock. The
 * extractor is the real one over the ratified tables, because a mocked extraction would only prove that the
 * orchestrator passes through whatever it is handed.
 */
class CbomAssetIngestServiceTest {

    private static final UUID CBOM = UUID.randomUUID();
    private static final OffsetDateTime SEEN_AT = OffsetDateTime.parse("2026-09-14T10:00:00Z");
    private static final String LOCK_KEY = CbomAssetIngestService.assetSyncLockKey(CBOM);

    private final CryptoAssetWriter assetWriter = mock(CryptoAssetWriter.class);
    private final CryptoAssetSourceWriter sourceWriter = mock(CryptoAssetSourceWriter.class);
    private final CbomAssetSyncStateWriter stateWriter = mock(CbomAssetSyncStateWriter.class);
    private final CbomRepository cbomRepository = mock(CbomRepository.class);
    private final CryptoAssetRepository assetRepository = mock(CryptoAssetRepository.class);
    private final ClusterOperationSynchronizer synchronizer = mock(ClusterOperationSynchronizer.class);
    private final CbomAssetDetachService detachService = mock(CbomAssetDetachService.class);

    @Test
    void everyAssetIsStoredWithItsSourceAndTheCbomReadsSynced() {
        when(synchronizer.tryLock(LOCK_KEY)).thenReturn(true);
        whenUpsertReturnsAFreshUuid();

        CbomAssetIngestService.IngestOutcome outcome = ingest(twoAlgorithms(), 100);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.INGESTED);
        verify(assetWriter, times(2)).upsertIdentity(anyString(), any(), any());
        verify(sourceWriter, times(2)).upsertSource(any(), eq(CBOM), any(), any(), anyInt(), eq(SEEN_AT));
        verify(stateWriter).markInProgress(CBOM);
        verify(stateWriter).markSynced(CBOM, SEEN_AT);
        verify(stateWriter, never()).markFailed(any(), anyString());
    }

    /**
     * The lock is keyed on the document, not on the operation. A single key would serialize every node's ingest onto
     * one worker and throw away the document read and the extraction each loser had already paid for -- which is
     * exactly what the backlog pass's row claim exists to avoid.
     */
    @Test
    void theClusterLockIsKeyedOnTheCbomRatherThanOnTheOperation() {
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        whenUpsertReturnsAFreshUuid();

        ingest(twoAlgorithms(), 100);

        verify(synchronizer).tryLock(LOCK_KEY);
        assertThat(LOCK_KEY).contains(CBOM.toString());
    }

    /**
     * The ordering the writers document and no single-threaded run can violate visibly: the advisory lock outranks
     * every {@code crypto_asset} row lock, so an ingest that took a row lock first could deadlock against a concurrent
     * alias decision. Asserted here because a database would show it only as an intermittent failure.
     */
    @Test
    void theAliasLockIsTakenBeforeTheFirstAssetRowLock() {
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        whenUpsertReturnsAFreshUuid();

        ingest(twoAlgorithms(), 100);

        InOrder order = inOrder(synchronizer, assetWriter);
        order.verify(synchronizer).lock(CryptoAssetAliasWriter.ALIAS_DECISION_LOCK);
        order.verify(assetWriter, atLeastOnce()).upsertIdentity(anyString(), any(), any());
    }

    @Test
    void assetsAreCommittedInBatchesOfTheConfiguredSize() {
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        whenUpsertReturnsAFreshUuid();

        ingest(twoAlgorithms(), 1);

        // One lock acquisition per batch transaction, so two assets at a batch size of one is two transactions.
        verify(synchronizer, times(2)).tryLock(LOCK_KEY);
    }

    /**
     * The claim goes back. Left {@code IN_PROGRESS}, the row drops out of the pending list and into the retry list,
     * where it waits out {@code cbom.sync.ingest-retry-after} -- a whole run skipped over work no node is doing.
     */
    @Test
    void aContendedClusterLockGivesTheClaimBackAndLeavesTheCbomOwingAnIngest() {
        when(cbomRepository.findAssetSyncState(CBOM)).thenReturn(Optional.of(CbomAssetSyncState.PENDING));
        when(synchronizer.tryLock(anyString())).thenReturn(false);

        CbomAssetIngestService.IngestOutcome outcome = ingest(twoAlgorithms(), 100);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.LOCKED_ELSEWHERE);
        verify(stateWriter).releaseClaim(CBOM, CbomAssetSyncState.PENDING);
        verify(assetWriter, never()).upsertIdentity(anyString(), any(), any());
        verify(stateWriter, never()).markSynced(any(), any());
        verify(stateWriter, never()).markFailed(any(), anyString());
    }

    /**
     * A document with no usable scope is refused rather than ingested: with nothing refuted a fabricated digest is
     * trusted and every certificate's public-key slot empties, and both merge rows that are not the same asset. An
     * over-merge needs a re-key to undo; a refusal is retried.
     */
    @Test
    void aDocumentWhoseScopeCouldNotBeBuiltIsRefusedWithoutWritingAnything() {
        CbomAssetExtractor extractor = mock(CbomAssetExtractor.class);
        when(extractor.extract(any(JsonNode.class)))
                .thenReturn(new CbomAssetExtractor.Extraction(List.of(), List.of(), false, true));

        CbomAssetIngestService.IngestOutcome outcome = service(extractor, 100).ingest(CBOM, twoAlgorithms(), SEEN_AT);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.REFUSED);
        verify(assetWriter, never()).upsertIdentity(anyString(), any(), any());
        ArgumentCaptor<String> reason = ArgumentCaptor.forClass(String.class);
        verify(stateWriter).markFailed(eq(CBOM), reason.capture());
        assertThat(reason.getValue()).contains("cross-component scope");
    }

    /**
     * The failure is recorded even though the transaction carrying the write rolled back, and what it records is text
     * this platform shaped -- never the driver's, whose DETAIL line carries the failing row and with it the identity
     * key. The exception carries no {@code ConstraintViolationException} cause, so this pins the fallback rather than
     * the constraint mapping.
     */
    @Test
    void aRefusedWriteLeavesTheCbomFailedWithTextNoDriverWrote() {
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetWriter.upsertIdentity(anyString(), any(), any()))
                .thenThrow(new DataIntegrityViolationException(
                        "ERROR: duplicate key value violates unique constraint \"crypto_asset_identity_key_key\" "
                                + "DETAIL: Key (identity_key)=(ALG|AES|256||||) already exists."));

        CbomAssetIngestService.IngestOutcome outcome = ingest(twoAlgorithms(), 100);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.FAILED);
        ArgumentCaptor<String> reason = ArgumentCaptor.forClass(String.class);
        verify(stateWriter).markFailed(eq(CBOM), reason.capture());
        assertThat(reason.getValue()).doesNotContain("identity_key").doesNotContain("DETAIL");
        verify(stateWriter, never()).markSynced(any(), any());
    }

    /**
     * Most of what the write phase throws is not a constraint violation, and reporting it as one tells the operator
     * something false about a failure several of them could act on -- an alias already merging the asset above all. The
     * inventory's own writers shape that text for an operator, so it is passed through as they wrote it.
     */
    @Test
    void aWriterRefusalKeepsTheSentenceTheWriterShaped() {
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        when(assetWriter.upsertIdentity(anyString(), any(), any()))
                .thenThrow(new ValidationException(
                        ValidationError.create("An alias already merges this cryptographic asset into another one.")));

        ingest(twoAlgorithms(), 100);

        ArgumentCaptor<String> reason = ArgumentCaptor.forClass(String.class);
        verify(stateWriter).markFailed(eq(CBOM), reason.capture());
        assertThat(reason.getValue()).contains("An alias already merges this cryptographic asset");
        assertThat(reason.getValue()).doesNotContain("would violate a database constraint");
    }

    /**
     * The verdict is evaluated against the row the merge elected, not against the document being ingested: an asset
     * several CBOMs report has one payload, and it is not whichever document arrived last. Read through a native
     * projection, so a persistence context spanning two of the ingest's batch transactions -- which is what
     * {@code open-in-view} produces on the REST sync path -- cannot serve the row from before the merge.
     */
    @Test
    void theVerdictIsStampedFromTheMergedRowRatherThanTheDocument() {
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        UUID assetUuid = UUID.randomUUID();
        when(assetWriter.upsertIdentity(anyString(), any(), any())).thenReturn(assetUuid);
        when(assetRepository.verdictRowsByUuids(any())).thenReturn(List.of(mergedRsaRow(assetUuid)));

        ingest(oneAlgorithm(), 100);

        verify(assetRepository, never()).findById(any());
        verify(assetWriter, times(1)).applyPqcVerdict(eq(assetUuid), any(), anyString(), anyString(), anyInt(), any());
    }

    /**
     * Stamping is a latency decision, so it must not be able to fail the unit of work. Letting the exception out would
     * roll the batch back -- every identity and source write in it -- and fail the document for ever, since the retry
     * meets the same row. Left unstamped, the row is exactly what the sweep's work list selects.
     */
    @Test
    void anUnevaluableAssetDoesNotFailTheDocument() {
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        UUID assetUuid = UUID.randomUUID();
        when(assetWriter.upsertIdentity(anyString(), any(), any())).thenReturn(assetUuid);
        when(assetRepository.verdictRowsByUuids(any())).thenReturn(List.of(mergedRsaRow(assetUuid)));
        doThrowFromVerdictStamp();

        CbomAssetIngestService.IngestOutcome outcome = ingest(oneAlgorithm(), 100);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.INGESTED);
        verify(stateWriter).markSynced(CBOM, SEEN_AT);
        verify(stateWriter, never()).markFailed(any(), anyString());
    }

    /**
     * Supersede is what makes the inventory say what the newest version of each URN says. Every version keeps its own
     * {@code cbom} row, so the earlier one has to be withdrawn explicitly -- and after the new version's sources are
     * written, so that a run dying in between overstates a count rather than losing the asset.
     */
    @Test
    void theEarlierVersionsOfTheUrnAreWithdrawnAfterTheNewOneIsWritten() {
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        whenUpsertReturnsAFreshUuid();
        UUID earlier = UUID.randomUUID();
        when(cbomRepository.findSupersededVersionUuids(CBOM)).thenReturn(List.of(earlier));
        when(detachService.withdraw(earlier)).thenReturn(new CbomAssetDetachService.Withdrawal(2, 1, 0, true));

        CbomAssetIngestService.IngestOutcome outcome = ingest(twoAlgorithms(), 100);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.INGESTED);
        InOrder order = inOrder(sourceWriter, detachService, stateWriter);
        order.verify(sourceWriter, atLeastOnce()).upsertSource(any(), eq(CBOM), any(), any(), anyInt(), any());
        order.verify(detachService).withdraw(earlier);
        order.verify(stateWriter).markSynced(CBOM, SEEN_AT);
    }

    /**
     * A withdrawal another node took the lock for leaves the whole unit owed: the CBOM is not marked synced, so the
     * next run redoes it -- upserts included, which are idempotent -- rather than leaving one asset sourced by two
     * revisions of the same document.
     */
    @Test
    void aContendedWithdrawalLeavesTheCbomOwingTheWholeUnit() {
        when(cbomRepository.findAssetSyncState(CBOM)).thenReturn(Optional.of(CbomAssetSyncState.PENDING));
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        whenUpsertReturnsAFreshUuid();
        UUID earlier = UUID.randomUUID();
        when(cbomRepository.findSupersededVersionUuids(CBOM)).thenReturn(List.of(earlier));
        when(detachService.withdraw(earlier)).thenReturn(new CbomAssetDetachService.Withdrawal(0, 0, 0, false));

        CbomAssetIngestService.IngestOutcome outcome = ingest(twoAlgorithms(), 100);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.LOCKED_ELSEWHERE);
        verify(stateWriter, never()).markSynced(any(), any());
        verify(stateWriter, never()).markFailed(any(), anyString());
        // The claim goes back, as it does when a batch finds the lock taken: the whole unit is owed again.
        verify(stateWriter).releaseClaim(CBOM, CbomAssetSyncState.PENDING);
    }

    /**
     * Two components reporting the same algorithm are one source row, and the arbiter's {@code DO UPDATE} assigns
     * rather than accumulates on a {@code last_seen_at} tie -- which every component of one document is. Written one at
     * a time the last component would replace the first's payload and count; folded here they add up.
     */
    @Test
    void componentsThatKeyAsOneAssetAreWrittenOnce() {
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        whenUpsertReturnsAFreshUuid();

        ingest(theSameAlgorithmTwice(), 100);

        ArgumentCaptor<Integer> occurrences = ArgumentCaptor.forClass(Integer.class);
        ArgumentCaptor<List<Map<String, Object>>> evidence = ArgumentCaptor.forClass(List.class);
        verify(sourceWriter, times(1))
                .upsertSource(any(), eq(CBOM), any(), evidence.capture(), occurrences.capture(), eq(SEEN_AT));
        verify(assetWriter, times(1)).upsertIdentity(anyString(), any(), any());
        assertThat(occurrences.getValue()).isEqualTo(2);
        assertThat(evidence.getValue()).hasSize(2);
    }

    /**
     * The switch is checked inside the unit of work, not only by its callers: both passes return before reaching it
     * when it is off, and this is what makes "nothing is written" a property of every caller rather than of the two
     * that remember to ask. The row is left exactly as it was found, so turning the switch back on resumes.
     */
    @Test
    void ingestWritesNothingWhenTheKillSwitchIsOff() {
        CbomAssetIngestService.IngestOutcome outcome = new CbomAssetIngestService(realExtractor(), assetWriter,
                sourceWriter, detachService, stateWriter, cbomRepository, assetRepository,
                new PqcEvaluator(new AssetNormalizer(IdentityTables.load())), synchronizer, new TransactionHandler(),
                new SimpleMeterRegistry(), CbomIngestTestFixtures.propertiesWithIngestDisabled())
                .ingest(CBOM, twoAlgorithms(), SEEN_AT);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.DISABLED);
        verify(stateWriter, never()).markInProgress(any());
        verify(assetWriter, never()).upsertIdentity(anyString(), any(), any());
        verify(synchronizer, never()).tryLock(anyString());
    }

    /**
     * A revision an <em>ingested</em> later one supersedes is never extracted, takes no claim, and is settled without a
     * sync time of its own.
     */
    @Test
    void aSupersededVersionIsNotExtracted() {
        when(cbomRepository.hasIngestedLaterVersion(CBOM)).thenReturn(true);
        when(detachService.withdraw(CBOM)).thenReturn(CbomAssetDetachService.Withdrawal.NOTHING);
        CbomAssetExtractor extractor = mock(CbomAssetExtractor.class);

        CbomAssetIngestService.IngestOutcome outcome = service(extractor, 100).ingest(CBOM, twoAlgorithms(), SEEN_AT);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.SUPERSEDED);
        verify(extractor, never()).extract(any(JsonNode.class));
        verify(assetWriter, never()).upsertIdentity(anyString(), any(), any());
        verify(stateWriter, never()).markInProgress(any());
        verify(stateWriter).markSuperseded(CBOM);
        verify(stateWriter, never()).markSynced(any(), any());
    }

    /**
     * A later row that has not itself been ingested is not a supersession. After the upgrade that introduced the state
     * column every pre-existing row is PENDING, so a serial's revisions are commonly all unsynced at once; writing the
     * older one off against a newer row whose document may never be readable would leave the URN contributing nothing
     * at all, and nothing ever moves a SYNCED row back onto a work list.
     */
    @Test
    void aLaterVersionThatHasNotItselfBeenIngestedSupersedesNothing() {
        when(cbomRepository.hasIngestedLaterVersion(CBOM)).thenReturn(false);
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        whenUpsertReturnsAFreshUuid();

        CbomAssetIngestService.IngestOutcome outcome = ingest(twoAlgorithms(), 100);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.INGESTED);
        verify(assetWriter, atLeastOnce()).upsertIdentity(anyString(), any(), any());
    }

    /**
     * The supersede check is re-read under the cluster lock, because that lock is released at every batch commit. In
     * the gap a newer revision can be stored, ingested, and withdraw everything written so far; resuming would
     * re-attach a superseded revision's links to assets the newer one now owns, permanently -- the newer row is SYNCED
     * and never looks again.
     */
    @Test
    void aVersionOvertakenBetweenBatchesAbandonsTheRestAndGivesBackWhatItWrote() {
        when(cbomRepository.findAssetSyncState(CBOM)).thenReturn(Optional.of(CbomAssetSyncState.PENDING));
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        whenUpsertReturnsAFreshUuid();
        // False at entry, true by the second batch: a newer revision landed in the gap between the two commits.
        when(cbomRepository.hasIngestedLaterVersion(CBOM)).thenReturn(false, false, true);
        when(detachService.withdraw(CBOM)).thenReturn(new CbomAssetDetachService.Withdrawal(1, 1, 0, true));

        CbomAssetIngestService.IngestOutcome outcome = ingest(twoAlgorithms(), 1);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.SUPERSEDED);
        // What the first batch wrote is given back rather than stranded: nothing else would ever withdraw it, since
        // the withdrawal half of supersession only runs from the ingesting version.
        verify(detachService).withdraw(CBOM);
        verify(stateWriter).markSuperseded(CBOM);
        verify(stateWriter, never()).markSynced(any(), any());
    }

    /** A withdrawal of its own contribution that another node holds the lock for leaves the row owing the unit. */
    @Test
    void aSupersededVersionWhoseOwnWithdrawalIsContendedIsNotWrittenOff() {
        when(cbomRepository.hasIngestedLaterVersion(CBOM)).thenReturn(true);
        when(cbomRepository.findAssetSyncState(CBOM)).thenReturn(Optional.of(CbomAssetSyncState.FAILED));
        when(detachService.withdraw(CBOM)).thenReturn(new CbomAssetDetachService.Withdrawal(1, 0, 0, false));

        CbomAssetIngestService.IngestOutcome outcome = service(mock(CbomAssetExtractor.class), 100)
                .ingest(CBOM, twoAlgorithms(), SEEN_AT);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.LOCKED_ELSEWHERE);
        verify(stateWriter, never()).markSuperseded(any());
        verify(stateWriter).releaseClaim(CBOM, CbomAssetSyncState.FAILED);
    }

    /**
     * A CBOM deleted while its assets were being ingested stops the ingest instead of sourcing a header that is gone.
     *
     * <p>
     * The lock is released at every batch commit, and the deletion takes it to withdraw the inventory and remove the
     * header. Resuming would insert {@code crypto_asset_source} rows against a {@code cbom_uuid} that no longer exists:
     * a foreign-key violation, a noisy failed document, and a {@code markFailed} that updates no row because there is
     * no row. The probe sits next to the supersession re-read, which is there for the same reason.
     */
    @Test
    void aCbomDeletedBetweenTwoBatchesStopsTheIngestRatherThanSourcingAMissingHeader() {
        when(cbomRepository.hasIngestedLaterVersion(CBOM)).thenReturn(false);
        when(synchronizer.tryLock(anyString())).thenReturn(true);
        whenUpsertReturnsAFreshUuid();
        CbomAssetIngestService service = service(realExtractor(), 1);
        when(cbomRepository.existsById(CBOM)).thenReturn(true, false);

        CbomAssetIngestService.IngestOutcome outcome = service.ingest(CBOM, twoAlgorithms(), SEEN_AT);

        assertThat(outcome).isEqualTo(CbomAssetIngestService.IngestOutcome.DELETED);
        verify(stateWriter, never()).markSynced(any(), any());
    }

    // ---------------------------------------------------------------- fixtures

    private CbomAssetIngestService.IngestOutcome ingest(JsonNode document, int batchSize) {
        return service(realExtractor(), batchSize).ingest(CBOM, document, SEEN_AT);
    }

    private CbomAssetIngestService service(CbomAssetExtractor extractor, int batchSize) {
        // The header is there unless a test says otherwise: every batch re-reads it under the lock, because a deletion
        // can remove it in the gap between two batch commits.
        when(cbomRepository.existsById(CBOM)).thenReturn(true);
        return new CbomAssetIngestService(extractor, assetWriter, sourceWriter, detachService, stateWriter,
                cbomRepository, assetRepository, new PqcEvaluator(new AssetNormalizer(IdentityTables.load())),
                synchronizer, new TransactionHandler(), new SimpleMeterRegistry(),
                CbomIngestTestFixtures.properties(batchSize));
    }

    private void doThrowFromVerdictStamp() {
        org.mockito.Mockito
                .doThrow(new IllegalStateException("the rules could not evaluate this row"))
                .when(assetWriter)
                .applyPqcVerdict(any(), any(), anyString(), anyString(), anyInt(), any());
    }

    private static CbomAssetExtractor realExtractor() {
        return new CbomAssetExtractor(new CryptoAssetIdentity(new AssetNormalizer(IdentityTables.load())));
    }

    private void whenUpsertReturnsAFreshUuid() {
        when(assetWriter.upsertIdentity(anyString(), any(), any())).thenAnswer(call -> UUID.randomUUID());
    }

    /** A row as the database holds it after the merge, with a payload the document being ingested does not carry. */
    private static PqcStaleVerdictRow mergedRsaRow(UUID uuid) {
        return new PqcStaleVerdictRow(uuid, CryptographicAssetType.ALGORITHM, "RSA-2048", null, "RSA", null, "2048",
                null, null, null, null,
                "{\"assetType\":\"algorithm\",\"algorithmProperties\":{\"parameterSetIdentifier\":\"2048\"}}", 1L);
    }

    private static JsonNode oneAlgorithm() {
        return CbomIngestTestFixtures.algorithmDocument("RSA-2048");
    }

    private static JsonNode twoAlgorithms() {
        return CbomIngestTestFixtures.algorithmDocument("AES-256", "RSA-2048");
    }

    /** Two components reporting the same algorithm, each with its own occurrence evidence. */
    private static JsonNode theSameAlgorithmTwice() {
        return CbomIngestTestFixtures
                .read("{\"components\":["
                        + "{\"type\":\"cryptographic-asset\",\"name\":\"RSA-2048\",\"cryptoProperties\":"
                        + "{\"assetType\":\"algorithm\",\"algorithmProperties\":{}},"
                        + "\"evidence\":{\"occurrences\":[{\"location\":\"/one\"}]}},"
                        + "{\"type\":\"cryptographic-asset\",\"name\":\"RSA-2048\",\"cryptoProperties\":"
                        + "{\"assetType\":\"algorithm\",\"algorithmProperties\":{}},"
                        + "\"evidence\":{\"occurrences\":[{\"location\":\"/two\"}]}}]}");
    }

}
