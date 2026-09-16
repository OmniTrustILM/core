package com.otilm.core.dao.repository.cbom;

import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.SecurityFilterRepository;
import com.otilm.core.model.cbom.CryptoAssetListRow;
import com.otilm.core.model.cbom.PqcStaleVerdictRow;
import jakarta.persistence.Tuple;
import java.util.Collection;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

/**
 * Queries and guarded writes for the deduplicated cryptographic asset inventory.
 *
 * <p>
 * Every {@code @Modifying} statement here is called from a writer bean in {@code ..service.writer..} and from nowhere
 * else -- {@code CryptoAssetWriter} for the ingest path, {@code CryptoAssetPqcVerdictWriter} for the re-evaluation
 * sweep's batches. The transactional boundary lives on those writers, never on this interface.
 */
@Repository
public interface CryptoAssetRepository extends SecurityFilterRepository<CryptoAsset, UUID> {

    Optional<CryptoAsset> findByIdentityKey(String identityKey);

    @Query("SELECT a.uuid FROM CryptoAsset a WHERE a.identityKey = :key")
    Optional<UUID> findUuidByIdentityKey(@Param("key") String key);

    /**
     * Assets keyed by a rule-set generation older than {@code version} -- the re-keying sweep's work list, and the
     * reason the rule-set version is recorded on the row instead of folded into the key.
     */
    @Query("SELECT a.uuid FROM CryptoAsset a WHERE a.rulesetVersion < :version ORDER BY a.uuid")
    List<UUID> findUuidsKeyedBefore(@Param("version") int version);

    /**
     * Which of the given assets no CBOM sources any more, and which of those an operator decision points at -- the
     * orphan rule's two questions, answered together for a whole batch.
     *
     * <p>
     * <b>One round trip for the batch, not two per asset.</b> The caller runs inside the transaction holding
     * {@code ALIAS_DECISION_LOCK}, which every ingest batch on every node also blocks on, and it already pays three
     * statements per asset to detach it. Asking both questions per asset would make that five, all serialized behind a
     * cluster-wide lock; on a document with a few thousand assets that is the whole cluster's ingest throughput.
     *
     * <p>
     * <b>The absence of a source row, not {@code source_count}.</b> The counter is bookkeeping only
     * {@code recomputeMergeFromSources} maintains, while {@code crypto_asset_source} is the fact it is derived from --
     * and what this answer authorizes is an irreversible {@code DELETE} whose
     * {@code crypto_asset_source_to_crypto_asset_key} cascade takes every other CBOM's provenance with it. Gating that
     * on a derived counter turns any divergence into data loss instead of a stale number. The predicate is served by
     * {@code uq_crypto_asset_source}, which leads with {@code asset_uuid}, so it costs what the counter read cost.
     *
     * <p>
     * <b>Only the canonical side of a merge.</b> {@code crypto_asset_alias} has exactly one foreign key --
     * {@code canonical_key}, {@code ON DELETE CASCADE} -- so deleting an orphan is capable of destroying an operator's
     * merge decision on that side alone. An orphan whose key is only some alias's {@code absorbed_key} can be collected
     * without touching the alias at all, and per the migration's own comment an absorbed row that no longer exists is
     * the alias table's normal state. Retaining those would keep rows the documents no longer mention, for a risk that
     * is not present on that side.
     *
     * <p>
     * Native, so it reads the rows the detachment just wrote rather than entities the persistence context cached before
     * it: {@code recomputeMergeFromSources} is a {@code @Modifying} native statement, which leaves any managed copy
     * stale. An asset with no {@code crypto_asset} row is simply not returned, which is the same answer as "nothing to
     * collect". The alias join stays inside the repository rather than the key being handed to a caller: the key is a
     * hash over a low-entropy preimage, and the fewer sources that name it the narrower the disclosure surface stays.
     */
    @Query(value = """
            SELECT a.uuid,
                   EXISTS (SELECT 1 FROM {h-schema}crypto_asset_alias al
                           WHERE al.canonical_key = a.identity_key) AS aliased
            FROM {h-schema}crypto_asset a
            WHERE a.uuid IN (:uuids)
              AND NOT EXISTS (SELECT 1 FROM {h-schema}crypto_asset_source s WHERE s.asset_uuid = a.uuid)
            """, nativeQuery = true)
    List<Object[]> findOrphanRows(@Param("uuids") Collection<UUID> uuids);

    /** One orphaned asset of a withdrawn batch, and whether an operator's merge decision points at it. */
    record OrphanRow(UUID uuid, boolean namedByAnAlias) {
    }

    /** {@link #findOrphanRows}, mapped. Empty for an empty batch: {@code IN ()} is not valid SQL. */
    default List<OrphanRow> orphansAmong(Collection<UUID> uuids) {
        if (uuids.isEmpty()) {
            return List.of();
        }
        return findOrphanRows(uuids).stream().map(row -> new OrphanRow((UUID) row[0], (Boolean) row[1])).toList();
    }

    /**
     * Inserts the asset for an identity key, or refreshes the identity columns of the row already keyed under it.
     *
     * <p>
     * <b>Concurrency:</b> atomic on the unique identity key -- a concurrent loser is a clean re-write, not a constraint
     * violation, which is what makes a re-sync idempotent without a read-then-write window to race in.
     *
     * <p>
     * <b>Rule-set version:</b> written on both branches, from the same calculation that produced the key. A row the
     * current sync does not touch keeps the older version, which is what leaves it findable by
     * {@link #findUuidsKeyedBefore(int)}.
     *
     * <p>
     * <b>Identity:</b> on conflict the passed {@code uuid} is discarded with the rest of the losing insert; the caller
     * resolves the surviving row's uuid by its key afterwards.
     *
     * <p>
     * <b>Identity columns:</b> filled once, never reassigned. The key is built from the whole component, not from these
     * ten columns, so it is no longer a function of them -- and assigning {@code EXCLUDED.*} therefore let the last
     * producer to sync decide what an {@code EQUALS} filter matches. {@code primitive} is the clearest case, because it
     * is deliberately kept out of the key: two CBOMs describing one RSA-2048 land on one key carrying different
     * primitives, and the row flipped on every re-sync. {@code COALESCE} makes a later report able to fill a gap but
     * never to overwrite an answer, which is the same rule the guard below already used and the only one that makes a
     * re-sync idempotent. The cost is accepted: a producer correcting its own spelling does not update the row, and
     * reconciling a genuine disagreement is an explicit decision rather than a side effect of sync order.
     *
     * <p>
     * <b>Curve:</b> bound as the members, so a hybrid scheme's members can each be matched on their own. The split is a
     * storage projection of the {@code +}-joined spelling the identity preimage hashes, and it is taken in Java rather
     * than in this statement -- {@code CompositeCurve} holds both directions of it, so the separator has one definition
     * and a caller that has to see individual members (folding a curve onto a class representative, core#2166) can.
     *
     * <p>
     * <b>Identity guard:</b> an existing guard survives, because it is a safety refusal rather than a field. A guard
     * says this row was deliberately kept separate — a refuted certificate digest, a bare common name facing a full
     * subject DN — and {@code CryptoAssetAliasWriter} refuses an alias by reading the guard that is on the row now.
     * Assigning {@code EXCLUDED.identity_guard} would therefore let any later unguarded report of the same normalized
     * identity clear the refusal as a side effect of ordinary re-ingest, and the merge it was protecting against would
     * become available. Lifting a guard is an explicit reviewed decision, never a consequence of re-reading a document.
     *
     * <p>
     * The merge bookkeeping and the PQC verdict are deliberately untouched: they belong to the source that was just
     * ingested and to the rule set, not to the identity.
     */
    @Modifying
    @Query(value = """
            INSERT INTO {h-schema}crypto_asset (uuid, identity_key, ruleset_version, asset_type, name, oid,
                    algorithm_family, primitive, parameter_set, curve, mode, padding, variant, identity_guard,
                    properties_leaf_count, source_count, i_cre, i_upd)
            VALUES (:uuid, :key, :rulesetVersion, :assetType, :name, :oid, :algorithmFamily, :primitive,
                    :parameterSet, :curve, :mode, :padding, :variant, :identityGuard,
                    0, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
            ON CONFLICT (identity_key) DO UPDATE SET
                ruleset_version = EXCLUDED.ruleset_version,
                asset_type = COALESCE(crypto_asset.asset_type, EXCLUDED.asset_type),
                name = COALESCE(crypto_asset.name, EXCLUDED.name),
                oid = COALESCE(crypto_asset.oid, EXCLUDED.oid),
                algorithm_family = COALESCE(crypto_asset.algorithm_family, EXCLUDED.algorithm_family),
                primitive = COALESCE(crypto_asset.primitive, EXCLUDED.primitive),
                parameter_set = COALESCE(crypto_asset.parameter_set, EXCLUDED.parameter_set),
                curve = COALESCE(crypto_asset.curve, EXCLUDED.curve),
                mode = COALESCE(crypto_asset.mode, EXCLUDED.mode),
                padding = COALESCE(crypto_asset.padding, EXCLUDED.padding),
                variant = COALESCE(crypto_asset.variant, EXCLUDED.variant),
                identity_guard = COALESCE(crypto_asset.identity_guard, EXCLUDED.identity_guard),
                i_upd = CURRENT_TIMESTAMP
            """, nativeQuery = true)
    void upsertIdentity(@Param("uuid") UUID uuid, @Param("key") String key, @Param("rulesetVersion") int rulesetVersion,
            @Param("assetType") String assetType, @Param("name") String name, @Param("oid") String oid,
            @Param("algorithmFamily") String algorithmFamily, @Param("primitive") String primitive,
            @Param("parameterSet") String parameterSet, @Param("curve") String[] curve, @Param("mode") String mode,
            @Param("padding") String padding, @Param("variant") String variant,
            @Param("identityGuard") String identityGuard);

    /**
     * Takes the asset's row lock before its source rows are touched.
     *
     * <p>
     * {@code crypto_asset} and {@code crypto_asset_source} reference each other -- CASCADE one way, SET NULL the other
     * -- so a path that deleted a source first would lock source-then-asset while ingest locks asset-then-source, and
     * the two deadlock whenever they meet on the same {@code (asset, cbom)} pair. Every path takes this lock first, so
     * the cycle cannot close.
     *
     * <p>
     * {@code FOR NO KEY UPDATE} rather than {@code FOR UPDATE} (which is what {@code PESSIMISTIC_WRITE} would emit):
     * inserting a source row needs only {@code FOR KEY SHARE} on its parent, and {@code FOR UPDATE} would block that
     * unrelated traffic for no gain.
     */
    @Query(value = "SELECT a.uuid FROM {h-schema}crypto_asset a WHERE a.uuid = :uuid FOR NO KEY UPDATE",
            nativeQuery = true)
    Optional<UUID> lockForSourceChange(@Param("uuid") UUID uuid);

    /**
     * Re-derives the asset's merged payload, provenance pointer and source count from the sources it has right now.
     *
     * <p>
     * The election is a total order -- richest payload, then hash, then uuid -- so two nodes recomputing the same asset
     * reach the same answer and the pointer cannot oscillate. The count subquery is a plain {@code FROM} item rather
     * than a correlated {@code LEFT JOIN}, so the statement still updates the row when the asset has no sources left:
     * that is exactly the case where the pointer and payload must be cleared.
     */
    @Modifying
    @Query(value = """
            UPDATE {h-schema}crypto_asset a
            SET properties_source_uuid = elected.uuid,
                merged_crypto_properties = elected.original_crypto_properties,
                properties_leaf_count = COALESCE(elected.properties_leaf_count, 0),
                properties_hash = elected.properties_hash,
                source_count = counted.n,
                i_upd = CURRENT_TIMESTAMP
            FROM (SELECT count(*) AS n FROM {h-schema}crypto_asset_source s WHERE s.asset_uuid = :uuid) counted
            LEFT JOIN LATERAL (
                SELECT s.uuid, s.original_crypto_properties, s.properties_leaf_count, s.properties_hash
                FROM {h-schema}crypto_asset_source s
                WHERE s.asset_uuid = :uuid
                ORDER BY s.properties_leaf_count DESC, s.properties_hash ASC, s.uuid ASC
                LIMIT 1
            ) elected ON true
            WHERE a.uuid = :uuid
            """, nativeQuery = true)
    void recomputeMergeFromSources(@Param("uuid") UUID uuid);

    /**
     * Stores a PQC verdict together with the rule that produced it and the fields that rule read. The identity columns
     * and {@code ruleset_version} are untouched: a verdict is not an identity.
     *
     * <p>
     * <b>Decided versus evaluated:</b> the contract asks two different questions of a verdict, so the row answers both.
     * {@code pqc_evaluated_at} advances on every call, including one that re-confirms the verdict it already held;
     * {@code pqc_decided_at} moves only when the value actually changes, so it dates the finding rather than the last
     * time anybody looked. {@code IS DISTINCT FROM} rather than {@code <>} because either side may be null and a null
     * comparison would silently take the confirm branch. Neither is derivable from {@code i_upd}, which moves on every
     * identity refresh.
     */
    @Modifying
    @Query(value = """
            UPDATE {h-schema}crypto_asset
            SET pqc_verdict = :verdict,
                pqc_rule_id = :ruleId,
                pqc_reason = :reason,
                pqc_ruleset_version = :rulesetVersion,
                pqc_evaluated_fields = CAST(:evaluatedFields AS jsonb),
                pqc_evaluated_at = CURRENT_TIMESTAMP,
                pqc_decided_at = CASE
                    WHEN crypto_asset.pqc_verdict IS DISTINCT FROM CAST(:verdict AS TEXT) THEN CURRENT_TIMESTAMP
                    ELSE COALESCE(crypto_asset.pqc_decided_at, CURRENT_TIMESTAMP)
                END,
                i_upd = CURRENT_TIMESTAMP
            WHERE uuid = :uuid
            """, nativeQuery = true)
    void applyPqcVerdict(@Param("uuid") UUID uuid, @Param("verdict") String verdict, @Param("ruleId") String ruleId,
            @Param("reason") String reason, @Param("rulesetVersion") int rulesetVersion,
            @Param("evaluatedFields") String evaluatedFields);

    /**
     * The sweep's work list, one keyset page of it. See {@link #staleVerdictRows} for what a caller uses.
     *
     * <p>
     * Native, and not for speed: {@code xmin} is the row version the guarded write compares, and no JPQL projection can
     * reach a system column. It has to be read in the <em>same</em> statement as the columns the verdict is computed
     * from -- the sweep's transaction is {@code READ COMMITTED}, so a second statement would see a later snapshot and a
     * write landing between the two would be invisible to the guard. {@code merged_crypto_properties} comes back as
     * text because the evaluator wants a {@code JsonNode}: the entity converter would build a {@code Map} only for the
     * sweep to serialize it again. {@code curve} comes back joined on {@code +} because the record and the rules read
     * the identity spelling, which the column stores split.
     *
     * <p>
     * <b>Stale</b> is either half of the contract: a verdict from an older generation of the rules, or a verdict older
     * than the row it describes. {@code pqc_evaluated_at < i_upd} catches the second -- a payload re-election, a richer
     * source winning, an identity refresh -- because the guarded write sets both to one {@code CURRENT_TIMESTAMP}, so a
     * verdict never re-offers itself while any later writer does.
     *
     * <p>
     * Keyset-cursored, and that is correctness rather than performance: a written row leaves this result set, so an
     * offset would skip exactly as many unread rows as the last batch wrote, and re-querying from the start only
     * terminates if every claimed row leaves -- one the guard refuses does not, and would return at the head forever.
     */
    @Query(value = """
            SELECT uuid,
                   asset_type,
                   name,
                   oid,
                   algorithm_family,
                   primitive,
                   parameter_set,
                   array_to_string(curve, '+') AS curve,
                   mode,
                   padding,
                   variant,
                   merged_crypto_properties::text AS merged_crypto_properties,
                   xmin::text::bigint AS row_version
            FROM {h-schema}crypto_asset
            WHERE (pqc_ruleset_version IS NULL
                    OR pqc_ruleset_version < :version
                    OR pqc_evaluated_at < i_upd)
              AND uuid > :after
            ORDER BY uuid
            LIMIT :limit
            """, nativeQuery = true)
    List<Tuple> findStaleVerdictRows(@Param("version") int version, @Param("after") UUID after,
            @Param("limit") int limit);

    /**
     * {@link #findStaleVerdictRows} mapped onto the record the sweep evaluates. A default method rather than a
     * {@code @SqlResultSetMapping} so the column-to-component mapping is read by name, in one place, and by a caller
     * that can be mocked.
     */
    default List<PqcStaleVerdictRow> staleVerdictRows(int version, UUID after, int limit) {
        return findStaleVerdictRows(version, after, limit).stream().map(PqcStaleVerdictRow::fromWorkListRow).toList();
    }

    /**
     * The same projection as {@link #findStaleVerdictRows}, for a caller that already knows which rows it wants: the
     * ingest, which has just merged a batch's sources and stamps their verdicts before leaving them to the sweep.
     *
     * <p>
     * <b>Native, and that is the point.</b> Read through {@code findById} these rows come from the first-level cache
     * whenever one persistence context spans more than one of the ingest's batch transactions -- which is what
     * {@code spring.jpa.open-in-view} produces on the REST {@code sync} path, since {@code JpaTransactionManager}
     * reuses the request-bound {@code EntityManager} and a commit does not evict. An asset two batches of one document
     * both touch would then be evaluated on the payload the first batch saw, and the mis-stamp is permanent: the stamp
     * sets {@code pqc_evaluated_at} and {@code i_upd} to one {@code CURRENT_TIMESTAMP}, so
     * {@link #findStaleVerdictRows}' {@code pqc_evaluated_at < i_upd} never re-offers the row.
     *
     * <p>
     * Ordered by {@code uuid}, which the caller depends on: the verdict writes take {@code crypto_asset} row locks, and
     * the sweep's own batch takes them in this order. Two writers ordering an overlapping row set differently is a
     * deadlock.
     */
    @Query(value = """
            SELECT uuid,
                   asset_type,
                   name,
                   oid,
                   algorithm_family,
                   primitive,
                   parameter_set,
                   array_to_string(curve, '+') AS curve,
                   mode,
                   padding,
                   variant,
                   merged_crypto_properties::text AS merged_crypto_properties,
                   xmin::text::bigint AS row_version
            FROM {h-schema}crypto_asset
            WHERE uuid IN :uuids
            ORDER BY uuid
            """, nativeQuery = true)
    List<Tuple> findVerdictRowsByUuids(@Param("uuids") Collection<UUID> uuids);

    /**
     * {@link #findVerdictRowsByUuids} mapped onto the record the evaluator reads, as {@link #staleVerdictRows} does.
     */
    default List<PqcStaleVerdictRow> verdictRowsByUuids(Collection<UUID> uuids) {
        return uuids.isEmpty()
                ? List.of()
                : findVerdictRowsByUuids(uuids).stream().map(PqcStaleVerdictRow::fromWorkListRow).toList();
    }

    /**
     * {@link #applyPqcVerdict} guarded against the sweep's read-to-write window, so a verdict computed from columns
     * that have since moved is refused rather than stamped current.
     *
     * <p>
     * The guard is {@code xmin}, the transaction that wrote the row's current version, and not {@code i_upd}.
     * {@code i_upd} is {@code CURRENT_TIMESTAMP}, which is {@code transaction_timestamp()}: microsecond resolution,
     * non-monotonic, and <em>identical</em> for two backends whose transactions begin together -- measured at 2.0 % of
     * barrier-synchronised pairs. Comparing it is a value check, not a version check, and a payload landing from such a
     * transaction would pass. No two transactions share an xid. A tuple frozen between the read and this write reads
     * {@code xmin} as 2, which can only refuse a write the next sweep retries, never admit a stale one.
     *
     * <p>
     * The staleness clause restates {@link #findStaleVerdictRows}'s definition of the work list, and has to: a row
     * offered because its payload moved is already at the current generation, so a version-only clause would refuse
     * every write the widened work list asks for.
     *
     * @return 1 if the row was written, 0 if it was written by someone else since it was read, or is no longer stale
     */
    @Modifying
    @Query(value = """
            UPDATE {h-schema}crypto_asset
            SET pqc_verdict = :verdict,
                pqc_rule_id = :ruleId,
                pqc_reason = :reason,
                pqc_ruleset_version = :rulesetVersion,
                pqc_evaluated_fields = CAST(:evaluatedFields AS jsonb),
                pqc_evaluated_at = CURRENT_TIMESTAMP,
                pqc_decided_at = CASE
                    WHEN crypto_asset.pqc_verdict IS DISTINCT FROM CAST(:verdict AS TEXT) THEN CURRENT_TIMESTAMP
                    ELSE COALESCE(crypto_asset.pqc_decided_at, CURRENT_TIMESTAMP)
                END,
                i_upd = CURRENT_TIMESTAMP
            WHERE uuid = :uuid
              AND (pqc_ruleset_version IS NULL
                    OR pqc_ruleset_version < :rulesetVersion
                    OR pqc_evaluated_at < i_upd)
              AND xmin::text::bigint = :rowVersion
            """, nativeQuery = true)
    int applyPqcVerdictIfStale(@Param("uuid") UUID uuid, @Param("rowVersion") long rowVersion,
            @Param("verdict") String verdict, @Param("ruleId") String ruleId, @Param("reason") String reason,
            @Param("rulesetVersion") int rulesetVersion, @Param("evaluatedFields") String evaluatedFields);

    @Modifying
    @Query("DELETE FROM CryptoAsset a WHERE a.uuid = :uuid")
    int deleteAsset(@Param("uuid") UUID uuid);

    /**
     * Distinct stored values of one normalized filter column, for the searchable-fields value lists. The columns hold
     * the stored normalized spelling (case/whitespace/Unicode-folded), so the lists collapse casing variants of one
     * token. Class-level canonicalization -- folding P-256 and secp256r1 into one secg/* representative -- is the
     * ingest pipeline's obligation (core#2072): these lists offer exactly what that pipeline stores, one entry per
     * stored spelling, and become the ratified class representatives the moment it writes them.
     *
     * <p>
     * Native recursive CTEs -- a loose index scan. Postgres has no btree skip scan, so {@code SELECT DISTINCT} walks
     * the whole table (a parallel seq scan pinning workers): hundreds of milliseconds per column at millions of rows,
     * for eight columns on every filter-panel open. The CTE instead hops index-min to index-min over the per-column
     * btrees the migration already ships -- O(distinct values x log rows), reliably milliseconds. {@code min()} ignores
     * NULLs, and the strictly-greater walk makes the values distinct and sorted by construction.
     *
     * <p>
     * That budget no longer holds for the panel as a whole. {@code getSearchableFieldInformationByGroup} calls all
     * eight of these in one request, and {@link #findDistinctCurve()} is a full unnest scan -- the array's elements are
     * the distinct values and no index orders them. So the seven skip scans still avoid seven scans, but the request's
     * latency is the curve scan, and the property this loose index scan was written to buy the endpoint is not one the
     * endpoint has while curve is in it. Restoring it and making the curve list proportional to the number of distinct
     * curves are the same work: an expression index a skip scan can walk, a side table of members, or a cached value
     * list. Recorded as open work on core#2166, which touches the same list. core#2073 is what first puts rows in the
     * table, so the figure is measurable from the first ingest rather than estimated.
     */
    @Query(value = """
            WITH RECURSIVE vals AS (
                SELECT min(algorithm_family) AS v FROM {h-schema}crypto_asset
                UNION ALL
                SELECT (SELECT min(algorithm_family) FROM {h-schema}crypto_asset WHERE algorithm_family > vals.v)
                FROM vals WHERE vals.v IS NOT NULL
            )
            SELECT v FROM vals WHERE v IS NOT NULL ORDER BY v
            """, nativeQuery = true)
    List<String> findDistinctAlgorithmFamily();

    @Query(value = """
            WITH RECURSIVE vals AS (
                SELECT min(primitive) AS v FROM {h-schema}crypto_asset
                UNION ALL
                SELECT (SELECT min(primitive) FROM {h-schema}crypto_asset WHERE primitive > vals.v)
                FROM vals WHERE vals.v IS NOT NULL
            )
            SELECT v FROM vals WHERE v IS NOT NULL ORDER BY v
            """, nativeQuery = true)
    List<String> findDistinctPrimitive();

    @Query(value = """
            WITH RECURSIVE vals AS (
                SELECT min(parameter_set) AS v FROM {h-schema}crypto_asset
                UNION ALL
                SELECT (SELECT min(parameter_set) FROM {h-schema}crypto_asset WHERE parameter_set > vals.v)
                FROM vals WHERE vals.v IS NOT NULL
            )
            SELECT v FROM vals WHERE v IS NOT NULL ORDER BY v
            """, nativeQuery = true)
    List<String> findDistinctParameterSet();

    /**
     * Every curve any asset touches, once each -- not every combination once.
     *
     * <p>
     * The sibling finders skip along a btree with a recursive loose index scan. That cannot work here: the distinct
     * values are the array's elements, and no index orders them. The unnest is a sequential scan, which is what the
     * value list for a membership filter costs -- and, because the filter panel asks for all eight lists in one
     * request, what that whole request now costs. See {@link #findDistinctAlgorithmFamily()} for the budget this spends
     * and what would restore it.
     */
    @Query(value = """
            SELECT DISTINCT member FROM {h-schema}crypto_asset a, unnest(a.curve) AS member
            WHERE member IS NOT NULL ORDER BY member
            """, nativeQuery = true)
    List<String> findDistinctCurve();

    @Query(value = """
            WITH RECURSIVE vals AS (
                SELECT min(mode) AS v FROM {h-schema}crypto_asset
                UNION ALL
                SELECT (SELECT min(mode) FROM {h-schema}crypto_asset WHERE mode > vals.v)
                FROM vals WHERE vals.v IS NOT NULL
            )
            SELECT v FROM vals WHERE v IS NOT NULL ORDER BY v
            """, nativeQuery = true)
    List<String> findDistinctMode();

    @Query(value = """
            WITH RECURSIVE vals AS (
                SELECT min(padding) AS v FROM {h-schema}crypto_asset
                UNION ALL
                SELECT (SELECT min(padding) FROM {h-schema}crypto_asset WHERE padding > vals.v)
                FROM vals WHERE vals.v IS NOT NULL
            )
            SELECT v FROM vals WHERE v IS NOT NULL ORDER BY v
            """, nativeQuery = true)
    List<String> findDistinctPadding();

    @Query(value = """
            WITH RECURSIVE vals AS (
                SELECT min(variant) AS v FROM {h-schema}crypto_asset
                UNION ALL
                SELECT (SELECT min(variant) FROM {h-schema}crypto_asset WHERE variant > vals.v)
                FROM vals WHERE vals.v IS NOT NULL
            )
            SELECT v FROM vals WHERE v IS NOT NULL ORDER BY v
            """, nativeQuery = true)
    List<String> findDistinctVariant();

    /**
     * List-page rows for the given assets. A projection rather than the entity: the list serves none of the JSONB
     * payload columns, and a page can be 1000 rows. The occurrence total is summed over the per-source rows, whose
     * count is deliberately uncapped (capping drops evidence payloads, never the count). Rows come back in no
     * particular order -- IN provides none -- so the caller restores its page order.
     */
    @Query("""
            SELECT new com.otilm.core.model.cbom.CryptoAssetListRow(a.uuid, a.name, a.oid, a.assetType,
                    a.pqcVerdict, a.sourceCount, a.identityGuard, COALESCE(SUM(s.occurrenceCount), 0L))
            FROM CryptoAsset a
            LEFT JOIN CryptoAssetSource s ON s.assetUuid = a.uuid
            WHERE a.uuid IN :uuids
            GROUP BY a.uuid, a.name, a.oid, a.assetType, a.pqcVerdict, a.sourceCount, a.identityGuard
            """)
    List<CryptoAssetListRow> findListRowsByUuids(@Param("uuids") Collection<UUID> uuids);
}
