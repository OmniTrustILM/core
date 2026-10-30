package com.otilm.core.service.writer.cbom;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.cbom.CryptoAssetAliasRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import java.time.OffsetDateTime;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short transactional writes against {@code crypto_asset_alias} -- the repair path for an accidental duplicate.
 *
 * <p>
 * An alias never reaches identity. The key is a function of ten typed columns, so recording, re-pointing or removing an
 * alias cannot change any row's key; it changes only which row a later ingest lands on. That is also why the repair is
 * exactly reversible: every source keeps its own payload, so removing the alias and re-ingesting re-splits the rows
 * from evidence that was never discarded.
 *
 * <p>
 * An alias is <b>refused</b> where a safety rule caused the split. A guarded row was kept separate on purpose -- a
 * refuted certificate digest, a bare common name facing a full subject DN, a refuted OID -- and merging it would assert
 * an identity the evidence refuted. Chains are refused too: an alias whose absorbed key is another alias's canonical
 * key, or whose canonical key is itself absorbed, has no single reversal.
 */
@Service
public class CryptoAssetAliasWriter {

    /**
     * The cluster-lock key every alias mutation serializes on. Held through {@link ClusterOperationSynchronizer}, which
     * owns the platform's advisory-lock keyspace: a bespoke literal here could not be checked against the keys declared
     * there, and one inside {@code hashtext}'s int32 codomain could silently collide with an unrelated
     * {@code lock(String)} caller -- serializing, or deadlock-aborting, a feature that shares no code with aliases.
     *
     * <p>
     * Published rather than private because {@link CryptoAssetWriter} takes the same lock before it stamps a guard --
     * guarding and aliasing are the two contradictory statements about one key, and a guard applied while an alias
     * decision is mid-flight would slip past both checks -- and because the ingest orchestrator has to take it up
     * front, before its first asset row lock, which it cannot do with a key it cannot name.
     *
     * <p>
     * <b>It outranks every row lock in this inventory.</b> A transaction that will take both this and a
     * {@code crypto_asset} row lock must take this one first -- see the lock-order note on
     * {@link CryptoAssetSourceWriter}. Both methods here obey that: the lock is taken before the first read.
     */
    public static final String ALIAS_DECISION_LOCK = "crypto-asset-alias-decisions";

    private final CryptoAssetAliasRepository aliasRepository;
    private final CryptoAssetRepository assetRepository;
    private final ClusterOperationSynchronizer clusterOperationSynchronizer;

    public CryptoAssetAliasWriter(CryptoAssetAliasRepository aliasRepository, CryptoAssetRepository assetRepository,
            ClusterOperationSynchronizer clusterOperationSynchronizer) {
        this.aliasRepository = aliasRepository;
        this.assetRepository = assetRepository;
        this.clusterOperationSynchronizer = clusterOperationSynchronizer;
    }

    /**
     * Records, or re-points, the decision that one asset key is really another.
     *
     * <p>
     * The chain and cycle rules are checked, not constrained: no single row is common to {@code A→B} and {@code B→C},
     * so no unique index can refuse the pair and there is nothing to lock pessimistically. Without serialization both
     * decisions read a chain-free table and both commit. The advisory lock is therefore taken <em>before</em> the first
     * read, so every check runs against a table no other alias mutation can be changing.
     *
     * @throws ValidationException if either side was split by a safety rule, if the canonical asset does not exist, if
     * the decision is self-referential, or if it would form a chain
     */
    @Transactional
    public void record(String absorbedKey, String canonicalKey, String reason, String decidedBy) {
        requireDistinct(absorbedKey, canonicalKey);
        clusterOperationSynchronizer.lock(ALIAS_DECISION_LOCK);
        requireUnguarded(canonicalKey, "canonical");
        requireUnguarded(absorbedKey, "absorbed");
        requireCanonicalExists(canonicalKey);
        requireNoChain(absorbedKey, canonicalKey);
        requireSomethingToDecide(absorbedKey);
        aliasRepository
                .upsertAlias(UUID.randomUUID(), absorbedKey, canonicalKey, reason, decidedBy, OffsetDateTime.now());
    }

    /**
     * Withdraws an alias. A later ingest of the absorbed asset creates its own row again, rebuilt from the per-source
     * payloads that were retained throughout.
     *
     * <p>
     * Takes the same lock as {@link #record}: a removal cannot form a chain on its own, but it changes the very table a
     * concurrent {@code record} is reading to decide whether one would form. Serializing both directions is what makes
     * "no chain exists" an invariant rather than a statement about the last thing that happened to commit.
     *
     * @return 1 if an alias was removed, 0 if there was none
     */
    @Transactional
    public int remove(String absorbedKey) {
        clusterOperationSynchronizer.lock(ALIAS_DECISION_LOCK);
        return aliasRepository.deleteByAbsorbedKey(absorbedKey);
    }

    private void requireDistinct(String absorbedKey, String canonicalKey) {
        if (absorbedKey == null || canonicalKey == null || absorbedKey.equals(canonicalKey)) {
            throw new ValidationException(
                    ValidationError.create("A cryptographic asset alias needs two distinct asset keys."));
        }
    }

    /**
     * A guarded row was deliberately kept separate, so it may be neither absorbed nor absorbed into. A row that is
     * absent carries no guard to check: an absorbed row is already gone when an alias is re-pointed, and the guard that
     * mattered was checked when the merge was first decided and the row was still there.
     */
    private void requireUnguarded(String identity, String side) {
        Optional<CryptoAsset> asset = assetRepository.findByIdentityKey(identity);
        if (asset.isPresent() && asset.get().getIdentityGuard() != null) {
            throw new ValidationException(ValidationError
                    .create("The {} cryptographic asset was kept separate by the {} safety rule, so it cannot be "
                            + "merged by an alias.", side, asset.get().getIdentityGuard().name()));
        }
    }

    /**
     * Refuses a decision whose canonical asset is not there.
     *
     * <p>
     * The database refuses it too -- {@code crypto_asset_alias_to_canonical_key} -- but only as a
     * {@code DataIntegrityViolationException} that nothing on this path translates, so it escapes as a 500 and the
     * generic handler prints the driver's {@code DETAIL}, which quotes the missing key. That key is an identity key,
     * and putting one in a log is the disclosure this whole fence exists to prevent. Refusing here means the operator
     * gets a sentence we wrote, and the driver never gets the chance to write one.
     *
     * <p>
     * Checked under the lock the caller already holds, so a canonical asset cannot be deleted between this read and the
     * insert by another alias decision. It can still be deleted by an asset delete, which is why the foreign key stays:
     * this check makes the common case a clean refusal, not a substitute for the constraint.
     */
    private void requireCanonicalExists(String canonicalKey) {
        if (assetRepository.findByIdentityKey(canonicalKey).isEmpty()) {
            throw new ValidationException(ValidationError
                    .create("There is no cryptographic asset to merge into; the canonical asset does not exist."));
        }
    }

    /**
     * Refuses a decision that would chain. Both directions matter: absorbing a key that another alias already treats as
     * canonical strands that alias behind two hops, and pointing at a key that is itself absorbed does the same on the
     * other side. Either way the repair stops having one reversal, which is the property that makes it safe.
     */
    private void requireNoChain(String absorbedKey, String canonicalKey) {
        if (aliasRepository.existsByCanonicalKey(absorbedKey)) {
            throw new ValidationException(ValidationError
                    .create("Another alias already points at the absorbed cryptographic asset; alias chains have no "
                            + "single reversal."));
        }
        if (aliasRepository.resolveCanonicalKey(canonicalKey).isPresent()) {
            throw new ValidationException(ValidationError
                    .create("The canonical cryptographic asset is itself absorbed by another alias; alias chains have "
                            + "no single reversal."));
        }
    }

    /**
     * Refuses a decision with nothing to decide about: neither an asset row to absorb nor an existing alias to
     * re-point. Without it a typo would record a redirect no ingest can ever follow.
     */
    private void requireSomethingToDecide(String absorbedKey) {
        if (aliasRepository.findByAbsorbedKey(absorbedKey).isEmpty()
                && assetRepository.findByIdentityKey(absorbedKey).isEmpty()) {
            throw new ValidationException(
                    ValidationError.create("There is no cryptographic asset to absorb, and no alias to re-point."));
        }
    }
}
