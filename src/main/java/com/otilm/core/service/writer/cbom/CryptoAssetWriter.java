package com.otilm.core.service.writer.cbom;

import com.otilm.api.exception.ValidationError;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.cbom.asset.CompositeCurve;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.asset.JsonColumnText;
import com.otilm.core.cbom.asset.identity.IdentityRuleset;
import com.otilm.core.cbom.pqc.PqcDecision;
import com.otilm.core.cluster.ClusterOperationSynchronizer;
import com.otilm.core.dao.CryptoAssetConstraintTranslator;
import com.otilm.core.dao.repository.cbom.CryptoAssetAliasRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

/**
 * Short transactional writes against {@code crypto_asset}. The repository carries no {@code @Transactional}; every
 * {@code @Modifying} write goes through this bean, and every method is {@code REQUIRED} so it joins the ingest
 * transaction it belongs to or opens its own.
 */
@Service
public class CryptoAssetWriter {

    private static final Pattern IDENTITY_KEY = Pattern.compile("[0-9a-f]{64}");

    private final CryptoAssetRepository assetRepository;
    private final CryptoAssetAliasRepository aliasRepository;
    private final ClusterOperationSynchronizer clusterOperationSynchronizer;
    private final AttributeEngine attributeEngine;

    public CryptoAssetWriter(CryptoAssetRepository assetRepository, CryptoAssetAliasRepository aliasRepository,
            ClusterOperationSynchronizer clusterOperationSynchronizer, AttributeEngine attributeEngine) {
        this.assetRepository = assetRepository;
        this.aliasRepository = aliasRepository;
        this.clusterOperationSynchronizer = clusterOperationSynchronizer;
        this.attributeEngine = attributeEngine;
    }

    /**
     * Inserts or refreshes the asset row under the identity the caller computed, stamping the rule-set generation that
     * produced it.
     *
     * <p>
     * <b>The key is the caller's, and that is a downgrade this method used to avoid.</b> It was computed here, which
     * made "a row cannot be stored under a key that does not describe it" a structural impossibility. It is now a
     * property the extraction pipeline is <em>tested</em> to have, which is strictly weaker. The reason for the trade
     * is that the ratified key cannot be computed from these fields: a certificate keys on a content digest from
     * {@code component.hashes[]}, on a composite that resolves {@code subjectPublicKeyRef} across the whole document,
     * or on document-scoped digest refutation -- none of which is reconstructible from ten typed columns. What carries
     * the weight instead is the byte-level conformance suite that arrives with the decision tables in core#2168,
     * pinning the ratified vectors across every chain step.
     *
     * <p>
     * Callers that must redirect an ingested asset onto another row -- the alias repair path -- resolve the alias and
     * address the surviving asset by uuid instead; they never re-key it, because rewriting the canonical row's identity
     * columns with the absorbed row's fields would change what the canonical row claims to be.
     *
     * <p>
     * The columns store {@link CryptoAssetIdentityFields#normalized()}, not the caller's raw input. An asset row is a
     * deduplicated view over every producer that reported it, so it has no single raw spelling to hold; the producers'
     * own spellings live per source. Storing the raw input made the row a function of sync order, and normalizing it
     * was only half the fix: the upsert still reassigned every identity column on conflict, so two producers whose
     * normalized fields genuinely differ -- {@code primitive} above all, which is deliberately out of the key -- still
     * let the last one to sync decide what an {@code EQUALS} filter matched. The statement now fills a column once and
     * never reassigns it, so re-sync is idempotent in the columns as well as in the key.
     *
     * <p>
     * The length bound is checked before the alias lookup on purpose: a write that is already doomed must not take
     * {@code ALIAS_DECISION_LOCK} on its way to failing. It is measured on the <em>stored</em> text, because that is
     * what the column receives and therefore what its {@code CHECK} will judge.
     *
     * @param identityKey the ratified identity, computed by the extraction pipeline from the whole component
     * @return the uuid of the surviving row, which is the inserted uuid only when the insert won
     * @throws ValidationException if an identity column exceeds its length bound, or if a guard is being stamped on a
     * key an alias already refers to
     */
    @Transactional
    public UUID upsertIdentity(String identityKey, CryptoAssetIdentityFields fields, CryptoAssetIdentityGuard guard) {
        return upsertIdentityWithOutcome(identityKey, fields, guard).uuid();
    }

    public record UpsertOutcome(UUID uuid, boolean inserted) {
    }

    /** Whether the caller's insert won the identity-key arbiter, without a racing pre-insert read. */
    @Transactional
    public UpsertOutcome upsertIdentityWithOutcome(String identityKey, CryptoAssetIdentityFields fields,
            CryptoAssetIdentityGuard guard) {
        CryptoAssetIdentityFields stored = fields.normalized();
        requireIdentityKeyShape(identityKey);
        requireWithinLengthBounds(stored);
        if (guard != null) {
            requireNoAlias(identityKey, guard);
        }
        UUID proposedUuid = UUID.randomUUID();
        assetRepository
                .upsertIdentity(proposedUuid, identityKey, IdentityRuleset.VERSION,
                        stored.assetType() == null ? null : stored.assetType().name(), stored.name(), stored.oid(),
                        stored.algorithmFamily(), stored.primitive(), stored.parameterSet(), curveMembers(stored),
                        stored.mode(), stored.padding(), stored.variant(), guard == null ? null : guard.name());
        UUID storedUuid = assetRepository
                .findUuidByIdentityKey(identityKey)
                // Deliberately says nothing about the key: this text can reach an operator.
                .orElseThrow(() -> new IllegalStateException(
                        "The cryptographic asset row disappeared between its upsert and its lookup"));
        return new UpsertOutcome(storedUuid, proposedUuid.equals(storedUuid));
    }

    /**
     * Re-derives the asset's merged payload, provenance pointer and source count from the sources it currently has.
     * Call it in the same transaction as any change to those sources, so the two can never be observed apart.
     */
    @Transactional
    public void recomputeMerge(UUID assetUuid) {
        assetRepository.recomputeMergeFromSources(assetUuid);
    }

    /**
     * Stores a PQC verdict with the rule that produced it and the fields the rule read. The identity columns and the
     * identity rule-set version are untouched: a verdict is not an identity.
     *
     * @param reason operator-facing text, which the caller must have shaped itself
     */
    @Transactional
    public void applyPqcVerdict(UUID assetUuid, PqcVerdict verdict, String ruleId, String reason,
            Map<String, Object> evaluatedFields) {
        assetRepository
                .applyPqcVerdict(assetUuid, verdict == null ? null : verdict.name(), ruleId, reason,
                        JsonColumnText.render(evaluatedFields), null, null);
    }

    /**
     * Stores a decision together with what a certificate's or protocol's references read, so the sweep can tell when a
     * target has moved since.
     *
     * @param referenceBasis {@code PqcReferences#basis()} as read, or null
     */
    @Transactional
    public void applyPqcVerdict(UUID assetUuid, PqcDecision decision, String referenceBasis) {
        assetRepository
                .applyPqcVerdict(assetUuid, decision.verdict().name(), decision.ruleId(), decision.reason(),
                        JsonColumnText.render(decision.evaluatedFields()), decision.referencedAssetUuid(),
                        referenceBasis);
    }

    /**
     * The bounds the migration declares on the two identity columns a producer can realistically make long. Held here
     * as well so the refusal happens before the statement runs; {@code CryptoAssetWriterTest} pins them against the
     * migration, so a bound that moves in one place fails rather than diverging.
     */
    static final int MAX_OID_LENGTH = 255;

    static final int MAX_NAME_LENGTH = 1024;

    static void requireIdentityKeyShape(String identityKey) {
        if (identityKey == null || !IDENTITY_KEY.matcher(identityKey).matches()) {
            throw new ValidationException(ValidationError.create("Cryptographic asset identity key has invalid shape"));
        }
    }

    /**
     * Refuses an over-long identity column before it can reach the statement.
     *
     * <p>
     * The CHECK constraints remain, and remain the authority; this only keeps the database from being the thing that
     * says no. PostgreSQL reports a failed CHECK with a {@code DETAIL: Failing row contains (...)} line carrying every
     * column of the offending row, and Hibernate's {@code SqlExceptionHelper} logs the driver's message at ERROR the
     * moment the statement fails -- upstream of every catch, so no translation or handler downstream can prevent it.
     * That row contains {@code identity_key}, which is 64 hex characters, exactly at the driver's per-value truncation
     * point, so it prints whole. Letting a length bound be enforced by the constraint therefore turns an over-long name
     * -- something a producer controls -- into a way to make the platform log an identity key. Enforced here, the
     * constraint is a backstop that a correct pipeline never reaches.
     *
     * <p>
     * Counted in code points, because PostgreSQL's {@code length()} counts characters. {@link String#length} counts
     * UTF-16 units, which would refuse a name of 513 astral characters that the constraint accepts -- and a pre-check
     * stricter than its constraint rejects valid rows, while one looser than its constraint leaves the channel open for
     * exactly the inputs it was added to stop.
     */
    /** The column holds the members; the caller carries the joined spelling, which is what the preimage hashes. */
    private static String[] curveMembers(CryptoAssetIdentityFields stored) {
        List<String> members = CompositeCurve.split(stored.curve());
        return members == null ? null : members.toArray(new String[0]);
    }

    private static void requireWithinLengthBounds(CryptoAssetIdentityFields stored) {
        rejectIfLonger(stored.oid(), MAX_OID_LENGTH, "ck_crypto_asset_oid_length");
        rejectIfLonger(stored.name(), MAX_NAME_LENGTH, "ck_crypto_asset_name_length");
    }

    /**
     * @param constraintName the constraint this check anticipates, which supplies the operator-facing sentence so the
     * pre-check and the backstop cannot say different things
     */
    static void rejectIfLonger(String value, int limit, String constraintName) {
        if (value != null && value.codePointCount(0, value.length()) > limit) {
            throw new ValidationException(
                    ValidationError.create(CryptoAssetConstraintTranslator.explain(constraintName)));
        }
    }

    /**
     * Refuses a guard on a key some alias already refers to.
     *
     * <p>
     * A guard and an alias are contradictory statements about one key: the alias says this key <em>is</em> another one,
     * the guard says a safety rule requires it to stand alone. {@link CryptoAssetAliasWriter#record} already refuses
     * the alias when the guard came first; this is the same rule read from the other end, so whichever decision arrives
     * second is the one that fails, and the operator who made it is told what it contradicts rather than silently
     * overwriting or being silently overwritten.
     *
     * <p>
     * Both sides are checked. An alias that <em>absorbed</em> the key means the row is expected to disappear into
     * another; an alias that points at it as <em>canonical</em> means other rows are expected to merge into it. A guard
     * contradicts both. The lock is {@link CryptoAssetAliasWriter#ALIAS_DECISION_LOCK}, so this check and a concurrent
     * alias decision cannot each read a table the other is about to change.
     *
     * <p>
     * It is taken before this method writes anything, which keeps this path inside the ranked lock order -- the
     * advisory lock above every {@code crypto_asset} row lock. A caller that has already taken an asset row lock in the
     * same transaction, by upserting a source, inverts that order and can deadlock against a concurrent transaction
     * doing the reverse; {@link CryptoAssetSourceWriter} states the obligation that avoids it.
     */
    private void requireNoAlias(String key, CryptoAssetIdentityGuard guard) {
        clusterOperationSynchronizer.lock(CryptoAssetAliasWriter.ALIAS_DECISION_LOCK);
        if (aliasRepository.findByAbsorbedKey(key).isPresent()) {
            throw new ValidationException(ValidationError
                    .create("The {} safety rule would keep this cryptographic asset separate, but an alias already "
                            + "merges it into another asset. Withdraw that alias first, or leave the asset merged.",
                            guard.name()));
        }
        if (aliasRepository.existsByCanonicalKey(key)) {
            throw new ValidationException(ValidationError
                    .create("The {} safety rule would keep this cryptographic asset separate, but another asset is "
                            + "already merged into it by an alias. Withdraw that alias first, or leave the assets "
                            + "merged.", guard.name()));
        }
    }

    /**
     * Deletes an asset. Its source rows and aliases go with it by cascade, and its custom attribute content is purged.
     * The CBOM rows referenced by those sources remain.
     *
     * @return 1 if a row was deleted, 0 if it was already gone
     */
    @Transactional
    public int delete(UUID assetUuid) {
        int deleted = assetRepository.deleteAsset(assetUuid);
        if (deleted == 1) {
            attributeEngine.deleteObjectAttributeContent(Resource.CRYPTO_ASSET, assetUuid);
        }
        return deleted;
    }
}
