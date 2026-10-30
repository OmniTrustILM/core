package com.otilm.core.model.cbom;

/**
 * The safety rule that forced a cryptographic asset to remain its own row, where a looser reading of the producer's
 * data would have merged it into another.
 *
 * <p>
 * Recorded on the row because the alias repair path has to refuse an alias "where a safety rule caused the split", and
 * that is undecidable unless the row says which rule fired. Deriving it at refusal time from the unindexed merged
 * payload would make a safety check depend on parsing a document whose shape the producer controls.
 *
 * <ul>
 * <li>{@link #REFUTED_CERTIFICATE_DIGEST} -- a certificate whose supplied digest contradicted its other properties, so
 * the digest was not used to key it. Merging it with a digest-keyed row would assert an identity the evidence
 * refuted.</li>
 * <li>{@link #BARE_CN_SUBJECT} -- a certificate identified only by common name, facing rows identified by a full
 * subject DN. Two certificates can share a common name.</li>
 * <li>{@link #REFUTED_OID} -- an OID whose registry meaning contradicted the component's other properties, so what the
 * OID would have contributed -- a family, a size, a mode, a curve -- was discarded. An arc that is wrong about the
 * family is no reason to trust its size. The arc itself stays stored and auditable on every row, but the inventory
 * search neutralizes it by default: a refuted OID answers value predicates (and the free-text OID side) only after the
 * caller opts into the refuted facet, while its presence -- EMPTY/NOT_EMPTY -- stays a true fact
 * (FilterPredicatesBuilder's carve-outs).</li>
 * </ul>
 *
 * <p>
 * The guard records a <em>consequence</em>, never the mechanism that produced it. An earlier draft of this enum said
 * {@code REFUTED_OID} meant the OID "was not used to key it", which describes no pipeline: the ratified identity rules
 * keep the OID out of every tuple unconditionally, so under them that sentence is true of every row and distinguishes
 * nothing, and the guard would carry no information. Stating the consequence also keeps the row shape core#2074 needs
 * available -- {@code identity_guard = 'REFUTED_OID'} together with a populated {@code oid} -- which the mechanism
 * reading forbids.
 *
 * <p>
 * No path in this ticket stamps {@code REFUTED_OID}; the normalization pipeline that derives it lands in core#2072.
 *
 * <p>
 * Core-local; to be reconciled with the vocabulary ratified in core#2070. The constant names are the persisted values.
 */
public enum CryptoAssetIdentityGuard {
    REFUTED_CERTIFICATE_DIGEST,
    BARE_CN_SUBJECT,
    REFUTED_OID
}
