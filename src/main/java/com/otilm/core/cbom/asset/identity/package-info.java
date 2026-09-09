/**
 * The ratified cryptographic-asset identity chain: one CycloneDX component in, one identity key out.
 *
 * <p>
 * The classes here look like a grab bag of utilities and are not one. They are four layers of a single pipeline, and
 * the reason each exists is that its JDK or platform equivalent would have made a stored key unstable.
 *
 * <ul>
 * <li><b>Byte determinism.</b> {@link com.otilm.core.cbom.asset.identity.AsciiText},
 * {@link com.otilm.core.cbom.asset.identity.IdentityDigests}, {@link com.otilm.core.cbom.asset.identity.PreImageSlot},
 * {@link com.otilm.core.cbom.asset.identity.ValidityTimestamps} and
 * {@link com.otilm.core.cbom.asset.identity.CanonicalJson}. Each deliberately diverges from the obvious JDK call: an
 * ASCII-only fold because Unicode case tables change between versions, a digest that refuses unpaired surrogates
 * because the encoder would silently fold them onto one byte sequence, slot escaping so a value cannot forge a
 * delimiter, epoch folding so two spellings of one instant agree.</li>
 * <li><b>Field reducers.</b> {@link com.otilm.core.cbom.asset.identity.CbomNames},
 * {@link com.otilm.core.cbom.asset.identity.ComponentNames},
 * {@link com.otilm.core.cbom.asset.identity.CertificateDigests},
 * {@link com.otilm.core.cbom.asset.identity.CipherSuites}, {@link com.otilm.core.cbom.asset.identity.Occurrences},
 * {@link com.otilm.core.cbom.asset.identity.MaterialValueDigest} and
 * {@link com.otilm.core.cbom.asset.identity.MaterialRedaction}. Each reduces one producer-controlled field to a keyable
 * token. Redaction is here rather than in a security package because its digest is an input to the material tier, not
 * only a control.</li>
 * <li><b>Table-driven normalization.</b> {@link com.otilm.core.cbom.asset.identity.IdentityTables},
 * {@link com.otilm.core.cbom.asset.identity.AssetNormalizer},
 * {@link com.otilm.core.cbom.asset.identity.NormalizedAsset} and
 * {@link com.otilm.core.cbom.asset.identity.DistinguishedNames} — the half driven by the ratified decision tables.</li>
 * <li><b>Orchestration.</b> {@link com.otilm.core.cbom.asset.identity.CryptoAssetIdentity} routes by asset type,
 * {@link com.otilm.core.cbom.asset.identity.DocumentScope} carries the whole-document derivations a single component
 * cannot see, and {@link com.otilm.core.cbom.asset.identity.CbomAssetExtractor} walks the tree.</li>
 * </ul>
 *
 * <p>
 * <b>Do not reuse these as general utilities.</b> Their divergences are the point, and a caller who wants ordinary text
 * handling wants {@code StringUtils} or {@code CertificateUtil} instead. Reaching for {@code AsciiText.strip} because
 * it is nearby gives non-JDK whitespace semantics to code that did not ask for them.
 *
 * <p>
 * The package stays flat on purpose. Splitting it by layer would force
 * {@link com.otilm.core.cbom.asset.identity.CbomNames} and the digest-claim helpers to widen from package-private, and
 * that encapsulation is what keeps the pipeline's vocabulary out of reach of the rest of the platform.
 */
package com.otilm.core.cbom.asset.identity;
