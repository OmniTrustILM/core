package com.otilm.core.cbom.asset.identity;

/**
 * The CycloneDX names the identity pipeline reads: the canonical asset types, and the component fields several tiers of
 * the chain reach into.
 *
 * <p>
 * Named in one place because these strings are a <em>schema contract</em>, not incidental text. A field read under a
 * misspelled name does not fail -- it reads absent, and an absent field silently changes the key an asset gets, which
 * is the one defect class this pipeline cannot detect after the fact. Only names shared across classes, or repeated
 * within one, live here; a name read exactly once stays at its single site.
 */
final class CbomNames {

    static final String ASSET_TYPE_ALGORITHM = "algorithm";

    static final String ASSET_TYPE_CERTIFICATE = "certificate";

    static final String ASSET_TYPE_PROTOCOL = "protocol";

    static final String ASSET_TYPE_RELATED_CRYPTO_MATERIAL = "related-crypto-material";

    static final String CERTIFICATE_PROPERTIES = "certificateProperties";

    static final String RELATED_CRYPTO_MATERIAL_PROPERTIES = "relatedCryptoMaterialProperties";

    static final String ISSUER_NAME = "issuerName";

    static final String SUBJECT_NAME = "subjectName";

    static final String CONTENT = "content";

    static final String VALUE = "value";

    static final String LOCATION = "location";

    static final String PARAMETER_SET_IDENTIFIER = "parameterSetIdentifier";

    static final String ELLIPTIC_CURVE = "ellipticCurve";

    private CbomNames() {
    }
}
