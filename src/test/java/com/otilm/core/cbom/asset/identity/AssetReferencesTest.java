package com.otilm.core.cbom.asset.identity;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.core.model.cbom.CryptoAssetReferenceKind;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.tuple;

class AssetReferencesTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Test
    void aCertificateNamesItsKeyAndSignatureAlgorithmByTheDeprecatedFields() {
        assertThat(AssetReferences.of(certificate("\"subjectPublicKeyRef\":\"k\",\"signatureAlgorithmRef\":\"s\"")))
                .extracting(AssetReferences.Reference::kind, AssetReferences.Reference::ref)
                .containsExactly(tuple(CryptoAssetReferenceKind.SUBJECT_PUBLIC_KEY, "k"),
                        tuple(CryptoAssetReferenceKind.SIGNATURE_ALGORITHM, "s"));
    }

    /**
     * One kind at a time: the 1.7 key entry replaces the 1.6 key field, and leaves the 1.6 signature field standing.
     */
    @Test
    void aRelatedEntryReplacesTheDeprecatedFieldOfItsOwnKind() {
        assertThat(AssetReferences
                .of(certificate("\"subjectPublicKeyRef\":\"old\",\"signatureAlgorithmRef\":\"s\","
                        + "\"relatedCryptographicAssets\":[{\"type\":\"PublicKey\",\"ref\":\"new\"}]")))
                .extracting(AssetReferences.Reference::kind, AssetReferences.Reference::ref)
                .containsExactly(tuple(CryptoAssetReferenceKind.SUBJECT_PUBLIC_KEY, "new"),
                        tuple(CryptoAssetReferenceKind.SIGNATURE_ALGORITHM, "s"));
        assertThat(AssetReferences
                .of(certificate(
                        "\"relatedCryptographicAssets\":[{\"type\":\"signature-algorithm\",\"ref\":\"sig\"},{\"type\":\"algorithm\",\"ref\":\"x\"}]")))
                .extracting(AssetReferences.Reference::kind, AssetReferences.Reference::ref)
                .containsExactly(tuple(CryptoAssetReferenceKind.SIGNATURE_ALGORITHM, "sig"));
    }

    /**
     * Counted the way the certificate tier's key slot counts: a typed entry states the kind whatever its ref looks
     * like, so the deprecated field is not consulted, and two entries stay ambiguous even when one ref is unusable.
     */
    @Test
    void everyTypedEntryCountsWhateverItsRefLooksLike() {
        assertThat(AssetReferences
                .of(certificate(
                        "\"relatedCryptographicAssets\":[{\"type\":\"publicKey\",\"ref\":\"k1\"},{\"type\":\"publicKey\",\"ref\":\"\"}]")))
                .extracting(AssetReferences.Reference::ref)
                .containsExactly("k1", AssetReferences.UNUSABLE_REF);
        assertThat(AssetReferences
                .of(certificate(
                        "\"subjectPublicKeyRef\":\"legacy\",\"relatedCryptographicAssets\":[{\"type\":\"publicKey\"}]")))
                .describedAs("the array stated the key, so the legacy field does not stand in for it")
                .isEmpty();
    }

    @Test
    void aProtocolNamesEachDistinctSuiteAlgorithmOnceUnderTheFirstSuiteThatNamesIt() {
        JsonNode protocol = component("{\"assetType\":\"protocol\",\"protocolProperties\":{\"cipherSuites\":["
                + "{\"identifiers\":[\"0x13\",\"0x01\"],\"algorithms\":[\"aes\",\"sha\"]},"
                + "{\"name\":\"LEGACY\",\"algorithms\":[\"sha\",\"rsa\"]},{\"algorithms\":[\"des\"]},{\"name\":\"EMPTY\"}]}}");

        assertThat(AssetReferences.of(protocol))
                .extracting(AssetReferences.Reference::ref, AssetReferences.Reference::suite)
                .containsExactly(tuple("aes", "0x1301"), tuple("sha", "0x1301"), tuple("rsa", "LEGACY"),
                        tuple("des", "#3"));
    }

    @Test
    void aReferenceThatCannotBeStoredIsDroppedAndAnAlgorithmMakesNone() {
        assertThat(AssetReferences
                .of(certificate("\"subjectPublicKeyRef\":\"bad\\uD800\",\"signatureAlgorithmRef\":\" \""))).isEmpty();
        assertThat(AssetReferences.of(component("{\"assetType\":\"algorithm\",\"algorithmProperties\":{}}"))).isEmpty();
    }

    private static JsonNode certificate(String members) {
        return component("{\"assetType\":\"certificate\",\"certificateProperties\":{" + members + "}}");
    }

    private static JsonNode component(String cryptoProperties) {
        try {
            return MAPPER.readTree("{\"type\":\"cryptographic-asset\",\"cryptoProperties\":" + cryptoProperties + "}");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
