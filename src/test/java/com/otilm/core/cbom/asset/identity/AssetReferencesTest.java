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

    /** A key names the algorithm it is for: the 1.7 typed entry first, the 1.6 field only when the array names none. */
    @Test
    void aKeyNamesTheAlgorithmItIsFor() {
        assertThat(AssetReferences.of(material("\"algorithmRef\":\"alg\"")))
                .containsExactly(new AssetReferences.Reference(CryptoAssetReferenceKind.ALGORITHM, "alg", null));
        assertThat(AssetReferences
                .of(material("\"algorithmRef\":\"legacy\",\"relatedCryptographicAssets\":[{\"type\":\"algorithm\","
                        + "\"ref\":\"typed\"},{\"type\":\"publicKey\",\"ref\":\"other\"}]")))
                .extracting(AssetReferences.Reference::ref)
                .containsExactly("typed");
        assertThat(AssetReferences
                .of(material("\"relatedCryptographicAssets\":[{\"type\":\"algorithm\",\"ref\":\"one\"},"
                        + "{\"type\":\"Algorithm\",\"ref\":\"two\"}]")))
                .extracting(AssetReferences.Reference::ref)
                .describedAs("two of a kind are both kept, for the ingest to resolve to nothing")
                .containsExactly("one", "two");
        assertThat(AssetReferences.of(material("\"type\":\"secret-key\",\"size\":256"))).isEmpty();
    }

    /** At the protocol level the 1.7 typed algorithm entries count, else every entry of the 1.6 array. */
    @Test
    void aProtocolNamesItsProtocolLevelAlgorithmsAndItsKeyExchangeMethods() {
        JsonNode typed = component("{\"assetType\":\"protocol\",\"protocolProperties\":{\"type\":\"tls\","
                + "\"relatedCryptographicAssets\":[{\"type\":\"algorithm\",\"ref\":\"kex\"},"
                + "{\"type\":\"certificate\",\"ref\":\"cert\"},{\"type\":\"algorithm\",\"ref\":\"kex\"}],"
                + "\"cryptoRefArray\":[\"legacy\"]}}");
        assertThat(AssetReferences.of(typed))
                .containsExactly(
                        new AssetReferences.Reference(CryptoAssetReferenceKind.PROTOCOL_ALGORITHM, "kex", null));

        JsonNode legacy = component("{\"assetType\":\"protocol\",\"protocolProperties\":{\"type\":\"tls\","
                + "\"relatedCryptographicAssets\":[{\"type\":\"certificate\",\"ref\":\"cert\"}],"
                + "\"cryptoRefArray\":[\"a\",\"b\",\"a\"]}}");
        assertThat(AssetReferences.of(legacy))
                .extracting(AssetReferences.Reference::kind, AssetReferences.Reference::ref)
                .containsExactly(tuple(CryptoAssetReferenceKind.PROTOCOL_ALGORITHM, "a"),
                        tuple(CryptoAssetReferenceKind.PROTOCOL_ALGORITHM, "b"));

        JsonNode ike = component("{\"assetType\":\"protocol\",\"protocolProperties\":{\"type\":\"ikev2\","
                + "\"ikev2TransformTypes\":{\"encr\":[\"aes\"],\"ke\":[{\"group\":35,\"algorithm\":\"mlkem\"},"
                + "{\"group\":14},\"dh14\"]}}}");
        assertThat(AssetReferences.of(ike))
                .extracting(AssetReferences.Reference::kind, AssetReferences.Reference::ref)
                .containsExactly(tuple(CryptoAssetReferenceKind.KEY_EXCHANGE_TRANSFORM, "mlkem"),
                        tuple(CryptoAssetReferenceKind.KEY_EXCHANGE_TRANSFORM, "dh14"));
    }

    @Test
    void theNamesTheSuitesOfferAreReadOnceEachInDocumentOrder() {
        JsonNode protocol = component("{\"assetType\":\"protocol\",\"protocolProperties\":{\"cipherSuites\":["
                + "{\"name\":\"A\",\"tlsGroups\":[\"x25519\",\"secp256r1\"],\"tlsSignatureSchemes\":[\"ed25519\"]},"
                + "{\"name\":\"B\",\"tlsGroups\":[\"secp256r1\",\" \",\"X25519MLKEM768\"]},{\"name\":\"C\"}]}}");
        JsonNode properties = protocol.get("cryptoProperties").get("protocolProperties");

        assertThat(AssetReferences.offeredNames(properties, "tlsGroups"))
                .containsExactly("x25519", "secp256r1", "X25519MLKEM768");
        assertThat(AssetReferences.offeredNames(properties, "tlsSignatureSchemes")).containsExactly("ed25519");
        assertThat(AssetReferences.offeredNames(null, "tlsGroups")).isEmpty();
    }

    private static JsonNode material(String members) {
        return component(
                "{\"assetType\":\"related-crypto-material\",\"relatedCryptoMaterialProperties\":{" + members + "}}");
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
