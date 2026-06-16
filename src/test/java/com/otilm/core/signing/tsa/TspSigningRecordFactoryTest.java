package com.otilm.core.signing.tsa;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.core.util.builders.SigningProfileModelBuilder;
import com.otilm.core.signing.record.SigningRecordInput;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;

import java.math.BigInteger;
import java.time.Instant;
import java.util.Map;

import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static com.otilm.core.model.signing.SigningRecordPolicyModelBuilder.aSigningRecordPolicy;
import static com.otilm.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Pure unit test for {@link TspSigningRecordFactory}: the assembly of a {@link SigningRecordInput} from a
 * signing profile, TSP request, and the already-encoded granted timestamp token. Uses a real
 * {@link ObjectMapper} (fast and deterministic); the token DER-encoding now happens upstream in the engine,
 * so the factory takes the encoded bytes directly and no token mocking is needed.
 */
class TspSigningRecordFactoryTest {

    private static final BigInteger SERIAL = BigInteger.ONE;
    private static final Instant GEN_TIME = Instant.parse("2026-06-16T00:00:00Z");
    private static final byte[] ENCODED_TOKEN = {10, 20, 30};

    private ObjectMapper objectMapper;
    private TspSigningRecordFactory factory;

    @BeforeEach
    void setUp() {
        objectMapper = new ObjectMapper();
        factory = new TspSigningRecordFactory(objectMapper);
    }

    @Test
    void build_populatesMetadataJson_whenRecordRequestMetadataOn() throws Exception {
        // given
        var profileName = "test-profile";
        var profileVersion = 7;
        var serialNumber = BigInteger.valueOf(255);   // hex "ff"
        var policyOid = "1.2.3.4.5";
        var nonce = BigInteger.valueOf(255);           // decimal "255" — distinct from the hex serial
        var hashAlgorithm = DigestAlgorithm.SHA_256;
        var profile = aRecordingProfile().withName(profileName).withVersion(profileVersion).build();
        var request = aTspRequest().hashAlgorithm(hashAlgorithm).policy(policyOid).nonce(nonce).build();

        // when
        SigningRecordInput input = factory.build(profile, request, serialNumber, GEN_TIME, ENCODED_TOKEN);

        // then
        Map<String, Object> metadata = parseMetadata(input.getRequestMetadataJson());
        assertEquals(profileName, metadata.get("signingProfileName"));
        assertEquals(profileVersion, metadata.get("signingProfileVersion"));
        assertEquals("ff", metadata.get("serialNumber"));
        assertEquals(hashAlgorithm.name(), metadata.get("hashAlgorithm"));
        assertEquals(policyOid, metadata.get("policy"));
        assertEquals("255", metadata.get("nonce"));
    }

    @Test
    void build_metadataHashAlgorithmNull_whenHashAlgorithmNull() throws Exception {
        // given a request whose hash algorithm is absent, with policy and nonce present to isolate this branch
        var request = aTspRequest().hashAlgorithm(null).policy("1.2.3").nonce(BigInteger.TEN).build();

        // when
        SigningRecordInput input = factory.build(aRecordingProfile().build(), request, SERIAL, GEN_TIME, ENCODED_TOKEN);

        // then
        assertNull(parseMetadata(input.getRequestMetadataJson()).get("hashAlgorithm"));
    }

    @Test
    void build_metadataPolicyNull_whenPolicyEmpty() throws Exception {
        // given a request with no policy, with hash algorithm and nonce present to isolate this branch
        var request = aTspRequest().hashAlgorithm(DigestAlgorithm.SHA_256).nonce(BigInteger.TEN).build();

        // when
        SigningRecordInput input = factory.build(aRecordingProfile().build(), request, SERIAL, GEN_TIME, ENCODED_TOKEN);

        // then
        assertNull(parseMetadata(input.getRequestMetadataJson()).get("policy"));
    }

    @Test
    void build_metadataNonceNull_whenNonceEmpty() throws Exception {
        // given a request with no nonce, with hash algorithm and policy present to isolate this branch
        var request = aTspRequest().hashAlgorithm(DigestAlgorithm.SHA_256).policy("1.2.3").build();

        // when
        SigningRecordInput input = factory.build(aRecordingProfile().build(), request, SERIAL, GEN_TIME, ENCODED_TOKEN);

        // then
        assertNull(parseMetadata(input.getRequestMetadataJson()).get("nonce"));
    }

    @Test
    void build_buildsDisplayName_asNameWithHexSerial() {
        // given
        var profileName = "my-tsa-profile";
        var serialNumber = BigInteger.valueOf(255);   // hex "ff"
        var profile = aSigningProfile().withName(profileName).build();

        // when
        SigningRecordInput input = factory.build(profile, aTspRequest().build(), serialNumber, GEN_TIME, ENCODED_TOKEN);

        // then
        assertEquals(profileName + " #ff", input.getDisplayName());
    }

    @Test
    void build_setsSignedDocument_fromEncodedToken() {
        // given the engine has already DER-encoded the token; the factory must store those bytes verbatim
        var encodedToken = new byte[]{1, 2, 3, 4};

        // when
        SigningRecordInput input = factory.build(aSigningProfile().build(), aTspRequest().build(), SERIAL, GEN_TIME, encodedToken);

        // then
        assertArrayEquals(encodedToken, input.getSignedDocument());
    }

    @Test
    void build_leavesSignatureDtbsAndRequestedByNull() {
        // given the TSP path stores only the self-contained token, leaving the other content slots empty

        // when
        SigningRecordInput input = factory.build(aSigningProfile().build(), aTspRequest().build(), SERIAL, GEN_TIME, ENCODED_TOKEN);

        // then
        assertNull(input.getSignature());
        assertNull(input.getDtbs());
    }

    @Test
    void build_wrapsJsonProcessingException_asIllegalState() throws Exception {
        // given a mapper that fails to serialize the request metadata
        ObjectMapper failingMapper = mock(ObjectMapper.class);
        when(failingMapper.writeValueAsString(any())).thenThrow(mock(JsonProcessingException.class));
        var factoryWithFailingMapper = new TspSigningRecordFactory(failingMapper);

        // when
        Executable build = () -> factoryWithFailingMapper.build(
                aRecordingProfile().build(), aTspRequest().build(), SERIAL, GEN_TIME, ENCODED_TOKEN);

        // then
        assertThrows(IllegalStateException.class, build);
    }

    private static SigningProfileModelBuilder aRecordingProfile() {
        return aSigningProfile().withRecordPolicy(aSigningRecordPolicy().recordRequestMetadata(true).build());
    }

    private Map<String, Object> parseMetadata(String json) throws JsonProcessingException {
        return objectMapper.readValue(json, new TypeReference<>() {});
    }
}
