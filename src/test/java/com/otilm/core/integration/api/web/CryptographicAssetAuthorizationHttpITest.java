package com.otilm.core.integration.api.web;

import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.AssetRowKeys;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * {@code @ExternalAuthorization} over HTTP for the cryptographic asset inventory's list, searchable-fields, detail and
 * statistics endpoints, mirroring {@link ExternalAuthorizationHttpITest}'s style: the real security filter chain, the
 * method-security advisor, and {@code ExceptionHandlingAdvice.handleAccessDeniedException}. Detail additionally pins
 * the not-found path (a 404, not a leak) and the wire shape of its own core#2145 contract.
 *
 * <p>
 * The permitted-path assertions also carry the wire-level identity-key criterion: none of the four endpoints' raw
 * responses ever mentions it.
 */
@AutoConfigureMockMvc
class CryptographicAssetAuthorizationHttpITest extends BaseSpringBootTest {

    private static final String LIST_ENDPOINT = "/v1/cryptoAssets";

    private static final String SEARCHABLE_FIELDS_ENDPOINT = "/v1/cryptoAssets/search";

    private static final String DETAIL_ENDPOINT = "/v1/cryptoAssets/";

    private static final String STATISTICS_ENDPOINT = "/v1/statistics/cryptoAssets";

    // The same detection rule IdentityKeyExposureFence uses, applied to the live wire response. A bare "identity"
    // substring is not it: CBOM_ASSET_RULESET_VERSION's own label is "Identity Rule Set Version" -- "identity" as an
    // ordinary adjective, naming the ruleset that computes identity, not the guarded value itself.
    private static final Pattern IDENTITY_KEY = Pattern
            .compile("identity[_\\-\\s]?key|absorbed[_\\-\\s]?key|canonical[_\\-\\s]?key", Pattern.CASE_INSENSITIVE);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CryptoAssetWriter assetWriter;

    @Autowired
    private CryptoAssetSourceWriter sourceWriter;

    @Autowired
    private CbomRepository cbomRepository;

    private CryptoAssetIdentityFields seededFields;

    private UUID seededUuid;

    @BeforeEach
    void seedAsset() {
        seededFields = new CryptoAssetIdentityFields(CryptographicAssetType.ALGORITHM, "ECDSA", "1.2.840.10045.4.3.2",
                "ecdsa", "signature", "P-256", "secp256r1", null, null, null);
        seededUuid = assetWriter.upsertIdentity(AssetRowKeys.forFields(seededFields), seededFields, null);
    }

    @Test
    void deniesBothOperationsWhenTheListActionIsDenied() throws Exception {
        denyResourceAccess(Resource.CRYPTO_ASSET, ResourceAction.LIST);

        mockMvc
                .perform(post(LIST_ENDPOINT).contentType("application/json").content("{}"))
                .andExpectAll(status().isForbidden(), jsonPath("$.code").value("ACCESS_DENIED"));
        // Both operations share the LIST action.
        mockMvc.perform(get(SEARCHABLE_FIELDS_ENDPOINT)).andExpect(status().isForbidden());
    }

    @Test
    void servesBothOperationsWithoutMentioningTheIdentityKeyWhenPermitted() throws Exception {
        // The positive control: the seeded row must actually reach the response, or a filter/security regression
        // that empties the page would satisfy every doesNotContain assertion below vacuously.
        String listResponse = mockMvc
                .perform(post(LIST_ENDPOINT).contentType("application/json").content("{}"))
                .andExpectAll(status().isOk(), jsonPath("$.totalItems").value(1),
                        jsonPath("$.items[0].name").value("ecdsa"))
                .andReturn()
                .getResponse()
                .getContentAsString();
        assertThat(listResponse).doesNotContainPattern(IDENTITY_KEY);

        String searchableFieldsResponse = mockMvc
                .perform(get(SEARCHABLE_FIELDS_ENDPOINT))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        assertThat(searchableFieldsResponse).doesNotContainPattern(IDENTITY_KEY);

        // The name pattern catches field names; a wire leak would realistically be the VALUE. The calculator can
        // recompute this row's exact key from the same fixture input, so assert the strongest possible fact: the
        // literal key appears in neither raw response.
        assertThat(listResponse).doesNotContain(theSeededKeyLiteral());
        assertThat(searchableFieldsResponse).doesNotContain(theSeededKeyLiteral());
    }

    @Test
    void refusesInvalidPagingWithAShapedUnprocessableEntity() throws Exception {
        mockMvc
                .perform(post(LIST_ENDPOINT).contentType("application/json").content("{\"pageNumber\":0}"))
                .andExpect(status().isUnprocessableEntity());
    }

    /**
     * The source-CBOM value list crosses a resource gate -- CBOM serial numbers belong to the CBOM resource -- so it is
     * scoped by the caller's own {@code cboms:list} access rather than served platform-wide: a caller holding only
     * {@code cryptoAssets:list} still gets the searchable fields, but that one value list comes back empty.
     */
    @Test
    void scopesTheSourceCbomValueListByTheCallersCbomAccess() throws Exception {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber("urn:uuid:scoped");
        cbom.setVersion(1);
        cbom.setSpecVersion("1.7");
        cbomRepository.save(cbom);

        String permitted = mockMvc
                .perform(get(SEARCHABLE_FIELDS_ENDPOINT))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        assertThat(permitted).contains("urn:uuid:scoped");

        denyObjectAccess(Resource.CBOM, ResourceAction.LIST);
        String scoped = mockMvc
                .perform(get(SEARCHABLE_FIELDS_ENDPOINT))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        assertThat(scoped).doesNotContain("urn:uuid:scoped");
        assertThat(scoped)
                .describedAs("the fields themselves still serve; only the cross-resource value list is scoped")
                .contains("CBOM_ASSET_SOURCE_CBOM");
    }

    @Test
    void deniesDetailWhenTheDetailActionIsDenied() throws Exception {
        UUID assetUuid = seedOneAsset();
        denyResourceAccess(Resource.CRYPTO_ASSET, ResourceAction.DETAIL);

        mockMvc
                .perform(get(DETAIL_ENDPOINT + assetUuid))
                .andExpectAll(status().isForbidden(), jsonPath("$.code").value("ACCESS_DENIED"));
    }

    @Test
    void deniesStatisticsWhenTheListActionIsDenied() throws Exception {
        denyResourceAccess(Resource.CRYPTO_ASSET, ResourceAction.LIST);

        mockMvc
                .perform(get(STATISTICS_ENDPOINT))
                .andExpectAll(status().isForbidden(), jsonPath("$.code").value("ACCESS_DENIED"));
    }

    @Test
    void detailNotFoundIsA404NotALeak() throws Exception {
        String body = mockMvc
                .perform(get(DETAIL_ENDPOINT + UUID.randomUUID()))
                .andExpect(status().isNotFound())
                .andReturn()
                .getResponse()
                .getContentAsString();

        assertThat(body).doesNotContainPattern(IDENTITY_KEY);
    }

    /**
     * The permitted-path identity-key criterion, extended to detail and statistics. Seeding a source payload, capped
     * evidence and an evaluated verdict puts every map-typed channel either response carries -- the elected payload,
     * the per-source original, the verdict's evaluated fields, and the statistics group-by maps -- onto the wire, so
     * the two assertions below (the vocabulary regex and the literal recomputed key) are checking something real rather
     * than passing vacuously over a near-empty response.
     */
    @Test
    void neitherDetailNorStatisticsResponseCarriesTheIdentityKey() throws Exception {
        UUID assetUuid = seedAssetWithSourcesPayloadsAndVerdict();

        String detailBody = mockMvc
                .perform(get(DETAIL_ENDPOINT + assetUuid))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        String statisticsBody = mockMvc
                .perform(get(STATISTICS_ENDPOINT))
                .andExpect(status().isOk())
                .andReturn()
                .getResponse()
                .getContentAsString();
        // same two assertions the list test makes: the vocabulary regex AND the literal recomputed key value
        assertThat(detailBody).doesNotContainPattern(IDENTITY_KEY).doesNotContain(theSeededKeyLiteral());
        assertThat(statisticsBody).doesNotContainPattern(IDENTITY_KEY).doesNotContain(theSeededKeyLiteral());
    }

    /**
     * The JSON property names on detail are the contract, not just the Java getters -- this pins {@code
     * electedPayload}, a per-source {@code payload} and {@code serialNumber}, a per-OID {@code refuted} flag and
     * {@code verdict.ruleId} on the wire. The same row is read before and after it earns a verdict, so the negative
     * half of the contract is pinned too: {@code NON_NULL} omits the {@code verdict} field entirely rather than serving
     * it as {@code null}.
     */
    @Test
    void servesDetailWireShapeAndOmitsVerdictUntilEvaluated() throws Exception {
        UUID assetUuid = seedOneAsset();

        mockMvc
                .perform(get(DETAIL_ENDPOINT + assetUuid))
                .andExpectAll(status().isOk(), jsonPath("$.verdict").doesNotExist());

        seedAssetWithSourcesPayloadsAndVerdict();

        mockMvc
                .perform(get(DETAIL_ENDPOINT + assetUuid))
                .andExpectAll(status().isOk(), jsonPath("$.electedPayload").exists(),
                        jsonPath("$.sources[0].payload").exists(), jsonPath("$.sources[0].serialNumber").exists(),
                        jsonPath("$.oids[0].refuted").exists(), jsonPath("$.verdict.ruleId").exists());
    }

    private UUID seedOneAsset() {
        return seededUuid;
    }

    /**
     * Extends the row {@link #seedAsset()} already created with a source (a payload map and capped evidence) and an
     * evaluated verdict (whose own {@code evaluatedFields} is a map too), reusing the same {@link #seededFields} so
     * {@link #theSeededKeyLiteral()} still names the row under test.
     */
    private UUID seedAssetWithSourcesPayloadsAndVerdict() {
        Cbom cbom = newCbom("urn:uuid:fence-source");
        Map<String, Object> payload = Map.of("name", "ecdsa", "curve", "P-256");
        sourceWriter
                .upsertSource(seededUuid, cbom.getUuid(), payload,
                        List.of(Map.of("location", "src/fence.c", "line", 1)), OffsetDateTime.now());
        assetWriter
                .applyPqcVerdict(seededUuid, PqcVerdict.NOT_READY, "fence-rule", "fence reason", 1,
                        Map.of("checked", "field"));
        return seededUuid;
    }

    /** The seeded row's exact identity key, recomputed the same way {@link CryptoAssetWriter} would have. */
    private String theSeededKeyLiteral() {
        return AssetRowKeys.forFields(seededFields);
    }

    private Cbom newCbom(String serialNumber) {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(1);
        cbom.setSpecVersion("1.7");
        return cbomRepository.save(cbom);
    }
}
