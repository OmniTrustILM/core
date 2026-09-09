package com.otilm.core.integration.cbom;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.CryptoAssetIdentity;
import com.otilm.core.cbom.asset.identity.NormalizedAsset;
import com.otilm.core.cbom.pqc.PqcDecision;
import com.otilm.core.cbom.pqc.PqcEvaluator;
import com.otilm.core.cbom.pqc.PqcRules;
import com.otilm.core.cbom.pqc.PqcRuleset;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Stream;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A row written by the shipped writers and read back from PostgreSQL still carries the columns and the elected payload
 * ingest gave it, and the verdict recorded on it is the one the rule set owes those stored inputs.
 *
 * <p>
 * Not a parity test. There is one input shape, so evaluating the read-back row and comparing with the verdict that same
 * evaluation recorded is one function on both sides; what that comparison catches is a column or payload that did not
 * survive storage. The hardcoded rule ids and evidence values in each test are the oracle that a derivation which drops
 * a column cannot satisfy -- both sides would agree on {@code FAMILY-UNRESOLVED} and the comparison alone would not see
 * it.
 */
class PqcStoredRowRoundTripITest extends BaseSpringBootTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final TypeReference<Map<String, Object>> PAYLOAD = new TypeReference<>() {
    };

    @Autowired
    private CryptoAssetRepository assetRepository;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CryptoAssetWriter assetWriter;

    @Autowired
    private CryptoAssetSourceWriter sourceWriter;

    @Autowired
    private AssetNormalizer normalizer;

    @Autowired
    private PqcEvaluator evaluator;

    private CryptoAssetIdentity identity;
    private Cbom firstCbom;
    private Cbom secondCbom;

    @BeforeEach
    void seed() {
        identity = new CryptoAssetIdentity(normalizer);
        firstCbom = cbom("urn:uuid:first");
        secondCbom = cbom("urn:uuid:second");
    }

    static Stream<Arguments> singleProducerVectors() {
        return Stream
                .of(Arguments.of(algorithm("RSA-2048"), "CLASSICAL-SHOR"),
                        Arguments.of(algorithm("X25519-ML-KEM-768"), "PQC-HYBRID-PQC-STANDARDIZED"),
                        Arguments.of(algorithm("X25519-ML-KEM-７６８"), "PQC-HYBRID-PQC-STANDARDIZED"),
                        Arguments.of(algorithm("AES-256-GCM"), "SYMMETRIC-READY"),
                        Arguments.of(algorithm("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"), "NAME-CIPHER-SUITE"),
                        Arguments
                                .of(material("vault-key-2024", "\"id\":\"vault-key-2024\",\"size\":256"),
                                        "MATERIAL-SYMMETRIC-READY"));
    }

    /**
     * With one producer the row is exactly the derivation's columns, folded -- the premise the unit suite's in-memory
     * stored-row fixture rests on, pinned here against the real writer.
     */
    @ParameterizedTest
    @MethodSource("singleProducerVectors")
    void aRowWrittenByOneProducerKeepsItsColumnsAndItsVerdict(JsonNode component, String expectedRuleId) {
        CryptoAsset row = asset(ingest(component, firstCbom));

        PqcDecision fromStoredRow = decide(row);

        assertThat(row.getPqcRuleId())
                .describedAs("ingest must have decided what the rule set owes this asset")
                .isEqualTo(expectedRuleId);
        assertThat(storedFields(row)).isEqualTo(derivedFields(identity.of(component).asset()).normalized());
        assertRecordedVerdictIsWhatTheStoredRowDecides(fromStoredRow, row);
    }

    /**
     * The key path collapses internal whitespace runs where the column's fold does not, so the two spellings share one
     * row; {@code COALESCE} then keeps the first, which is what makes re-sync idempotent. The second producer's verdict
     * is read off that stored spelling, not off the one it sent.
     */
    @Test
    void twoSpellingsOfOneNameDecideFromTheStoredSpelling() {
        UUID first = ingest(algorithm("private key"), firstCbom);
        UUID second = ingest(algorithm("private  key"), secondCbom);
        assertThat(second).describedAs("the two spellings key alike").isEqualTo(first);

        CryptoAsset row = asset(second);

        assertThat(row.getName()).isEqualTo("private key");
        assertThat(row.getPqcRuleId()).isEqualTo("NAME-NOT-AN-ALGORITHM");
        assertThat(row.getPqcVerdict()).isEqualTo(PqcVerdict.NOT_APPLICABLE);
        assertThat(row.getPqcEvaluatedFields()).containsEntry(PqcRules.NAME, "private key");
        assertRecordedVerdictIsWhatTheStoredRowDecides(decide(row), row);
    }

    /**
     * {@code size} is outside the material identity tuple, so producers disagreeing about it share one row, and the
     * merge elects the richest payload. The verdict is read off the elected payload, whichever producer sent it.
     */
    @Test
    void producersDisagreeingAboutASizeDecideFromTheElectedPayload() {
        UUID rich = ingest(material("vault-key-2024",
                "\"id\":\"vault-key-2024\",\"size\":64,\"state\":\"active\",\"format\":\"raw\""), firstCbom);
        UUID thin = ingest(material("vault-key-2024", "\"id\":\"vault-key-2024\",\"size\":256"), secondCbom);
        assertThat(thin).describedAs("size is not part of the material identity").isEqualTo(rich);

        CryptoAsset row = asset(thin);

        assertThat(row.getSourceCount()).isEqualTo(2);
        assertThat(elected(row).get("size").intValue()).isEqualTo(64);
        assertThat(row.getPqcRuleId())
                .describedAs("64 is inside the ratified size band")
                .isEqualTo("MATERIAL-SYMMETRIC-WEAK");
        assertThat(row.getPqcVerdict()).isEqualTo(PqcVerdict.NOT_READY);
        assertThat(row.getPqcEvaluatedFields()).containsEntry(PqcRules.MATERIAL_SIZE, 64);
        assertRecordedVerdictIsWhatTheStoredRowDecides(decide(row), row);
    }

    // ---- the two sides ----

    /** Key the component, upsert identity and source, then evaluate the row that came back and record the verdict. */
    private UUID ingest(JsonNode component, Cbom cbom) {
        CryptoAssetIdentity.Identity keyed = identity.of(component);
        JsonNode payload = keyed.redaction().storedPayload();

        UUID assetUuid = assetWriter.upsertIdentity(keyed.key(), derivedFields(keyed.asset()), keyed.guard());
        sourceWriter
                .upsertSource(assetUuid, cbom.getUuid(), MAPPER.convertValue(payload, PAYLOAD), List.of(),
                        OffsetDateTime.now());

        PqcDecision decision = decide(asset(assetUuid));
        assetWriter
                .applyPqcVerdict(assetUuid, decision.verdict(), decision.ruleId(), decision.reason(),
                        PqcRuleset.VERSION, decision.evaluatedFields());
        return assetUuid;
    }

    /** Nothing but the columns and the elected payload that came back from the database. */
    private PqcDecision decide(CryptoAsset row) {
        JsonNode merged = row.getMergedCryptoProperties() == null
                ? null
                : MAPPER.valueToTree(row.getMergedCryptoProperties());
        return evaluator
                .evaluate(evaluator.fromStoredRow(storedFields(row), merged),
                        PqcEvaluator.nistQuantumSecurityLevel(merged));
    }

    /** The stored columns and payload still decide what was recorded from them; a lost column would move one side. */
    private void assertRecordedVerdictIsWhatTheStoredRowDecides(PqcDecision fromStoredRow, CryptoAsset row) {
        assertThat(fromStoredRow.ruleId()).isEqualTo(row.getPqcRuleId());
        assertThat(fromStoredRow.verdict()).isEqualTo(row.getPqcVerdict());
        JsonNode decidedEvidence = MAPPER.valueToTree(fromStoredRow.evaluatedFields());
        JsonNode recordedEvidence = MAPPER.valueToTree(row.getPqcEvaluatedFields());
        assertThat(decidedEvidence).isEqualTo(recordedEvidence);
    }

    private static CryptoAssetIdentityFields storedFields(CryptoAsset row) {
        return new CryptoAssetIdentityFields(row.getAssetType(), row.getName(), row.getOid(), row.getAlgorithmFamily(),
                row.getPrimitive(), row.getParameterSet(), row.getCurve(), row.getMode(), row.getPadding(),
                row.getVariant());
    }

    private static CryptoAssetIdentityFields derivedFields(NormalizedAsset asset) {
        return CryptoAssetIdentityFields.of(PqcEvaluator.assetTypeOf(asset.assetType()), asset);
    }

    private static JsonNode elected(CryptoAsset row) {
        return MAPPER.valueToTree(row.getMergedCryptoProperties()).get("relatedCryptoMaterialProperties");
    }

    // ---- fixtures ----

    private CryptoAsset asset(UUID uuid) {
        return assetRepository.findById(uuid).orElseThrow();
    }

    private Cbom cbom(String serialNumber) {
        Cbom cbom = new Cbom();
        cbom.setSerialNumber(serialNumber);
        cbom.setVersion(1);
        cbom.setSpecVersion("1.7");
        return cbomRepository.save(cbom);
    }

    private static JsonNode algorithm(String name) {
        return component(name, "{\"assetType\":\"algorithm\",\"algorithmProperties\":{}}");
    }

    private static JsonNode material(String name, String materialMembers) {
        return component(name, "{\"assetType\":\"related-crypto-material\",\"relatedCryptoMaterialProperties\":{"
                + "\"type\":\"secret-key\"," + materialMembers + "}}");
    }

    private static JsonNode component(String name, String cryptoProperties) {
        try {
            return MAPPER
                    .readTree("{\"type\":\"cryptographic-asset\",\"name\":\"" + name + "\",\"cryptoProperties\":"
                            + cryptoProperties + "}");
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
