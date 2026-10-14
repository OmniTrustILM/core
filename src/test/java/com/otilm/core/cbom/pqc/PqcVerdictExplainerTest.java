package com.otilm.core.cbom.pqc;

import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.cryptoasset.PqcExplanationStepOutcome;
import com.otilm.api.model.core.cryptoasset.PqcVerdict;
import com.otilm.core.cbom.asset.identity.AssetNormalizer;
import com.otilm.core.cbom.asset.identity.IdentityTables;
import com.otilm.core.dao.repository.cbom.CryptoAssetReferenceRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.model.cbom.PqcStaleVerdictRow;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.springframework.dao.QueryTimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class PqcVerdictExplainerTest {

    private static final UUID ASSET = UUID.fromString("00000000-0000-4000-8000-0000000023a1");

    private final CryptoAssetRepository repository = mock(CryptoAssetRepository.class);

    private final CryptoAssetReferenceRepository references = mock(CryptoAssetReferenceRepository.class);

    private final PqcVerdictExplainer explainer = new PqcVerdictExplainer(repository,
            new PqcEvaluator(new AssetNormalizer(IdentityTables.load())), new PqcReferenceReader(references));

    /** The sweep stamps such a row EVALUATION-FAILED; the explanation says the same, as one failed step. */
    @Test
    void anAssetTheRulesCannotEvaluateIsExplainedByOneFailedStep() {
        when(repository.verdictRowsByUuids(List.of(ASSET)))
                .thenReturn(List
                        .of(new PqcStaleVerdictRow(ASSET, CryptographicAssetType.ALGORITHM, "aes", null, null, null,
                                null, null, null, null, null, "{not json", 1L)));

        PqcVerdictExplainer.Result result = explainer.explain(ASSET).orElseThrow();

        assertThat(result.inputs()).isEmpty();
        assertThat(result.explanation().decision().ruleId()).isEqualTo(PqcRules.EVALUATION_FAILED);
        assertThat(result.explanation().steps()).singleElement().satisfies(step -> {
            assertThat(step.outcome()).isEqualTo(PqcExplanationStepOutcome.FAILED);
            assertThat(step.verdict()).isEqualTo(PqcVerdict.UNKNOWN);
            assertThat(step.message()).isEqualTo(PqcRules.EVALUATION_FAILED_REASON);
        });
    }

    /** Only what the rules cannot evaluate is answered as a failed step; a database failure is the caller's error. */
    @Test
    void aDatabaseFailureWhileReadingReferencesIsNotAnEvaluationFailure() {
        when(repository.verdictRowsByUuids(List.of(ASSET)))
                .thenReturn(List
                        .of(new PqcStaleVerdictRow(ASSET, CryptographicAssetType.CERTIFICATE, "example.com", null, null,
                                null, null, null, null, null, null, "{}", 1L)));
        when(references.findElectedReferences(List.of(ASSET)))
                .thenThrow(new QueryTimeoutException("statement timeout"));

        assertThatThrownBy(() -> explainer.explain(ASSET)).isInstanceOf(QueryTimeoutException.class);
    }

    /** No rule serves the tier any more, so a row that predates its removal is answered like one that is gone. */
    @Test
    void aRowOnTheUnroutableTierHasNoExplanation() {
        when(repository.verdictRowsByUuids(List.of(ASSET)))
                .thenReturn(List
                        .of(new PqcStaleVerdictRow(ASSET, CryptographicAssetType.UNROUTABLE, "unclassified", null, null,
                                null, null, null, null, null, null, null, 1L)));

        assertThat(explainer.explain(ASSET)).isEmpty();
    }

    @Test
    void aRowThatIsGoneHasNoExplanation() {
        when(repository.verdictRowsByUuids(List.of(ASSET))).thenReturn(List.of());

        assertThat(explainer.explain(ASSET)).isEmpty();
    }
}
