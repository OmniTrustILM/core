package com.otilm.core.integration.evaluator;

import com.otilm.api.exception.RuleException;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.cryptoasset.CryptographicAssetType;
import com.otilm.api.model.core.search.FilterConditionOperator;
import com.otilm.api.model.core.search.FilterFieldSource;
import com.otilm.core.cbom.asset.AssetRowKeys;
import com.otilm.core.cbom.asset.CryptoAssetIdentityFields;
import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.cbom.CryptoAsset;
import com.otilm.core.dao.entity.workflows.ConditionItem;
import com.otilm.core.dao.repository.CbomRepository;
import com.otilm.core.dao.repository.cbom.CryptoAssetRepository;
import com.otilm.core.enums.FilterField;
import com.otilm.core.evaluator.CryptoAssetTriggerEvaluator;
import com.otilm.core.model.cbom.CryptoAssetIdentityGuard;
import com.otilm.core.service.writer.cbom.CryptoAssetSourceWriter;
import com.otilm.core.service.writer.cbom.CryptoAssetWriter;
import com.otilm.core.util.BaseSpringBootTest;
import java.time.OffsetDateTime;
import java.util.List;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.springframework.beans.factory.annotation.Autowired;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CryptoAssetTriggerEvaluatorITest extends BaseSpringBootTest {

    @Autowired
    private CryptoAssetTriggerEvaluator evaluator;

    @Autowired
    private CryptoAssetRepository assetRepository;

    @Autowired
    private CbomRepository cbomRepository;

    @Autowired
    private CryptoAssetWriter assetWriter;

    @Autowired
    private CryptoAssetSourceWriter sourceWriter;

    private CryptoAsset asset;

    @BeforeEach
    void createAsset() {
        asset = asset("rsa%_\\suffix");
    }

    @Test
    void freeTextSearchTreatsSqlWildcardsAsLiteralText() throws Exception {
        ConditionItem search = condition(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS,
                "rsa%_\\suffix");

        assertThat(evaluator.evaluateConditionItem(search, asset, Resource.CRYPTO_ASSET)).isTrue();
        assertThat(evaluator.evaluateConditionItem(search, asset("rsaXYZsuffix"), Resource.CRYPTO_ASSET)).isFalse();
    }

    @Test
    void aNonMatchingFreeTextConditionRemainsFalse() throws Exception {
        assertThat(evaluator
                .evaluateConditionItem(
                        condition(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS, "unrelated"),
                        asset, Resource.CRYPTO_ASSET))
                .isFalse();
    }

    @Test
    void freeTextRejectsAnUnsupportedOperator() {
        assertThatThrownBy(() -> evaluator
                .evaluateConditionItem(
                        condition(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.EQUALS, "rsa"), asset,
                        Resource.CRYPTO_ASSET))
                .isInstanceOf(RuleException.class);
    }

    @Test
    void freeTextRejectsANonTextValue() {
        assertThatThrownBy(() -> evaluator
                .evaluateConditionItem(
                        condition(FilterField.CBOM_ASSET_FREE_TEXT, FilterConditionOperator.CONTAINS, List.of("rsa")),
                        asset, Resource.CRYPTO_ASSET))
                .isInstanceOf(RuleException.class);
    }

    @ParameterizedTest
    @CsvSource({
            "EQUALS, urn:uuid:one, true",
            "EQUALS, urn:uuid:missing, false",
            "NOT_EQUALS, urn:uuid:one, false",
            "NOT_EQUALS, urn:uuid:missing, true",
            "EMPTY, ignored, false",
            "NOT_EMPTY, ignored, true"})
    void sourceCbomConditionsReadAllContributingSerialNumbers(FilterConditionOperator operator, String value,
            boolean expected) throws Exception {
        addSources();

        assertThat(evaluator
                .evaluateConditionItem(condition(FilterField.CBOM_ASSET_SOURCE_CBOM, operator, value), asset,
                        Resource.CRYPTO_ASSET))
                .isEqualTo(expected);
    }

    @Test
    void sourceCbomAcceptsAnyMatchingValueInACollection() throws Exception {
        addSources();

        assertThat(evaluator
                .evaluateConditionItem(condition(FilterField.CBOM_ASSET_SOURCE_CBOM, FilterConditionOperator.EQUALS,
                        List.of("urn:uuid:missing", "urn:uuid:two")), asset, Resource.CRYPTO_ASSET))
                .isTrue();
    }

    @Test
    void aSourceLessAssetSatisfiesTheEmptyCondition() throws Exception {
        assertThat(evaluator
                .evaluateConditionItem(
                        condition(FilterField.CBOM_ASSET_SOURCE_CBOM, FilterConditionOperator.EMPTY, null), asset,
                        Resource.CRYPTO_ASSET))
                .isTrue();
        assertThat(evaluator
                .evaluateConditionItem(
                        condition(FilterField.CBOM_ASSET_SOURCE_CBOM, FilterConditionOperator.NOT_EMPTY, null), asset,
                        Resource.CRYPTO_ASSET))
                .isFalse();
    }

    @Test
    void sourceCbomRejectsAnUnsupportedOperator() {
        addSources();

        assertThatThrownBy(() -> evaluator
                .evaluateConditionItem(
                        condition(FilterField.CBOM_ASSET_SOURCE_CBOM, FilterConditionOperator.CONTAINS, "one"), asset,
                        Resource.CRYPTO_ASSET))
                .isInstanceOf(RuleException.class);
    }

    @Test
    void ordinaryAssetPropertiesUseTheInheritedEvaluator() throws Exception {
        assertThat(evaluator
                .evaluateConditionItem(
                        condition(FilterField.CBOM_ASSET_NAME, FilterConditionOperator.EQUALS, "rsa%_\\suffix"), asset,
                        Resource.CRYPTO_ASSET))
                .isTrue();
        assertThat(evaluator
                .evaluateConditionItem(
                        condition(FilterField.CBOM_ASSET_NAME, FilterConditionOperator.EQUALS, "unrelated"), asset,
                        Resource.CRYPTO_ASSET))
                .isFalse();
    }

    @ParameterizedTest
    @CsvSource({
            "REFUTED_OID, EQUALS, true, true",
            "REFUTED_OID, EQUALS, false, false",
            "REFUTED_OID, NOT_EQUALS, true, false",
            "REFUTED_OID, NOT_EQUALS, false, true",
            "BARE_CN_SUBJECT, EQUALS, true, false",
            "BARE_CN_SUBJECT, EQUALS, false, true",
            ", EQUALS, true, false",
            ", EQUALS, false, true",
            ", NOT_EQUALS, true, true",
            ", NOT_EQUALS, false, false"})
    void oidRefutedMatchesTheInventoryFilter(CryptoAssetIdentityGuard guard, FilterConditionOperator operator,
            boolean value, boolean expected) throws Exception {
        CryptoAsset guarded = asset("guarded", CryptographicAssetType.ALGORITHM, guard);

        assertThat(evaluator
                .evaluateConditionItem(condition(FilterField.CBOM_ASSET_OID_REFUTED, operator, value), guarded,
                        Resource.CRYPTO_ASSET))
                .isEqualTo(expected);
    }

    @Test
    void oidRefutedAcceptsATextBoolean() throws Exception {
        CryptoAsset refuted = asset("refuted", CryptographicAssetType.ALGORITHM, CryptoAssetIdentityGuard.REFUTED_OID);

        assertThat(evaluator
                .evaluateConditionItem(
                        condition(FilterField.CBOM_ASSET_OID_REFUTED, FilterConditionOperator.EQUALS, "TRUE"), refuted,
                        Resource.CRYPTO_ASSET))
                .isTrue();
    }

    @Test
    void oidRefutedRejectsOperatorsTheInventoryFilterRefuses() {
        assertThatThrownBy(() -> evaluator
                .evaluateConditionItem(
                        condition(FilterField.CBOM_ASSET_OID_REFUTED, FilterConditionOperator.NOT_EMPTY, null), asset,
                        Resource.CRYPTO_ASSET))
                .isInstanceOf(RuleException.class);
    }

    @Test
    void oidRefutedRejectsAValueThatIsNotASingleBoolean() {
        assertThatThrownBy(() -> evaluator
                .evaluateConditionItem(
                        condition(FilterField.CBOM_ASSET_OID_REFUTED, FilterConditionOperator.EQUALS, List.of(true)),
                        asset, Resource.CRYPTO_ASSET))
                .isInstanceOf(RuleException.class);
    }

    @ParameterizedTest
    @CsvSource({
            "UNROUTABLE, EMPTY, true",
            "UNROUTABLE, NOT_EMPTY, false",
            "ALGORITHM, EMPTY, false",
            "ALGORITHM, NOT_EMPTY, true"})
    void anUnroutableAssetTypeIsEmptyAsInTheInventoryFilter(CryptographicAssetType type,
            FilterConditionOperator operator, boolean expected) throws Exception {
        CryptoAsset typed = asset("typed-" + type, type, null);

        assertThat(evaluator
                .evaluateConditionItem(condition(FilterField.CBOM_ASSET_TYPE, operator, null), typed,
                        Resource.CRYPTO_ASSET))
                .isEqualTo(expected);
    }

    private CryptoAsset asset(String name) {
        return asset(name, CryptographicAssetType.ALGORITHM, null);
    }

    private CryptoAsset asset(String name, CryptographicAssetType type, CryptoAssetIdentityGuard guard) {
        CryptoAssetIdentityFields fields = new CryptoAssetIdentityFields(type, name, null, null, null, null, null, null,
                null, null);
        return assetRepository
                .findById(assetWriter.upsertIdentity(AssetRowKeys.forFields(fields), fields, guard))
                .orElseThrow();
    }

    private void addSources() {
        for (String serial : List.of("urn:uuid:one", "urn:uuid:two")) {
            Cbom cbom = new Cbom();
            cbom.setSerialNumber(serial);
            cbom.setVersion(1);
            cbom.setSpecVersion("1.6");
            cbomRepository.save(cbom);
            sourceWriter.upsertSource(asset.getUuid(), cbom.getUuid(), null, List.of(), OffsetDateTime.now());
        }
    }

    private static ConditionItem condition(FilterField field, FilterConditionOperator operator, Object value) {
        ConditionItem condition = new ConditionItem();
        condition.setFieldSource(FilterFieldSource.PROPERTY);
        condition.setFieldIdentifier(field.name());
        condition.setOperator(operator);
        condition.setValue(value);
        return condition;
    }
}
