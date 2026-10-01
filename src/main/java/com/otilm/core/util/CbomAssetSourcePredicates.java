package com.otilm.core.util;

import com.otilm.core.dao.entity.Cbom;
import com.otilm.core.dao.entity.UniquelyIdentified_;
import com.otilm.core.dao.entity.cbom.CryptoAssetSource;
import com.otilm.core.dao.entity.cbom.CryptoAssetSource_;
import jakarta.persistence.criteria.CommonAbstractCriteria;
import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.Predicate;
import jakarta.persistence.criteria.Root;
import jakarta.persistence.criteria.Subquery;

public final class CbomAssetSourcePredicates {

    private CbomAssetSourcePredicates() {
        throw new IllegalStateException("Static utility class");
    }

    /** A CBOM contributes when at least one asset-source row points at its UUID. */
    public static Predicate hasContributedAssets(Root<Cbom> root, CriteriaBuilder cb, CommonAbstractCriteria query) {
        Subquery<Integer> contributed = query.subquery(Integer.class);
        Root<CryptoAssetSource> source = contributed.from(CryptoAssetSource.class);
        contributed
                .select(cb.literal(1))
                .where(cb.equal(source.get(CryptoAssetSource_.cbomUuid), root.get(UniquelyIdentified_.uuid)));
        return cb.exists(contributed);
    }
}
