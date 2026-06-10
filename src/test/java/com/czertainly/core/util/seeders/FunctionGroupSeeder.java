package com.czertainly.core.util.seeders;

import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.czertainly.core.dao.entity.FunctionGroup;
import com.czertainly.core.dao.repository.FunctionGroupRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Seeds connector function groups into the test database.
 * <p>
 * Function groups are platform reference data normally provided by Flyway migrations. In the test
 * profile Flyway is disabled and {@code BaseSpringBootTest} truncates every {@code core} table before
 * each test, so any test that registers a V1 connector through {@code ConnectorService} must re-create
 * the matching function group first — registration validation rejects an unknown function group.
 * There is no service for this metadata, so seeding goes through the repository.
 */
@Component
public class FunctionGroupSeeder {

    @Autowired
    private FunctionGroupRepository functionGroupRepository;

    public FunctionGroup seedCryptographyProvider() {
        return seed(FunctionGroupCode.CRYPTOGRAPHY_PROVIDER);
    }

    public FunctionGroup seed(FunctionGroupCode code) {
        return functionGroupRepository.findByCode(code).orElseGet(() -> {
            FunctionGroup functionGroup = new FunctionGroup();
            functionGroup.setCode(code);
            functionGroup.setName(code.getCode());
            return functionGroupRepository.save(functionGroup);
        });
    }
}
