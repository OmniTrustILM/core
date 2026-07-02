package com.otilm.core.util.seeders;

import com.otilm.api.model.core.connector.EndpointDto;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.dao.entity.Endpoint;
import com.otilm.core.dao.entity.FunctionGroup;
import com.otilm.core.dao.repository.EndpointRepository;
import com.otilm.core.dao.repository.FunctionGroupRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Seeds connector function groups and their endpoints into the test database.
 * <p>
 * Function groups and their required endpoints are platform reference data normally provided by Flyway
 * migrations. In the test profile Flyway is disabled and {@code BaseSpringBootTest} truncates every
 * {@code core} table before each test, so any test that registers a V1 connector through
 * {@code ConnectorExternalService} must re-create the matching function group first — registration validation
 * rejects an unknown function group, and {@code ConnectorV1Adapter#validateFunctionGroups} checks the
 * connector's advertised endpoints against the seeded required ones. There is no service for this
 * metadata, so seeding goes through repositories.
 */
@Component
public class FunctionGroupSeeder {

    @Autowired
    private FunctionGroupRepository functionGroupRepository;

    @Autowired
    private EndpointRepository endpointRepository;

    /**
     * Idempotently seeds the function group with the given required endpoints. Per-test truncation
     * guarantees an existing group already carries its endpoints, so finding one skips seeding entirely.
     */
    public FunctionGroup seed(FunctionGroupCode code, List<EndpointDto> requiredEndpoints) {
        return functionGroupRepository.findByCode(code).orElseGet(() -> {
            FunctionGroup functionGroup = new FunctionGroup();
            functionGroup.setCode(code);
            functionGroup.setName(code.getCode());
            functionGroupRepository.save(functionGroup);

            List<Endpoint> endpoints = requiredEndpoints.stream()
                    .map(dto -> toEndpoint(dto, functionGroup))
                    .toList();
            endpointRepository.saveAll(endpoints);

            return functionGroup;
        });
    }

    private static Endpoint toEndpoint(EndpointDto dto, FunctionGroup functionGroup) {
        Endpoint endpoint = new Endpoint();
        endpoint.setName(dto.getName());
        endpoint.setContext(dto.getContext());
        endpoint.setMethod(dto.getMethod());
        endpoint.setRequired(dto.isRequired());
        endpoint.setFunctionGroupUuid(functionGroup.getUuid());
        return endpoint;
    }
}
