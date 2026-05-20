package com.czertainly.core.architecture;

import com.czertainly.core.dao.entity.Connector;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Enforces that callers outside ConnectorService implementations must obtain connector routing info via
 * ConnectorService.getConnectorForApiClient() rather than calling Connector.mapToApiClientDtoV1() directly.
 * The service method is cache-backed; bypassing it silently skips the cache and risks stale / divergent connector state at call sites.
 */
@AnalyzeClasses(packages = "com.czertainly.core", importOptions = ImportOption.DoNotIncludeTests.class)
public class ConnectorApiClientArchTest {

    @ArchTest
    static final ArchRule only_connector_service_impls_may_call_mapToApiClientDtoV1 =
            noClasses()
                    .that().areNotAssignableTo(com.czertainly.core.service.impl.ConnectorServiceImpl.class)
                    .and().areNotAssignableTo(com.czertainly.core.service.v2.impl.ConnectorServiceImpl.class)
                    .should().callMethod(Connector.class, "mapToApiClientDtoV1")
                    .because("use ConnectorService.getConnectorForApiClient(UUID) instead; it is cache-backed and avoids stale connector state");

    @ArchTest
    static final ArchRule only_connector_service_impls_may_call_mapToApiClientDtoV2 =
            noClasses()
                    .that().areNotAssignableTo(com.czertainly.core.service.impl.ConnectorServiceImpl.class)
                    .and().areNotAssignableTo(com.czertainly.core.service.v2.impl.ConnectorServiceImpl.class)
                    .should().callMethod(Connector.class, "mapToApiClientDtoV2")
                    .because("use ConnectorService.getConnectorForApiClient(UUID) instead; it is cache-backed and avoids stale connector state");
}
