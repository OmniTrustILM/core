package com.otilm.core.architecture;

import com.otilm.core.dao.entity.Connector;
import com.otilm.core.service.v2.impl.ConnectorServiceImpl;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Enforces that callers outside the connector service implementations must obtain connector routing info via
 * ConnectorInternalService.getConnectorForApiClient() rather than calling Connector.mapToApiClientDtoV1() directly.
 * The service method is cache-backed; bypassing it silently skips the cache and risks stale / divergent connector state at call sites.
 */
@AnalyzeClasses(packages = "com.otilm.core", importOptions = ImportOption.DoNotIncludeTests.class)
public class ConnectorApiClientArchTest {

    @ArchTest
    static final ArchRule only_connector_service_impls_may_call_mapToApiClientDtoV1 =
            noClasses()
                    .that().areNotAssignableTo(com.otilm.core.service.impl.ConnectorServiceImpl.class)
                    .and().areNotAssignableTo(ConnectorServiceImpl.class)
                    .should().callMethod(Connector.class, "mapToApiClientDtoV1")
                    .because("use ConnectorInternalService.getConnectorForApiClient(UUID) instead; it is cache-backed and avoids stale connector state");

    @ArchTest
    static final ArchRule only_connector_service_impls_may_call_mapToApiClientDtoV2 =
            noClasses()
                    .that().areNotAssignableTo(com.otilm.core.service.impl.ConnectorServiceImpl.class)
                    .and().areNotAssignableTo(ConnectorServiceImpl.class)
                    .should().callMethod(Connector.class, "mapToApiClientDtoV2")
                    .because("use ConnectorInternalService.getConnectorForApiClient(UUID) instead; it is cache-backed and avoids stale connector state");
}
