package com.otilm.core.architecture;

import com.otilm.core.attribute.engine.AttributeEngine;
import com.otilm.core.attribute.engine.AttributeReferenceExpander;
import com.otilm.core.attribute.engine.CallerAuthorizedReferenceLoaderRegistry;
import com.otilm.core.attribute.engine.ConnectorRequestAttributesBuilder;
import com.otilm.core.service.impl.CredentialServiceImpl;
import com.otilm.core.service.impl.ResourceServiceImpl;
import com.otilm.core.util.AuthHelper;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import java.util.List;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * The fence for #1624 callback mode — THE load-bearing security boundary of this ticket.
 *
 * <p>Callback-mode expansion ({@link AttributeReferenceExpander#expandForCaller}) must resolve references
 * ONLY through the typed {@link CallerAuthorizedReferenceLoaderRegistry}, i.e. through the per-object
 * {@code SecuredUUID}+{@code DETAIL}-guarded loaders. It must NEVER reach the unguarded by-UUID primitives that
 * load object/credential material without a per-object authorization check.
 *
 * <p>A package-private (visibility) fence is impossible: the operation-mode primitive
 * ({@link ConnectorRequestAttributesBuilder}) and the underlying list-loaders
 * ({@code CredentialServiceImpl.loadFullCredentialData(List)},
 * {@code ResourceServiceImpl.loadResourceObjectContentData(List)}) are all public and reachable from many call
 * sites today (plan-review P1). So this type-level reachability assertion carries the ENTIRE fence weight. If it
 * is weakened or deleted, the per-object authorization boundary this ticket installs can be silently bypassed.
 *
 * <p>Modelled on {@link ConnectorApiClientArchTest} ({@code noClasses().that()...should().callMethod(...)}).
 */
@AnalyzeClasses(packages = "com.otilm.core.attribute.engine", importOptions = ImportOption.DoNotIncludeTests.class)
public class AttributeReferenceExpanderFenceArchTest {

    @ArchTest
    static final ArchRule callback_path_must_not_call_unguarded_credential_list_loader =
            noClasses()
                    .that().resideInAPackage("com.otilm.core.attribute.engine..")
                    .and().areNotAssignableTo(ConnectorRequestAttributesBuilder.class)
                    .and().areNotAssignableTo(AttributeEngine.class)
                    .should().callMethod(CredentialServiceImpl.class, "loadFullCredentialData", List.class)
                    .because("callback mode must resolve credentials only via the SecuredUUID+DETAIL guarded "
                            + "getAuthorizedObjectAttributes loader, never the resource-level (no per-object) list-loader");

    @ArchTest
    static final ArchRule callback_path_must_not_call_unguarded_resource_list_loader =
            noClasses()
                    .that().resideInAPackage("com.otilm.core.attribute.engine..")
                    .and().areNotAssignableTo(ConnectorRequestAttributesBuilder.class)
                    .and().areNotAssignableTo(AttributeEngine.class)
                    .should().callMethod(ResourceServiceImpl.class, "loadResourceObjectContentData", List.class)
                    .because("the resource list-loader carries no @ExternalAuthorization at all; callback mode must "
                            + "never reach it");

    @ArchTest
    static final ArchRule callback_path_must_not_reach_unguarded_operation_builder =
            noClasses()
                    .that().resideInAPackage("com.otilm.core.attribute.engine..")
                    .and().areNotAssignableTo(ConnectorRequestAttributesBuilder.class)
                    .and().areNotAssignableTo(AttributeEngine.class)
                    .should().dependOnClassesThat().areAssignableTo(ConnectorRequestAttributesBuilder.class)
                    .because("ConnectorRequestAttributesBuilder is the unguarded operation-mode primitive (it calls "
                            + "both unguarded list-loaders); callback mode must not link against it");

    @ArchTest
    static final ArchRule expander_must_not_mutate_security_context =
            noClasses()
                    .that().resideInAPackage("com.otilm.core.attribute.engine..")
                    .and().areNotAssignableTo(ConnectorRequestAttributesBuilder.class)
                    .and().areNotAssignableTo(AttributeEngine.class)
                    .should().dependOnClassesThat().areAssignableTo(AuthHelper.class)
                    .because("N3 invariant: the expander introduces no elevated principal — it never calls "
                            + "AuthHelper.authenticateAs* / sets a new Authentication; there is no context to leak");
}
