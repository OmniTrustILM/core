package com.otilm.core.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Keeps the common Signing Engine free of protocol knowledge. A dependency on a workflow package, on RFC 3161's error
 * vocabulary or on the content-signing formatting DTOs would silently re-narrow it to one of the workflows it serves.
 */
@AnalyzeClasses(packages = "com.otilm.core", importOptions = ImportOption.DoNotIncludeTests.class)
public class SigningEngineIsolationArchTest {

    @ArchTest
    static final ArchRule engine_does_not_depend_on_the_tsp_pipeline = noClasses()
            .that()
            .resideInAPackage("com.otilm.core.signing.engine..")
            .should()
            .dependOnClassesThat()
            .resideInAnyPackage("com.otilm.core.signing.tsa..", "com.otilm.core.signing.contentsigning..")
            .because("the engine is shared by three workflows; a dependency on one of them re-narrows it");

    @ArchTest
    static final ArchRule engine_does_not_speak_rfc_3161_errors = noClasses()
            .that()
            .resideInAPackage("com.otilm.core.signing.engine..")
            .should()
            .dependOnClassesThat()
            .resideInAPackage("com.otilm.api.interfaces.core.tsp..")
            .because("TspException and TspFailureInfo are protocol-shaped; the engine uses SigningEngineException");

    @ArchTest
    static final ArchRule engine_does_not_speak_content_signing_formatting = noClasses()
            .that()
            .resideInAPackage("com.otilm.core.signing.engine..")
            .should()
            .dependOnClassesThat()
            .resideInAnyPackage("com.otilm.api.interfaces.client.v1.signing.contentsigning..",
                    "com.otilm.api.model.connector.signatures.contentsigning..")
            .because("content-signing DTOs are as workflow-specific as RFC 3161's; the engine must not know either "
                    + "vocabulary");

    @ArchTest
    static final ArchRule content_signing_orchestrator_reaches_non_idempotent_steps_only_through_the_seam = noClasses()
            .that()
            .resideInAPackage("com.otilm.core.signing.contentsigning")
            .should()
            .dependOnClassesThat()
            .resideInAnyPackage("com.otilm.core.signing.engine.signer..", "com.otilm.core.signing.tsa")
            .because("minting a signature value or a timestamp token is not replayable; the orchestrator must reach "
                    + "both only through ContentSigningAcquisitions, or a run can never be persisted and replayed");

    @ArchTest
    static final ArchRule resolved_models_do_not_depend_on_a_protocol_package = noClasses()
            .that()
            .resideInAPackage("com.otilm.core.model.signing..")
            .should()
            .dependOnClassesThat()
            .resideInAPackage("com.otilm.core.signing.tsa..")
            .because("the resolved model hierarchy is shared by every workflow, so it must not reach into one "
                    + "workflow's package");
}
