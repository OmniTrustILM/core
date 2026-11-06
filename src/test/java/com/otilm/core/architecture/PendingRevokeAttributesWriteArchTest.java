package com.otilm.core.architecture;

import com.otilm.core.dao.entity.Certificate;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import java.util.List;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Hibernate leaves a changed {@code pendingRevokeAttributes} out of the UPDATE of a managed certificate, so the setter
 * stores nothing there and the attributes would be lost without an error. Production code writes them through
 * {@code CertificatePendingRevokeWriter}.
 */
@AnalyzeClasses(packages = "com.otilm.core", importOptions = ImportOption.DoNotIncludeTests.class)
public class PendingRevokeAttributesWriteArchTest {

    @ArchTest
    static final ArchRule pending_revoke_attributes_are_written_only_through_the_writer = noClasses()
            .should()
            .callMethod(Certificate.class, "setPendingRevokeAttributes", List.class)
            .because("the entity UPDATE does not store a changed pendingRevokeAttributes; use "
                    + "CertificatePendingRevokeWriter");
}
