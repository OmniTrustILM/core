package com.otilm.core.architecture;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.cfg.MapperBuilder;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.util.DatabaseAttributeMigration;
import com.tngtech.archunit.base.DescribedPredicate;
import com.tngtech.archunit.core.domain.JavaCall;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.domain.JavaConstructor;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.core.importer.Location;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import org.springframework.http.converter.json.Jackson2ObjectMapperBuilder;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;

/**
 * Keeps every production {@link ObjectMapper} recipe inside {@link ObjectMapperFactory}, because Jackson 3 changes
 * defaults with no compiler signature. Mapper builders and subclasses count too: a constructor-only rule stays green
 * while {@code Jackson2ObjectMapperBuilder.json().build()} recreates a decentralized recipe.
 * <p>
 * Java migrations are exempt: each pins its own mapper, because a migration must keep producing the shape it wrote on
 * its first run. {@link DatabaseAttributeMigration} is exempt too, as the body of migration {@code V202402171510}.
 */
@AnalyzeClasses(packages = {"com.otilm.core", "db.migration"},
        importOptions = ObjectMapperCentralizationArchTest.OnlyThisModule.class)
class ObjectMapperCentralizationArchTest {

    /**
     * A call that creates a mapper: a constructor of {@link ObjectMapper} or a subclass, or a builder's
     * {@code build()}. Matching the return type instead would also reject accessors and chained {@code configure()}
     * calls.
     */
    private static final DescribedPredicate<JavaCall<?>> BUILDS_AN_OBJECT_MAPPER = new DescribedPredicate<>(
            "construct an ObjectMapper, directly or through a mapper builder") {

        @Override
        public boolean test(JavaCall<?> call) {
            JavaClass owner = call.getTargetOwner();
            if (JavaConstructor.CONSTRUCTOR_NAME.equals(call.getName())) {
                return owner.isAssignableTo(ObjectMapper.class);
            }
            return "build".equals(call.getName()) && (owner.isAssignableTo(Jackson2ObjectMapperBuilder.class)
                    || owner.isAssignableTo(MapperBuilder.class));
        }
    };

    @ArchTest
    static final ArchRule onlyTheFactoryConstructsObjectMappers = noClasses()
            .that()
            .doNotBelongToAnyOf(ObjectMapperFactory.class, DatabaseAttributeMigration.class)
            .and()
            .resideOutsideOfPackage("db.migration..")
            .should()
            .callCodeUnitWhere(BUILDS_AN_OBJECT_MAPPER)
            .because("production mappers come from ObjectMapperFactory, so the Jackson 3 migration has one recipe set "
                    + "to review instead of one per construction site");

    /**
     * Restricts the import to this module's own output. The {@code interfaces} artifact publishes into
     * {@code com.otilm.core} as well, and its mappers are not ours to centralize.
     */
    static class OnlyThisModule implements ImportOption {

        @Override
        public boolean includes(Location location) {
            return location.contains("/target/classes/");
        }
    }
}
