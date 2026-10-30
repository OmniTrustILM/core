package com.otilm.core.architecture;

import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchRule;
import org.springframework.cache.Cache;
import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;

import static com.tngtech.archunit.base.DescribedPredicate.describe;
import static com.tngtech.archunit.core.domain.JavaCall.Predicates.target;
import static com.tngtech.archunit.core.domain.JavaClass.Predicates.assignableTo;
import static com.tngtech.archunit.core.domain.properties.HasName.Predicates.name;
import static com.tngtech.archunit.core.domain.properties.HasName.Predicates.nameMatching;
import static com.tngtech.archunit.core.domain.properties.HasOwner.Predicates.With.owner;
import static com.tngtech.archunit.lang.conditions.ArchConditions.have;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noClasses;
import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.noMethods;

/**
 * Keeps every cache entry owned by the load that fills it. A value written from outside a load could restore what an
 * eviction has just dropped.
 */
@AnalyzeClasses(packages = "com.otilm.core", importOptions = ImportOption.DoNotIncludeTests.class)
public class CacheReadThroughArchTest {

    private static final String LOAD_THROUGH = "load through ReadThroughCache.getOrLoad or @Cacheable(sync = true)";

    @ArchTest
    static final ArchRule no_class_writes_a_cache_entry = noClasses()
            .should()
            .callMethodWhere(target(nameMatching("put|putIfAbsent")).and(target(owner(assignableTo(Cache.class)))))
            .because(LOAD_THROUGH);

    @ArchTest
    static final ArchRule native_caches_stay_in_the_cache_configuration = noClasses()
            .that()
            .resideOutsideOfPackage("com.otilm.core.config.cache")
            .should()
            .callMethodWhere(target(name("getNativeCache")).and(target(owner(assignableTo(Cache.class)))))
            .because(LOAD_THROUGH);

    @ArchTest
    static final ArchRule no_method_publishes_its_result = noMethods()
            .should()
            .beAnnotatedWith(CachePut.class)
            .because(LOAD_THROUGH);

    @ArchTest
    static final ArchRule no_class_caches_its_methods = noClasses()
            .should()
            .beAnnotatedWith(Cacheable.class)
            .orShould()
            .beAnnotatedWith(CachePut.class)
            .orShould()
            .beAnnotatedWith(Caching.class)
            .because(LOAD_THROUGH);

    @ArchTest
    static final ArchRule no_method_combines_cache_operations = noMethods()
            .should()
            .beAnnotatedWith(Caching.class)
            .because(LOAD_THROUGH);

    @ArchTest
    static final ArchRule cacheable_methods_load_through_the_cache = methods()
            .that()
            .areAnnotatedWith(Cacheable.class)
            .should(have(
                    describe("@Cacheable(sync = true)", method -> method.getAnnotationOfType(Cacheable.class).sync())))
            .because(LOAD_THROUGH);
}
