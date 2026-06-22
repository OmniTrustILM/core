package com.otilm.core.architecture;

import com.tngtech.archunit.core.domain.JavaMethod;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import org.springframework.data.jpa.repository.Query;

import java.util.regex.Pattern;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.methods;

/**
 * Enforces that every native {@code @Query} schema-qualifies its table references with the Hibernate
 * {@code {h-schema}} placeholder.
 */
@AnalyzeClasses(packages = "com.otilm.core", importOptions = ImportOption.DoNotIncludeTests.class)
public class NativeQuerySchemaArchTest {

    /** Keywords that introduce a table reference in SQL; their presence means the query touches a table. */
    private static final Pattern REFERENCES_TABLE =
            Pattern.compile("\\b(FROM|JOIN|INTO|UPDATE)\\b", Pattern.CASE_INSENSITIVE);

    private static final String SCHEMA_PLACEHOLDER = "{h-schema}";

    @ArchTest
    static final ArchRule native_queries_must_qualify_tables_with_h_schema_placeholder =
            methods()
                    .that().areAnnotatedWith(Query.class)
                    .should(new ArchCondition<JavaMethod>(
                            "use the Hibernate {h-schema} placeholder for table references when nativeQuery = true") {
                        @Override
                        public void check(JavaMethod method, ConditionEvents events) {
                            Query query = method.getAnnotationOfType(Query.class);
                            if (!query.nativeQuery()) {
                                return; // JPQL — Hibernate applies hibernate.default_schema automatically
                            }
                            String sql = query.value();
                            if (!REFERENCES_TABLE.matcher(sql).find()) {
                                return; // no table reference (e.g. a bare function call) — nothing to qualify
                            }
                            if (sql.contains(SCHEMA_PLACEHOLDER)) {
                                return;
                            }
                            events.add(SimpleConditionEvent.violated(method,
                                    method.getFullName() + " is a native @Query that references a table without the"
                                            + " '{h-schema}' placeholder. Native queries bypass hibernate.default_schema,"
                                            + " so an unqualified table fails in production where 'core' is not on the"
                                            + " connection search_path. Qualify tables with {h-schema}, e.g."
                                            + " 'FROM {h-schema}my_table'."));
                        }
                    });
}
