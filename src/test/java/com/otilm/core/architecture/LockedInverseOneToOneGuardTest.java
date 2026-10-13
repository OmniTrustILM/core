package com.otilm.core.architecture;

import com.otilm.core.integration.repository.PessimisticLockITest;
import jakarta.persistence.LockModeType;
import jakarta.persistence.OneToOne;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.AnnotatedBeanDefinition;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.GenericTypeResolver;
import org.springframework.core.type.filter.AssignableTypeFilter;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.repository.Repository;
import org.springframework.util.ClassUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Pessimistic locks on entities with an inverse {@code @OneToOne} broke in Hibernate 7.2 (HHH-20744, fixed in 7.4.8),
 * so each {@code @Lock} repository query on such an entity needs a PessimisticLockITest case. Locks taken through the
 * EntityManager are not scanned.
 */
class LockedInverseOneToOneGuardTest {

    private static final Set<LockModeType> PESSIMISTIC = EnumSet
            .of(LockModeType.PESSIMISTIC_READ, LockModeType.PESSIMISTIC_WRITE,
                    LockModeType.PESSIMISTIC_FORCE_INCREMENT);

    @Test
    void everyLockQueryOnAnEntityWithAnInverseOneToOneHasACase() {
        assertEquals(PessimisticLockITest.LOCK_QUERIES, exposedLockQueries(),
                "Add a PessimisticLockITest case for each new lock query, then list it in LOCK_QUERIES");
    }

    private static Set<String> exposedLockQueries() {
        ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false) {
            @Override
            protected boolean isCandidateComponent(AnnotatedBeanDefinition definition) {
                return definition.getMetadata().isInterface();
            }
        };
        scanner.addIncludeFilter(new AssignableTypeFilter(Repository.class));
        Set<String> queries = new HashSet<>();
        for (BeanDefinition candidate : scanner.findCandidateComponents("com.otilm.core.dao.repository")) {
            Class<?> repository = ClassUtils.resolveClassName(candidate.getBeanClassName(), null);
            List<Method> locking = Arrays
                    .stream(repository.getMethods())
                    .filter(LockedInverseOneToOneGuardTest::locksPessimistically)
                    .toList();
            if (!locking.isEmpty() && hasInverseOneToOne(entityOf(repository))) {
                locking.forEach(method -> queries.add(repository.getSimpleName() + "#" + method.getName()));
            }
        }
        return queries;
    }

    private static Class<?> entityOf(Class<?> repository) {
        Class<?>[] types = GenericTypeResolver.resolveTypeArguments(repository, Repository.class);
        return Objects.requireNonNull(types, repository.getName())[0];
    }

    private static boolean locksPessimistically(Method method) {
        Lock lock = method.getAnnotation(Lock.class);
        return lock != null && PESSIMISTIC.contains(lock.value());
    }

    private static boolean hasInverseOneToOne(Class<?> entity) {
        for (Class<?> type = entity; type != Object.class; type = type.getSuperclass()) {
            for (Field field : type.getDeclaredFields()) {
                OneToOne mapping = field.getAnnotation(OneToOne.class);
                if (mapping != null && !mapping.mappedBy().isEmpty()) {
                    return true;
                }
            }
        }
        return false;
    }
}
