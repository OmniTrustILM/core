package com.otilm.core.architecture;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import jakarta.persistence.LockModeType;
import jakarta.persistence.OneToOne;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.EnumSet;
import java.util.HashSet;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;
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
 * Pessimistic locks on entities with an inverse {@code @OneToOne} broke in Hibernate 7 (HHH-20744, fixed in 7.4.12), so
 * each one behind a {@code @Lock} repository method needs a PessimisticLockITest case. Programmatic locks are
 * enumerated on core#2017.
 */
class LockedInverseOneToOneGuardTest {

    static final Set<Class<?>> COVERED = Set.of(Certificate.class, CryptographicKey.class);

    private static final Set<LockModeType> PESSIMISTIC = EnumSet
            .of(LockModeType.PESSIMISTIC_READ, LockModeType.PESSIMISTIC_WRITE,
                    LockModeType.PESSIMISTIC_FORCE_INCREMENT);

    @Test
    void everyLockedEntityWithAnInverseOneToOneIsCovered() {
        Set<Class<?>> exposed = pessimisticallyLockedEntities()
                .stream()
                .filter(LockedInverseOneToOneGuardTest::hasInverseOneToOne)
                .collect(Collectors.toSet());
        assertEquals(COVERED, exposed, "Add a PessimisticLockITest case for each new entity, then list it in COVERED");
    }

    private static Set<Class<?>> pessimisticallyLockedEntities() {
        ClassPathScanningCandidateComponentProvider scanner = new ClassPathScanningCandidateComponentProvider(false) {
            @Override
            protected boolean isCandidateComponent(AnnotatedBeanDefinition definition) {
                return definition.getMetadata().isInterface();
            }
        };
        scanner.addIncludeFilter(new AssignableTypeFilter(Repository.class));
        Set<Class<?>> entities = new HashSet<>();
        for (BeanDefinition candidate : scanner.findCandidateComponents("com.otilm.core.dao.repository")) {
            Class<?> repository = ClassUtils.resolveClassName(candidate.getBeanClassName(), null);
            if (Arrays.stream(repository.getMethods()).anyMatch(LockedInverseOneToOneGuardTest::locksPessimistically)) {
                Class<?>[] types = GenericTypeResolver.resolveTypeArguments(repository, Repository.class);
                entities.add(Objects.requireNonNull(types, repository.getName())[0]);
            }
        }
        return entities;
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
