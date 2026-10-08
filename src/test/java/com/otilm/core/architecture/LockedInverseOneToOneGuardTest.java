package com.otilm.core.architecture;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.entity.CryptographicKey;
import jakarta.persistence.OneToOne;
import java.lang.reflect.Field;
import java.util.Arrays;
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
 * Hibernate 7.2+ silently drops FOR UPDATE on entities with an inverse {@code @OneToOne} (HHH-20744), so each one
 * behind a {@code @Lock} repository method needs a PessimisticLockITest case. Programmatic locks are enumerated on
 * core#2017.
 */
class LockedInverseOneToOneGuardTest {

    static final Set<Class<?>> COVERED = Set.of(Certificate.class, CryptographicKey.class);

    @Test
    void everyLockedEntityWithAnInverseOneToOneIsCovered() {
        Set<Class<?>> exposed = lockedEntities()
                .stream()
                .filter(LockedInverseOneToOneGuardTest::hasInverseOneToOne)
                .collect(Collectors.toSet());
        assertEquals(COVERED, exposed, "Add a PessimisticLockITest case for each new entity, then list it in COVERED");
    }

    private static Set<Class<?>> lockedEntities() {
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
            if (Arrays.stream(repository.getMethods()).anyMatch(m -> m.isAnnotationPresent(Lock.class))) {
                Class<?>[] types = GenericTypeResolver.resolveTypeArguments(repository, Repository.class);
                entities.add(Objects.requireNonNull(types, repository.getName())[0]);
            }
        }
        return entities;
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
