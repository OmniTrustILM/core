package com.otilm.core.util;

import com.otilm.api.exception.ValidationException;
import jakarta.persistence.criteria.From;
import jakarta.persistence.criteria.Path;
import jakarta.persistence.metamodel.Attribute;
import jakarta.persistence.metamodel.ManagedType;
import jakarta.persistence.metamodel.PluralAttribute;
import jakarta.persistence.metamodel.SingularAttribute;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link FilterPredicatesBuilder#resolveFieldPath}.
 *
 * <p>
 * The metamodel is stubbed rather than derived from real entities, because the interesting cases are defined by where
 * an attribute is declared relative to the path being resolved against, not by any particular entity. The plural
 * subtype case has no counterpart among today's filter fields and can only be reached this way.
 */
@SuppressWarnings({"unchecked", "rawtypes"})
class FilterPredicatesBuilderFieldPathTest {

    private static class Base {
    }

    private static class Sub extends Base {
    }

    @Test
    void attributeDeclaredOnThePathsOwnType_isResolvedByName() {
        final From from = fromOfType(Base.class);
        final Path<?> expectedPath = pathReturnedByName(from, "displayName");

        final Path<?> resolvedPath = FilterPredicatesBuilder
                .resolveFieldPath(from, singularAttribute("displayName", Base.class));

        assertThat(resolvedPath).isSameAs(expectedPath);
    }

    @Test
    void attributeDeclaredOnASupertype_isResolvedByName() {
        final From from = fromOfType(Sub.class);
        final Path<?> expectedPath = pathReturnedByName(from, "uuid");

        final Path<?> resolvedPath = FilterPredicatesBuilder
                .resolveFieldPath(from, singularAttribute("uuid", Base.class));

        assertThat(resolvedPath).isSameAs(expectedPath);
    }

    @Test
    void singularAttributeDeclaredOnASubtype_isResolvedThroughTheAttribute() {
        final From from = fromOfType(Base.class);
        final SingularAttribute attribute = singularAttribute("code", Sub.class);
        final Path<?> expectedPath = mock(Path.class);
        when(from.get(attribute)).thenReturn(expectedPath);

        final Path<?> resolvedPath = FilterPredicatesBuilder.resolveFieldPath(from, attribute);

        assertThat(resolvedPath).isSameAs(expectedPath);
        verify(from, never()).get(anyString());
    }

    @Test
    void pluralAttributeDeclaredOnASubtype_isRejected() {
        final From from = fromOfType(Base.class);
        final PluralAttribute attribute = mock(PluralAttribute.class);
        stubDeclaration(attribute, "altCodes", Sub.class);

        assertThatThrownBy(() -> FilterPredicatesBuilder.resolveFieldPath(from, attribute))
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("altCodes")
                .hasMessageContaining("Sub");
        verify(from, never()).get(anyString());
    }

    private static From fromOfType(final Class<?> javaType) {
        final From from = mock(From.class);
        when(from.getJavaType()).thenReturn(javaType);
        return from;
    }

    private static Path<?> pathReturnedByName(final From from, final String attributeName) {
        final Path<?> path = mock(Path.class);
        when(from.get(attributeName)).thenReturn(path);
        return path;
    }

    private static SingularAttribute singularAttribute(final String name, final Class<?> declaringJavaType) {
        final SingularAttribute attribute = mock(SingularAttribute.class);
        stubDeclaration(attribute, name, declaringJavaType);
        return attribute;
    }

    private static void stubDeclaration(final Attribute attribute, final String name, final Class<?> declaringType) {
        final ManagedType managedType = mock(ManagedType.class);
        when(managedType.getJavaType()).thenReturn(declaringType);
        when(attribute.getDeclaringType()).thenReturn(managedType);
        when(attribute.getName()).thenReturn(name);
    }
}
