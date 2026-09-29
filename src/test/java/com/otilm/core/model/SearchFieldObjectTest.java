package com.otilm.core.model;

import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.common.content.data.ProtectionLevel;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.Arrays;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class SearchFieldObjectTest {

    @Test
    void aCopyCarriesEveryFieldAndChangesIndependently() {
        SearchFieldObject original = new SearchFieldObject("environment", AttributeContentType.STRING,
                AttributeType.CUSTOM);
        original.setLabel("Environment");
        original.setList(true);
        original.setMultiSelect(true);
        original.setProtectionLevel(ProtectionLevel.NONE);
        original.setVisible(false);
        original.setContentItems(List.of("production", "staging"));

        SearchFieldObject copy = original.copy();
        assertThat(copy).isEqualTo(original).isNotSameAs(original);

        copy.setVisible(true);
        copy.setContentItems(List.of("other"));
        assertThat(original.isVisible()).isFalse();
        assertThat(original.getContentItems()).containsExactly("production", "staging");
    }

    @Test
    void aCopyCarriesEveryDeclaredField() throws Exception {
        List<Field> fields = Arrays
                .stream(SearchFieldObject.class.getDeclaredFields())
                .filter(field -> !Modifier.isStatic(field.getModifiers()))
                .toList();
        SearchFieldObject original = new SearchFieldObject(AttributeContentType.STRING);
        for (Field field : fields) {
            field.setAccessible(true);
            field.set(original, differentValue(field, field.get(original)));
        }

        SearchFieldObject copy = original.copy();

        for (Field field : fields) {
            assertThat(field.get(copy)).as(field.getName()).isEqualTo(field.get(original));
        }
    }

    /** A value the field does not hold yet, so a field that copy() leaves out shows up as a difference. */
    private static Object differentValue(Field field, Object current) {
        Class<?> type = field.getType();
        if (type == String.class) {
            return field.getName() + "-value";
        }
        if (type == boolean.class) {
            return !((Boolean) current);
        }
        if (type.isEnum()) {
            Object[] constants = type.getEnumConstants();
            return constants[0] == current ? constants[1] : constants[0];
        }
        if (type == List.class) {
            return List.of(field.getName() + "-item");
        }
        if (type == UUID.class) {
            return UUID.randomUUID();
        }
        throw new AssertionError(
                "SearchFieldObject.%s has a type this test cannot fill: %s".formatted(field.getName(), type.getName()));
    }
}
