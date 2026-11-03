package com.otilm.core.signing.contentsigning.parameters;

import com.otilm.api.model.common.signature.parameters.SignatureParameterContainer;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Addresses the leaf fields of a signature-parameters tree by dotted path, so a test can sweep the merge one field at a
 * time without restating the field list it is trying to prove complete.
 */
final class ParameterPaths {

    private static final String DISCRIMINATOR = "family";

    private ParameterPaths() {
    }

    /** @return the dotted path of every leaf field the tree declares, nested containers included */
    static List<String> leafPaths(Class<?> type) {
        List<String> paths = new ArrayList<>();
        collect(type, "", paths);
        return paths;
    }

    private static void collect(Class<?> type, String prefix, List<String> paths) {
        for (Field field : instanceFields(type)) {
            if (DISCRIMINATOR.equals(field.getName())) {
                continue;
            }
            String path = prefix.isEmpty() ? field.getName() : prefix + "." + field.getName();
            if (SignatureParameterContainer.class.isAssignableFrom(field.getType())) {
                collect(field.getType(), path, paths);
            } else {
                paths.add(path);
            }
        }
    }

    /** Sets {@code path} to a {@link #sampleValue}, creating whatever containers the path passes through. */
    static Object populate(SignatureParametersDto root, String path, int variant) {
        String[] steps = path.split("\\.");
        Object node = root;
        for (int i = 0; i < steps.length - 1; i++) {
            Field field = declaredField(node.getClass(), steps[i]);
            Object child = read(field, node);
            if (child == null) {
                child = instantiate(field.getType());
                write(field, node, child);
            }
            node = child;
        }
        Field leaf = declaredField(node.getClass(), steps[steps.length - 1]);
        Object value = sampleValue(leaf, variant);
        write(leaf, node, value);
        return value;
    }

    static Object populate(SignatureParametersDto root, String path) {
        return populate(root, path, 0);
    }

    /** @return the value at {@code path}, or {@code null} where any container along the way is absent */
    static Object read(SignatureParametersDto root, String path) {
        Object node = root;
        for (String step : path.split("\\.")) {
            if (node == null) {
                return null;
            }
            node = read(declaredField(node.getClass(), step), node);
        }
        return node;
    }

    static Object sampleValue(Field field, int variant) {
        Class<?> type = field.getType();
        String name = field.getName();
        int seed = Math.abs(name.hashCode() % 97) + 1 + variant;
        if (type.isEnum()) {
            Object[] constants = type.getEnumConstants();
            return constants[variant == 0 ? constants.length - 1 : 0];
        }
        if (type == String.class) {
            return name + "-value-" + variant;
        }
        if (type == Boolean.class) {
            return Boolean.TRUE;
        }
        if (type == Integer.class) {
            return seed;
        }
        if (type == Float.class) {
            return (float) seed;
        }
        if (type == byte[].class) {
            return (name + variant).getBytes(StandardCharsets.UTF_8);
        }
        if (List.class.isAssignableFrom(type)) {
            return new ArrayList<>(List.of(name + "-" + variant));
        }
        throw new IllegalStateException("the sweep has no value for " + name + " of type " + type.getSimpleName()
                + "; teach ParameterPaths about the type rather than letting the field go unswept");
    }

    private static List<Field> instanceFields(Class<?> type) {
        List<Field> fields = new ArrayList<>();
        for (Class<?> current = type; current != null && current != Object.class; current = current.getSuperclass()) {
            for (Field field : current.getDeclaredFields()) {
                if (!field.isSynthetic() && !Modifier.isStatic(field.getModifiers())) {
                    field.setAccessible(true);
                    fields.add(field);
                }
            }
        }
        return fields;
    }

    private static Field declaredField(Class<?> type, String name) {
        return instanceFields(type)
                .stream()
                .filter(field -> field.getName().equals(name))
                .findFirst()
                .orElseThrow(() -> new IllegalStateException(type.getSimpleName() + " declares no field " + name));
    }

    private static Object instantiate(Class<?> type) {
        try {
            return type.getDeclaredConstructor().newInstance();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(type.getSimpleName() + " needs a no-argument constructor", e);
        }
    }

    private static Object read(Field field, Object node) {
        try {
            return field.get(node);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("could not read " + field.getName(), e);
        }
    }

    private static void write(Field field, Object node, Object value) {
        try {
            field.set(node, value);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException("could not write " + field.getName(), e);
        }
    }
}
