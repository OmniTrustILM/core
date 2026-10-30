package com.otilm.core.signing.contentsigning.parameters;

import com.otilm.api.model.common.signature.SignatureParameterGroup;
import com.otilm.api.model.common.signature.parameters.SignatureParameterContainer;
import com.otilm.api.model.common.signature.parameters.SignatureParameterSink;
import java.util.ArrayList;
import java.util.Collection;
import java.util.EnumMap;
import java.util.List;
import java.util.Map;

/**
 * Reads the parameter groups which a signature-parameters tree declares about itself.
 *
 * <p>
 * The contract's {@code describe} is the single authority on group membership, so the permission check asks the tree
 * rather than restating its field list.
 * </p>
 */
public final class RequestParameterGroups {

    private RequestParameterGroups() {
    }

    /**
     * @return whether the tree supplies no value at all. An envelope carrying only the family discriminator, and a
     * nested container carrying nothing, mean the same thing to the permission check and to the merge because both ask
     * this one question.
     */
    public static boolean suppliesNothing(SignatureParameterContainer node) {
        return presentFieldsByGroup(node).isEmpty();
    }

    /**
     * @return the dotted path of every field carrying a value, keyed by the group that field declares. A field set to
     * {@code null}, or to an empty collection, is absent.
     */
    public static Map<SignatureParameterGroup, List<String>> presentFieldsByGroup(SignatureParameterContainer node) {
        Map<SignatureParameterGroup, List<String>> byGroup = new EnumMap<>(SignatureParameterGroup.class);
        if (node != null) {
            node.describe(new PathSink("", byGroup));
        }
        return byGroup;
    }

    /**
     * Files the dotted path of each set field under the group it declares, descending into nested objects and extending
     * the path as it goes.
     *
     * @param prefix the path of the container currently being described, empty at the root
     */
    private record PathSink(String prefix,
            Map<SignatureParameterGroup, List<String>> byGroup) implements SignatureParameterSink {

        @Override
        public void leaf(String name, SignatureParameterGroup group, Object value) {
            if (isAbsent(value)) {
                return;
            }
            byGroup.computeIfAbsent(group, declared -> new ArrayList<>()).add(path(name));
        }

        @Override
        public void container(String name, SignatureParameterContainer value) {
            if (value != null) {
                value.describe(new PathSink(path(name), byGroup));
            }
        }

        private String path(String name) {
            return prefix.isEmpty() ? name : prefix + "." + name;
        }

        private static boolean isAbsent(Object value) {
            return value == null || (value instanceof Collection<?> collection && collection.isEmpty());
        }
    }
}
