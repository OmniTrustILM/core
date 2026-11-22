package com.otilm.core.signing.formatting;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.AttributeType;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.util.AttributeDefinitionUtils;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/** Checks a signing profile's formatter attributes against the definitions its formatter publishes. */
public final class FormattingAttributesCheck {

    private static final String CLIENT_MESSAGE = "Internal error: signing configuration is invalid";

    private FormattingAttributesCheck() {
    }

    /**
     * Refuses the profile as misconfigured when an attribute is undefined, breaks its definition, or is required and
     * missing.
     */
    public static void requireValid(String profileName, List<BaseAttribute> definitions,
            List<RequestAttribute> attributes) throws SigningEngineException {
        List<RequestAttribute> configured = attributes == null ? List.of() : attributes;
        // validateAttributes lets an undefined name through with a warning
        List<String> undefined = undefinedNames(definitions, configured);
        if (!undefined.isEmpty()) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Signing Profile '%s' carries formatter attributes its formatter does not define: %s"
                            .formatted(profileName, undefined),
                    CLIENT_MESSAGE);
        }
        try {
            AttributeDefinitionUtils.validateAttributes(definitions, configured);
        } catch (ValidationException e) {
            throw new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                    "Signing Profile '%s' carries formatter attributes its formatter refuses: %s"
                            .formatted(profileName, e.getMessage()),
                    e, CLIENT_MESSAGE);
        }
    }

    /**
     * The configured names the formatter does not define. A published group defines any name, since its members are
     * known only once its callback runs.
     */
    public static List<String> undefinedNames(List<BaseAttribute> definitions, List<RequestAttribute> attributes) {
        if (publishesGroup(definitions)) {
            return List.of();
        }
        Set<String> defined = definitions.stream().map(BaseAttribute::getName).collect(Collectors.toSet());
        return attributes.stream().map(RequestAttribute::getName).filter(name -> !defined.contains(name)).toList();
    }

    private static boolean publishesGroup(List<BaseAttribute> definitions) {
        return definitions.stream().anyMatch(definition -> definition.getType() == AttributeType.GROUP);
    }
}
