package com.otilm.core.service.est;

import com.otilm.api.model.core.est.EstPaths;
import com.otilm.core.util.ValidatorUtil;

/**
 * Decides which names can be the label EST clients put in the URL path, between {@code /.well-known/est/} and the
 * operation.
 */
public final class EstLabels {

    private EstLabels() {
    }

    /**
     * Whether a name can be used as an EST label: it consists only of RFC 3986 unreserved characters and is neither an
     * EST operation name nor a dot segment. An empty name is refused because it would address the route that carries no
     * label.
     *
     * @param name the candidate label, may be {@code null}
     * @return {@code true} when the name can be used as a label
     */
    public static boolean isUsable(String name) {
        if (name == null || name.isEmpty()) {
            return false;
        }
        // containsUnreservedCharacters is true when a character is NOT unreserved
        boolean onlyUnreservedCharacters = !ValidatorUtil.containsUnreservedCharacters(name);
        return onlyUnreservedCharacters && !EstPaths.isReservedLabel(name);
    }
}
