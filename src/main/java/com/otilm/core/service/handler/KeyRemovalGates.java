package com.otilm.core.service.handler;

import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.KeyRemovalCandidate;
import java.util.EnumSet;
import java.util.Optional;
import java.util.Set;
import org.springframework.stereotype.Component;

/**
 * Removal from the inventory leaves the key in its key storage. A later listing of its token must find it again, and a
 * compromised key must never come back active through onboarding.
 */
@Component
public class KeyRemovalGates {

    public static final String NO_PRIVATE_KEY_IN_TOKEN = "It holds no private key in a token. Delete it instead.";
    public static final String TOKEN_NOT_LISTABLE = "The connector backing this token cannot list keys, so it could not "
            + "be onboarded again. Delete or destroy it instead.";
    public static final String COMPROMISED = "It is compromised and would come back active when onboarded again. "
            + "Destroy it instead.";

    private static final Set<KeyState> DESTROYED_STATES = EnumSet
            .of(KeyState.DESTROYED, KeyState.DESTROYED_COMPROMISED);
    private static final Set<KeyState> COMPROMISED_STATES = EnumSet
            .of(KeyState.COMPROMISED, KeyState.DESTROYED_COMPROMISED);

    private final KeyListGates keyListGates;

    public KeyRemovalGates(KeyListGates keyListGates) {
        this.keyListGates = keyListGates;
    }

    public Optional<String> refusal(KeyRemovalCandidate candidate) {
        if (candidate.key().tokenInstanceReferenceUuid() == null
                || candidate.items().stream().noneMatch(KeyRemovalGates::isPrivateKeyInToken)) {
            return Optional.of(NO_PRIVATE_KEY_IN_TOKEN);
        }
        if (!keyListGates.isAvailable(candidate.tokenConnectorInterface())) {
            return Optional.of(TOKEN_NOT_LISTABLE);
        }
        if (candidate.items().stream().anyMatch(item -> COMPROMISED_STATES.contains(item.state()))) {
            return Optional.of(COMPROMISED);
        }
        return Optional.empty();
    }

    public boolean isRemovable(KeyRemovalCandidate candidate) {
        return refusal(candidate).isEmpty();
    }

    private static boolean isPrivateKeyInToken(CryptographicKeyItemBasicModel item) {
        return item.type() == KeyType.PRIVATE_KEY && !DESTROYED_STATES.contains(item.state());
    }
}
