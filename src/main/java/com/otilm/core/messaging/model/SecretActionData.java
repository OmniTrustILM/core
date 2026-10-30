package com.otilm.core.messaging.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.core.secret.SecretState;
import com.otilm.core.reference.ObjectRef;
import java.util.List;
import java.util.UUID;
import lombok.Builder;

/**
 * @param releasedBy the owner deleted together with the secret; only references held by others refuse the delete.
 * Written only when set, so a Core of an earlier version reads every other action.
 */
@Builder
public record SecretActionData(String encryptedContent, String name, UUID updatedSourceVaultProfileUuid,
        List<RequestAttribute> attributes, boolean deleteInVault, SecretState originalState,
        @JsonInclude(JsonInclude.Include.NON_NULL) ObjectRef releasedBy) {
}
