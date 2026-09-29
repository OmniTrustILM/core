package com.otilm.core.service.handler.key;

import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.core.model.crypto.ProviderKeyItem;
import java.util.List;

/** What a connector answers about a key import. */
public sealed interface ImportAnswer {

    /**
     * The key was imported.
     *
     * @param type the key type the connector reports
     * @param items the key's items as the connector describes them
     */
    record Imported(KeyRequestType type, List<ProviderKeyItem> items) implements ImportAnswer {

        /** The imported public key as the inventory holds it, base64 of its SPKI, or {@code null} for a secret key. */
        public String publicKey() {
            return items
                    .stream()
                    .filter(item -> item.type() == KeyType.PUBLIC_KEY && item.material() != null)
                    .map(item -> item.material().serializedValue())
                    .findFirst()
                    .orElse(null);
        }
    }

    /**
     * The import is still running.
     *
     * @param operationMeta the connector's handle for it, or {@code null} when the answer came without one
     */
    record Running(List<MetadataAttribute> operationMeta) implements ImportAnswer {
    }

    /** The import ended without a key: it failed, or it was cancelled. */
    record NotImported() implements ImportAnswer {
    }

    /** The connector never accepted an import under the identifier. */
    record NotAccepted() implements ImportAnswer {
    }
}
