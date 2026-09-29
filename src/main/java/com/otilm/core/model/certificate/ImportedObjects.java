package com.otilm.core.model.certificate;

import java.io.Serializable;
import java.util.List;

/**
 * What a certificate import produced, as its audit record names it: the certificate and the key each imported entry
 * came to, as the entry's result names them, whether the import registered them or found them in the inventory.
 *
 * @param certificateUuids the UUIDs of the certificates, each an entry's certificate or its key's leaf
 * @param keyUuids the UUIDs of the keys
 */
public record ImportedObjects(List<String> certificateUuids, List<String> keyUuids) implements Serializable {

    public ImportedObjects {
        certificateUuids = List.copyOf(certificateUuids);
        keyUuids = List.copyOf(keyUuids);
    }
}
