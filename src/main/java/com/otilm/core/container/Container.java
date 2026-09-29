package com.otilm.core.container;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;

/**
 * What an uploaded file holds.
 *
 * @param digest the lowercase hex SHA-256 of the file
 * @param entries the file's entries, in file order
 */
public record Container(String digest, List<ContainerEntry> entries) {

    public Container {
        entries = List.copyOf(entries);
    }

    /**
     * The entry of the reference.
     *
     * @param reference an entry reference
     * @return the entry, or nothing when the file holds no entry of that reference
     */
    public Optional<ContainerEntry> entry(String reference) {
        return entries.stream().filter(entry -> entry.reference().equals(reference)).findFirst();
    }

    /** Overwrites every key the entries keep. */
    public void clear() {
        for (ContainerEntry entry : entries) {
            if (entry instanceof KeyEntry key) {
                Arrays.fill(key.keyFile(), (byte) 0);
            }
        }
    }
}
