package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.key.normalization.DerivationBudget;
import java.util.List;

/** One container format; Spring collects every implementation and asks them in @Order order. */
interface ContainerFormat {

    /**
     * Whether the file is in this format, told from its content alone.
     *
     * @param file the uploaded file
     * @return whether this format reads the file
     */
    boolean recognizes(byte[] file);

    /**
     * What the file holds, in file order, before any key is opened. The keys the items carry are copies, which the
     * format overwrites itself when it refuses the file.
     *
     * @param file the uploaded file, which stays the caller's
     * @param passphrase the passphrase that opens the file, an empty one when the caller gave none
     * @param budget the budget of the file, charged every key derivation the format needs
     * @return the certificates, keys and certificate requests the file holds, and whether the passphrase verified it
     * @throws ValidationException with a fixed message when the file cannot be read
     */
    Contents read(byte[] file, Passphrase passphrase, DerivationBudget budget);

    /**
     * What a format read from a file.
     *
     * @param items the certificates, keys and certificate requests the file holds, in file order
     * @param verified whether the file's integrity was verified with the passphrase, so that a key the passphrase does
     * not open is under a passphrase of its own
     */
    record Contents(List<RawItem> items, boolean verified) {
    }
}
