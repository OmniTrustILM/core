package com.otilm.core.container;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.secret.Passphrase;
import com.otilm.core.key.normalization.DerivationBudget;
import java.util.List;
import org.springframework.stereotype.Component;

/**
 * Reads an uploaded file into the certificates, keys and certificate requests it holds, in memory, storing nothing and
 * calling no connector.
 *
 * <p>
 * The format is told from the file's content, never its name, by asking each format in turn. Every key is opened by the
 * key normalizer to learn what it is, and all the key derivations of one file together stay within one file's budget.
 * </p>
 *
 * <p>
 * No passphrase is read as an empty one, so that a file protected with an empty password opens without a passphrase, as
 * OpenSSL and keytool open it.
 * </p>
 */
@Component
public class ContainerReader {

    private final List<ContainerFormat> formats;

    private final ContainerAssembler assembler;

    /** A reader asking the formats in the order given, which is their {@code @Order} when Spring collects them. */
    ContainerReader(List<ContainerFormat> formats, ContainerAssembler assembler) {
        this.formats = formats;
        this.assembler = assembler;
    }

    /**
     * Reads the file into its entries; the file and passphrase stay the caller's to clear.
     *
     * @param file the uploaded file
     * @param passphrase the passphrase that opens the file, or {@code null} for a file without protection or protected
     * with an empty password
     * @return the file's digest and entries; the keys the entries keep are copies, which {@link Container#clear()}
     * overwrites
     * @throws ValidationException with a fixed message when the file cannot be read
     */
    public Container read(byte[] file, Passphrase passphrase) {
        DerivationBudget budget = DerivationBudget.forFile();
        Passphrase opening = opening(passphrase);
        ContainerFormat format = formats
                .stream()
                .filter(candidate -> candidate.recognizes(file))
                .findFirst()
                .orElseThrow(ContainerRefusal::notSupportedFormat);
        List<ContainerEntry> entries = assembler.assemble(format.read(file, opening, budget), opening, budget);
        return new Container(EntryReference.of(file), entries);
    }

    /**
     * The passphrase a file and the keys it holds are opened with, so that a key taken from the file opens as the
     * reader opened it.
     *
     * @param passphrase the passphrase the caller gave, or {@code null}
     * @return the passphrase given, or an empty one when none was given
     */
    public static Passphrase opening(Passphrase passphrase) {
        return passphrase != null ? passphrase : new Passphrase(new char[0]);
    }
}
