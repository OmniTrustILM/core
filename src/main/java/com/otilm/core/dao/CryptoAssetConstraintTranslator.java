package com.otilm.core.dao;

import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import org.hibernate.exception.ConstraintViolationException;

/**
 * Turns a cryptographic-asset constraint violation into a sentence that is safe to hand to a caller.
 *
 * <p>
 * The translation reads the violated <b>constraint name</b> and nothing else. PostgreSQL puts the offending row in the
 * error's {@code DETAIL} line -- {@code Key (uuid)=(...) is still referenced from table ...} -- and for
 * {@code crypto_asset} that row contains the identity key, whose whole protection is that it never leaves the database.
 * So this class never touches {@code getMessage()}, never reaches for the driver's {@code ServerErrorMessage}, and an
 * unrecognised constraint yields a fixed sentence rather than the exception's text.
 */
public final class CryptoAssetConstraintTranslator {

    /**
     * What each constraint means, in the caller's terms. Keys are the constraint names the migration declares, so a
     * renamed constraint degrades to {@link #GENERIC_REJECTION} rather than to a leak.
     */
    private static final Map<String, String> BY_CONSTRAINT = Map
            .ofEntries(
                    Map
                            .entry("crypto_asset_source_to_cbom_key",
                                    "The CBOM is still referenced by the cryptographic asset inventory. "
                                            + "Its asset sources must be detached before the CBOM can be deleted."),
                    Map
                            .entry("uq_crypto_asset_identity_key",
                                    "A cryptographic asset with the same identity is already in the inventory."),
                    Map
                            .entry("uq_crypto_asset_source",
                                    "This CBOM's contribution to the cryptographic asset is already recorded."),
                    Map
                            .entry("uq_crypto_asset_alias_absorbed",
                                    "An alias for that cryptographic asset already exists."),
                    Map
                            .entry("crypto_asset_alias_to_canonical_key",
                                    "The cryptographic asset an alias points at is not in the inventory."),
                    Map
                            .entry("ck_crypto_asset_alias_not_self",
                                    "An alias cannot point a cryptographic asset at itself."),
                    Map
                            .entry("crypto_asset_to_properties_source_key",
                                    "The recorded source of the asset's cryptographic properties is not one of its "
                                            + "sources."),
                    Map
                            .entry("uq_cbom_tombstone_serial_version",
                                    "That CBOM serial number and version is already recorded as deleted."),
                    Map
                            .entry("ck_crypto_asset_properties_pair",
                                    "A merged cryptographic properties payload must be stored together with its hash."),
                    // The two length bounds exist so a document that would otherwise fail at an index fails at the
                    // field instead. Without an entry here the refusal reads as a nameless constraint violation, and
                    // the bound achieves nothing an operator can act on.
                    Map
                            .entry("ck_crypto_asset_oid_length",
                                    "A cryptographic asset's object identifier is longer than 255 characters."),
                    Map
                            .entry("ck_crypto_asset_name_length",
                                    "A cryptographic asset's name is longer than 1024 characters."),
                    Map
                            .entry("ck_crypto_asset_asset_type",
                                    "That cryptographic asset type is not one this platform recognises."),
                    Map
                            .entry("ck_crypto_asset_identity_guard",
                                    "That cryptographic asset identity guard is not one this platform recognises."),
                    Map
                            .entry("ck_crypto_asset_pqc_verdict",
                                    "That post-quantum verdict is not one this platform recognises."),
                    Map
                            .entry("ck_cbom_asset_sync_state",
                                    "That CBOM asset sync state is not one this platform recognises."));

    static final String GENERIC_REJECTION = "The cryptographic asset inventory rejected the change: it would violate a "
            + "database constraint.";

    private CryptoAssetConstraintTranslator() {
    }

    /**
     * The constraint names this class explains, for the test that holds the map against the migration that declares
     * them. Package-private because it exists to be pinned, not to be called.
     */
    static Set<String> knownConstraintNames() {
        return BY_CONSTRAINT.keySet();
    }

    /**
     * The sentence this class would produce for {@code constraintName}, for a caller that refuses a value
     * <em>before</em> the statement runs rather than translating the database's refusal afterwards. A pre-check and the
     * constraint it anticipates must say the same thing to the operator, and the way to guarantee that is for both to
     * read it here.
     *
     * @return {@link #GENERIC_REJECTION} for a name this class does not explain
     */
    public static String explain(String constraintName) {
        return BY_CONSTRAINT.getOrDefault(constraintName, GENERIC_REJECTION);
    }

    /**
     * A caller-safe description of {@code failure}, whatever it turns out to be. Never derived from the exception's
     * message.
     */
    public static String describe(Throwable failure) {
        return constraintNameOf(failure).map(BY_CONSTRAINT::get).orElse(GENERIC_REJECTION);
    }

    /**
     * The violated constraint's bare name, if the failure carries one. Any schema qualification is dropped, and the
     * name is folded with {@link Locale#ROOT} so the lookup cannot depend on the platform locale.
     */
    public static Optional<String> constraintNameOf(Throwable failure) {
        for (Throwable cause = failure; cause != null; cause = cause.getCause()) {
            if (cause instanceof ConstraintViolationException violation && violation.getConstraintName() != null) {
                String name = violation.getConstraintName();
                return Optional
                        .of(name.substring(name.lastIndexOf('.') + 1).replace("\"", "").toLowerCase(Locale.ROOT));
            }
            if (cause.getCause() == cause) {
                break;
            }
        }
        return Optional.empty();
    }
}
