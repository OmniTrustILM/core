package com.otilm.core.events.handlers.discovery;

/**
 * How the platform finished handling one discovered-certificate row.
 *
 * <p>
 * Every value except {@link #NOT_ATTEMPTED} means the row reached a verdict, whether or not that verdict was a clean
 * import.
 */
public enum DiscoveryCertificateOutcome {

    /** Imported, or resolved to a certificate a concurrent caller had already committed. */
    IMPORTED,

    /** An ignore trigger matched, so no certificate was created. Not a failure. */
    IGNORED,

    /** The certificate could not be built from the discovered content. */
    ENTITY_CREATION_FAILED,

    /** The import transaction rolled back, so the certificate is absent from the inventory. */
    IMPORT_ROLLED_BACK,

    /** The certificate was imported, but its public key could not be associated with it. */
    KEY_ASSOCIATION_FAILED,

    /** The row never reached a verdict — interrupted, cancelled, or otherwise abandoned. */
    NOT_ATTEMPTED
}
