package com.otilm.core.model.discovery;

/**
 * The codes Core assigns to run messages it produces itself. A connector-reported problem carries the connector's own
 * code instead, straight from {@code DiscoveryErrorEvent}.
 *
 * <p>
 * The code names the <em>kind</em> of problem — what an operator or a support engineer matches on — and is what
 * aggregation and the per-code bound group by, so it must stay stable across releases and carry nothing run-specific
 * (see {@link DiscoveryMessageDraft}).
 *
 * <p>
 * Each code has exactly one producer, which owns the severity and the curated text that go with it.
 */
public enum DiscoveryMessageCode {

    /** A staged item the connector sent without the sequence that staging orders by. */
    ITEM_SEQUENCE_MISSING("itemSequenceMissing"),

    /** An item declared a certificate whose payload was not one. */
    CERTIFICATE_PAYLOAD_INVALID("certificatePayloadInvalid"),

    /** A discovered certificate that could not be staged; the message is the shaped reason. */
    CERTIFICATE_STAGING_FAILED("certificateStagingFailed"),

    /** A certificate the connector reported that never reached the inventory. */
    INVENTORY_GAP("inventoryGap"),

    /** A certificate imported without all of its public keys associated. */
    KEY_ASSOCIATION_GAP("keyAssociationGap"),

    /** A staged certificate that never reached a verdict either way. */
    CERTIFICATE_NOT_PROCESSED("certificateNotProcessed"),

    /** Per-certificate detail whose own write failed, leaving what is persisted knowingly incomplete. */
    BOOKKEEPING_INCOMPLETE("bookkeepingIncomplete"),

    /** Validation of the run's certificates was never requested. */
    VALIDATION_NOT_REQUESTED("validationNotRequested"),

    /** A processing batch that did not complete and went back for another attempt. */
    BATCH_PROCESSING_FAILED("batchProcessingFailed"),

    /** A processing batch that failed once its rows were already imported, so nothing is left to retry. */
    BATCH_PROCESSING_ABANDONED("batchProcessingAbandoned"),

    /** Stands in for a connector's own code when it reported an error without naming one. */
    CONNECTOR_ERROR("connectorError"),

    /** How the run ended; the message is the terminal reason and the severity follows the terminal status. */
    RUN_ENDED("runEnded"),

    /** A run metadata statement Core did not record: over the size cap, or malformed. */
    RUN_METADATA_NOT_RECORDED("runMetadataNotRecorded"),
    /** Stands in for everything a run had no room left to keep, whatever kind it was. */
    MESSAGES_SUPPRESSED("messagesSuppressed");

    private final String code;

    DiscoveryMessageCode(String code) {
        this.code = code;
    }

    public String code() {
        return code;
    }
}
