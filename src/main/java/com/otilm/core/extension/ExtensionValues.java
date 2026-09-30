package com.otilm.core.extension;

import com.fasterxml.jackson.databind.JsonNode;
import com.otilm.api.exception.ValidationException;
import java.util.Optional;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Encodes a DER extension's value against the ASN.1 module registered for its OID. Every path a value takes to a
 * certificate or a connector goes through here, so a value written out in JSON becomes the same bytes wherever it is
 * carried.
 */
public final class ExtensionValues {

    private static final Logger logger = LoggerFactory.getLogger(ExtensionValues.class);

    private ExtensionValues() {
    }

    /**
     * The DER of a value that was written out, or empty when it was handed over as base64 DER, which the caller reads
     * as bytes.
     *
     * @throws ValidationException when the value is written but malformed, the extension has no module or one that
     * cannot be read, or the value does not fit the type
     */
    public static Optional<byte[]> encodeWritten(String oid, String value) {
        return JerCodec.tryParse(value).map(written -> encode(oid, written));
    }

    public static byte[] encode(String oid, JsonNode written) {
        ExtensionType type;
        try {
            type = ExtensionTypes.resolve(oid).orElse(null);
        } catch (ValidationException e) {
            // A module written straight into the database, or saved before the reader tightened, must not turn
            // every request for this extension into a 500. The cause is logged for whoever has to tell malformed
            // stored data from a defect; the requester's message cannot say which.
            logger.warn("Registered ASN.1 module for extension {} could not be read", oid, e);
            throw new ValidationException(
                    "Extension value cannot be checked: the registered ASN.1 module for extension %s is not readable"
                            .formatted(oid));
        }
        if (type == null) {
            throw new ValidationException(
                    "Extension %s has no registered ASN.1 module, so its value must be base64-encoded DER"
                            .formatted(oid));
        }
        try {
            return JerCodec.encode(written, type);
        } catch (ValidationException e) {
            throw new ValidationException("Invalid value for extension %s: %s".formatted(oid, e.getMessage()));
        }
    }
}
