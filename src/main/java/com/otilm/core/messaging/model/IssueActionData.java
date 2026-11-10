package com.otilm.core.messaging.model;

import java.util.Map;
import java.util.UUID;

/**
 * The data of an ISSUE action: the certificate request it was queued for. A registration whose completion was undone,
 * or whose issuance approval was rejected, can take another completion before an earlier action or decision arrives, so
 * those must not act on the request they find. An approval keeps the action's data, so its decision names the same
 * request.
 *
 * @param certificateRequestUuid the request the action was queued for
 */
public record IssueActionData(UUID certificateRequestUuid) {

    private static final String CERTIFICATE_REQUEST_UUID = "certificateRequestUuid";

    /**
     * The request an ISSUE action's data names: the record itself, or the JSON object it becomes on the broker and in
     * an approval. Data that names none, such as that of an action queued before this record, gives null.
     */
    public static UUID certificateRequestUuidOf(Object data) {
        if (data instanceof IssueActionData issueActionData) {
            return issueActionData.certificateRequestUuid();
        }
        if (data instanceof Map<?, ?> json
                && json.get(CERTIFICATE_REQUEST_UUID) instanceof String certificateRequestUuid) {
            return UUID.fromString(certificateRequestUuid);
        }
        return null;
    }
}
