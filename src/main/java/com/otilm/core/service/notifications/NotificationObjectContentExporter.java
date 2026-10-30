package com.otilm.core.service.notifications;

import com.otilm.api.model.core.auth.Resource;

import java.util.Optional;
import java.util.UUID;

/**
 * Exports a resource's canonical content representation for the notification OBJECT_CONTENT category. The set of
 * registered exporters is the fail-closed whitelist: no resource's content is exportable unless an exporter is
 * deliberately registered for it. An implementation must export public material only (never key material, secrets, or
 * protected content), must have its permission requirements added to {@link NotificationDataCategoryGate} so enabling
 * the category is gated on them at configuration time, and must never activate silently for profiles that already have
 * the category enabled -- their operators were not gated against the new exporter's permissions.
 */
public interface NotificationObjectContentExporter {

    /** Resource key used to register this exporter; each resource may have only one exporter. */
    Resource resource();

    /** Wire format identifier of the exported content, e.g. {@code X509_DER_BASE64}. */
    String format();

    /**
     * The subject's content, or empty when the object does not exist or carries no content yet -- absence is
     * best-effort, never an error.
     */
    Optional<String> export(UUID objectUuid);
}
