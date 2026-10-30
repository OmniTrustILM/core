package com.otilm.core.events.handlers.discovery;

import com.otilm.core.dao.entity.Certificate;

/**
 * The result of importing one discovered certificate.
 *
 * @param certificate the surviving certificate, always the persisted one. When this caller lost the insert race it is
 * the winner's row, carrying a different UUID from the entity this caller built — so everything derived downstream must
 * come from here.
 */
public record DiscoveredCertificateImport(Certificate certificate) {
}
