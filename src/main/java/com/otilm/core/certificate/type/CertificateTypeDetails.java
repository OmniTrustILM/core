package com.otilm.core.certificate.type;

import java.util.Map;

/**
 * The details only one certificate type has, as the API presents them beside the common ones.
 *
 * @param typeCode the code of the type the details belong to
 * @param values the detail values by name
 */
public record CertificateTypeDetails(String typeCode, Map<String, Object> values) {
}
