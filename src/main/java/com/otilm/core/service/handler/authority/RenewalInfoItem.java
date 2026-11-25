package com.otilm.core.service.handler.authority;

import com.otilm.api.model.common.attribute.common.MetadataAttribute;
import java.util.List;

/**
 * A certificate to ask the authority's connector about.
 *
 * @param reference identifies the item in the request and its result
 * @param certificate base64 of the DER-encoded certificate
 * @param meta the connector's stored metadata of the certificate
 */
public record RenewalInfoItem(String reference, String certificate, List<MetadataAttribute> meta) {
}
