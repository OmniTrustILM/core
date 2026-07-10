package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.BaseAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.mapping.ExtensionMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.MappedField;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.SanMappedField;
import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
import com.otilm.api.model.connector.v3.certificate.RequestedExtension;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;

import java.util.*;

/**
 * Pure-kernel projector: maps attribute values into a {@link X509RequestContent} by following
 * the {@link FieldMapping} declared on each {@link DataAttributeV3} definition.
 *
 * <p>No Spring context required; all methods are static.
 */
public class CertificateRequestAttributeProjector {

    private CertificateRequestAttributeProjector() {}

    /**
     * Projects the supplied attribute values into an {@link X509RequestContent} driven by the
     * {@code fieldMapping} on each definition.
     *
     * <p>Definitions without a {@code fieldMapping}, and values without a matching definition UUID,
     * are silently ignored.
     *
     * <p>String content values are projected, including multi-valued attributes mapped to RDN or SAN.
     * Within each definition, entries are ordered by {@code MappedField.order}, then by content-list
     * order within a field; across definitions they follow the order the definitions are supplied in.
     * Multi-valued attributes mapped to an {@code EXTENSION} field are rejected (RFC 5280).
     *
     * @param definitions v3 attribute definitions carrying {@link FieldMapping}
     * @param values      request-time attribute values
     * @throws ValidationException when a multi-valued attribute maps to an EXTENSION field
     * @return populated {@link X509RequestContent}; never null
     */
    public static X509RequestContent project(List<DataAttributeV3> definitions, List<? extends RequestAttribute> values) {
        Map<UUID, List<String>> valuesByUuid = extractStringValues(values);

        List<RdnEntry> subject = new ArrayList<>();
        List<GeneralNameEntry> subjectAltNames = new ArrayList<>();
        List<RequestedExtension> extensions = new ArrayList<>();

        for (DataAttributeV3 def : definitions) {
            FieldMapping fm = def.getFieldMapping();
            List<String> attributeValues = getValuesFromMapping(def, fm, valuesByUuid);
            if (attributeValues.isEmpty()) continue;

            List<MappedField> sortedFields = fm.getFields().stream()
                    .sorted(Comparator.comparingInt(f -> f.getOrder() != null ? f.getOrder() : 0))
                    .toList();

            for (MappedField field : sortedFields) {
                switch (field) {
                    case RdnMappedField rdn -> {
                        for (String value : attributeValues) {
                            subject.add(new RdnEntry(rdn.getRdn(), value));
                        }
                    }
                    case SanMappedField san -> {
                        for (String value : attributeValues) {
                            subjectAltNames.add(new GeneralNameEntry(san.getGeneralNameType(), value, san.getGeneralNameType() == GeneralNameType.OTHER_NAME ? san.getOtherNameOid() : null, san.getOtherNameValueEncoding()));
                        }
                    }
                    case ExtensionMappedField ext -> {
                        // An extension may appear only once in a request (RFC 5280).
                        if (attributeValues.size() != 1) {
                            throw new ValidationException(
                                    "Attribute '%s' supplies %d values for certificate extension OID %s; an extension must map to exactly one value (RFC 5280)"
                                            .formatted(def.getName(), attributeValues.size(), ext.getExtensionOid()));
                        }
                        extensions.add(toRequestedExtension(ext.getExtensionOid(), attributeValues.getFirst()));
                    }
                    default ->
                            throw new IllegalStateException("Unexpected MappedField subtype: " + field.getClass().getSimpleName());
                }
            }
        }

        X509RequestContent content = new X509RequestContent();
        content.setCertificateType(CertificateType.X509);
        content.setSubject(subject.isEmpty() ? null : subject);
        content.setSubjectAltNames(subjectAltNames.isEmpty() ? null : subjectAltNames);
        content.setExtensions(extensions.isEmpty() ? null : extensions);
        return content;
    }

    /**
     * Builds a {@link RequestedExtension} for a mapped extension value, honouring the
     * {@code CERTIFICATE_EXTENSION} OID registry's {@code defaultCritical} and {@code valueEncoding}
     * metadata when the OID is registered. Unregistered OIDs fall back to non-critical with no declared
     * encoding (the value is then treated as base64-encoded DER by the renderer).
     */
    private static RequestedExtension toRequestedExtension(String extensionOid, String value) {
        boolean critical = false;
        ExtensionValueEncoding encoding = null;
        Map<String, OidRecord> registry = OidHandler.getOidCache(OidCategory.CERTIFICATE_EXTENSION);
        OidRecord oidRecord = registry == null ? null : registry.get(extensionOid);
        if (oidRecord != null) {
            critical = Boolean.TRUE.equals(oidRecord.defaultCritical());
            encoding = oidRecord.valueEncoding();
        }
        return new RequestedExtension(extensionOid, critical, encoding, value);
    }

    private static List<String> getValuesFromMapping(DataAttributeV3 def, FieldMapping fm, Map<UUID, List<String>> valuesByUuid) {
        if (fm == null || fm.getFields() == null) {
            return List.of();
        }
        return valuesByUuid.getOrDefault(UUID.fromString(def.getUuid()), List.of());
    }

    /**
     * Extracts the string values of each attribute, keyed by attribute UUID, preserving content order.
     *
     * <p>Non-string content items are not projected.
     */
    private static Map<UUID, List<String>> extractStringValues(List<? extends RequestAttribute> attributes) {
        Map<UUID, List<String>> map = new HashMap<>();
        for (RequestAttribute attr : attributes) {
            List<?> content = attr.getContent();
            if (content == null || content.isEmpty()) continue;
            List<String> values = new ArrayList<>();
            for (Object item : content) {
                if (item instanceof BaseAttributeContentV3<?> v3 && v3.getData() instanceof String s) {
                    values.add(s);
                }
            }
            if (!values.isEmpty()) {
                map.put(attr.getUuid(), values);
            }
        }
        return map;
    }
}
