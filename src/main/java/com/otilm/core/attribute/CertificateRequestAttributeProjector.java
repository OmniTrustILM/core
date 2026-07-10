package com.otilm.core.attribute;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.common.attribute.common.properties.DataAttributeProperties;
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
import org.bouncycastle.asn1.x509.Extension;

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
     * ValidationException is thrown when an extension OID would be mapped more than once (RFC 5280).
     *
     * @param definitions v3 attribute definitions carrying {@link FieldMapping}
     * @param values      request-time attribute values
     * @throws ValidationException when a non-list attribute supplies multiple values,
     *                             when a multi-valued  attribute maps to an EXTENSION field,
     *                             when the same extension OID is mapped by more than one field,
     *                             or when SAN entries collide with an explicit mapping to the subjectAltName extension OID
     * @return populated {@link X509RequestContent}; never null
     */
    public static X509RequestContent project(List<DataAttributeV3> definitions, List<? extends RequestAttribute> values) {
        Map<UUID, List<String>> valuesByUuid = extractStringValues(values);
        ProjectionSink sink = new ProjectionSink();

        for (DataAttributeV3 def : definitions) {
            FieldMapping fm = def.getFieldMapping();
            List<String> attributeValues = getValuesFromMapping(def, fm, valuesByUuid);
            if (attributeValues.isEmpty()) continue;
            rejectMultiValuedNonListAttribute(def, attributeValues);

            for (MappedField field : sortFields(fm)) {
                applyMappedField(field, attributeValues, def, sink);
            }
        }

        rejectSanAndExplicitExtensionCollision(sink);

        X509RequestContent content = new X509RequestContent();
        content.setCertificateType(CertificateType.X509);
        content.setSubject(sink.subject.isEmpty() ? null : sink.subject);
        content.setSubjectAltNames(sink.subjectAltNames.isEmpty() ? null : sink.subjectAltNames);
        content.setExtensions(sink.extensions.isEmpty() ? null : sink.extensions);
        return content;
    }

    /** OID of the subjectAltName extension; SAN entries render into this OID (RFC 5280 §4.2.1.6). */
    private static final String SUBJECT_ALT_NAME_OID = Extension.subjectAlternativeName.getId();

    /**
     * Rejects a non-list attribute that carries more than one value.
     */
    private static void rejectMultiValuedNonListAttribute(DataAttributeV3 def, List<String> attributeValues) {
        if (attributeValues.size() <= 1) return;
        DataAttributeProperties props = def.getProperties();
        if (props != null && !props.isList()) {
            throw new ValidationException(
                    "Attribute '%s' is not defined as a list but supplies %d values; a non-list attribute must map to at most one value"
                            .formatted(def.getName(), attributeValues.size()));
        }
    }

    /**
     * Rejects mapping SAN entries alongside an explicit extension mapping to the subjectAltName OID.
     * Both would render into the same {@code subjectAltName} extension, which may appear only once (RFC 5280).
     */
    private static void rejectSanAndExplicitExtensionCollision(ProjectionSink sink) {
        if (!sink.subjectAltNames.isEmpty() && sink.seenExtensionOids.contains(SUBJECT_ALT_NAME_OID)) {
            throw new ValidationException(
                    "Subject alternative names are mapped both as SAN entries and as an explicit extension OID %s; the subjectAltName extension may appear only once (RFC 5280)"
                            .formatted(SUBJECT_ALT_NAME_OID));
        }
    }

    private static List<MappedField> sortFields(FieldMapping fm) {
        return fm.getFields().stream()
                .sorted(Comparator.comparingInt(f -> f.getOrder() != null ? f.getOrder() : 0))
                .toList();
    }

    private static void applyMappedField(MappedField field, List<String> attributeValues, DataAttributeV3 def, ProjectionSink sink) {
        switch (field) {
            case RdnMappedField rdn -> {
                for (String value : attributeValues) {
                    sink.subject.add(new RdnEntry(rdn.getRdn(), value));
                }
            }
            case SanMappedField san -> {
                for (String value : attributeValues) {
                    sink.subjectAltNames.add(toGeneralNameEntry(san, value));
                }
            }
            case ExtensionMappedField ext -> projectExtension(ext, attributeValues, def, sink);
            default ->
                    throw new IllegalStateException("Unexpected MappedField subtype: " + field.getClass().getSimpleName());
        }
    }

    private static GeneralNameEntry toGeneralNameEntry(SanMappedField san, String value) {
        String otherNameOid = san.getGeneralNameType() == GeneralNameType.OTHER_NAME ? san.getOtherNameOid() : null;
        return new GeneralNameEntry(san.getGeneralNameType(), value, otherNameOid, san.getOtherNameValueEncoding());
    }

    private static void projectExtension(ExtensionMappedField ext, List<String> attributeValues, DataAttributeV3 def, ProjectionSink sink) {
        // An extension may appear only once in a request (RFC 5280).
        if (attributeValues.size() != 1) {
            throw new ValidationException(
                    "Attribute '%s' supplies %d values for certificate extension OID %s; an extension must map to exactly one value (RFC 5280)"
                            .formatted(def.getName(), attributeValues.size(), ext.getExtensionOid()));
        }
        if (!sink.seenExtensionOids.add(ext.getExtensionOid())) {
            throw new ValidationException(
                    "Certificate extension OID %s is mapped by more than one attribute field; an extension may appear only once (RFC 5280)"
                            .formatted(ext.getExtensionOid()));
        }
        sink.extensions.add(toRequestedExtension(ext.getExtensionOid(), attributeValues.getFirst()));
    }

    /** Mutable accumulator for the entries projected across all definitions, plus the extension OIDs already emitted. */
    private static final class ProjectionSink {
        final List<RdnEntry> subject = new ArrayList<>();
        final List<GeneralNameEntry> subjectAltNames = new ArrayList<>();
        final List<RequestedExtension> extensions = new ArrayList<>();
        final Set<String> seenExtensionOids = new HashSet<>();
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
