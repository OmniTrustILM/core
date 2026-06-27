package com.otilm.core.attribute;

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
import org.jspecify.annotations.Nullable;

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
     * @param definitions v3 attribute definitions carrying {@link FieldMapping}
     * @param values      request-time attribute values (one per attribute)
     * @return populated {@link X509RequestContent}; never null
     */
    public static X509RequestContent project(List<DataAttributeV3> definitions, List<? extends RequestAttribute> values) {
        Map<UUID, String> valueByUuid = extractStringValues(values);

        List<RdnEntry> subject = new ArrayList<>();
        List<GeneralNameEntry> subjectAltNames = new ArrayList<>();
        List<RequestedExtension> extensions = new ArrayList<>();

        for (DataAttributeV3 def : definitions) {
            FieldMapping fm = def.getFieldMapping();
            String value = getValueFromMapping(def, fm, valueByUuid);
            if (value == null) continue;

            List<MappedField> sortedFields = fm.getFields().stream()
                    .sorted(Comparator.comparingInt(f -> f.getOrder() != null ? f.getOrder() : 0))
                    .toList();

            for (MappedField field : sortedFields) {
                switch (field) {
                    case RdnMappedField rdn ->
                            subject.add(new RdnEntry(rdn.getRdn(), value));
                    case SanMappedField san ->
                            subjectAltNames.add(new GeneralNameEntry(san.getGeneralNameType(), value, san.getGeneralNameType() == GeneralNameType.OTHER_NAME ? san.getOtherNameOid() : null, san.getOtherNameValueEncoding()));
                    case ExtensionMappedField ext ->
                            extensions.add(toRequestedExtension(ext.getExtensionOid(), value));
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

    private static @Nullable String getValueFromMapping(DataAttributeV3 def, FieldMapping fm, Map<UUID, String> valueByUuid) {
        if (fm == null || fm.getFields() == null) return null;

        String value = valueByUuid.get(UUID.fromString(def.getUuid()));
        if (value == null) return null;
        return value;
    }

    private static Map<UUID, String> extractStringValues(List<? extends RequestAttribute> attributes) {
        Map<UUID, String> map = new HashMap<>();
        for (RequestAttribute attr : attributes) {
            List<?> content = attr.getContent();
            if (content == null || content.isEmpty()) continue;
            Object first = content.getFirst();
            if (first instanceof BaseAttributeContentV3<?> v3 && v3.getData() instanceof String s) {
                map.put(attr.getUuid(), s);
            }
        }
        return map;
    }
}
