package com.otilm.core.certificate.request;

import com.otilm.api.exception.CertificateRequestValidationException;
import com.otilm.api.exception.ValidationError;
import com.otilm.api.model.common.attribute.common.AttributeContent;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.content.StringAttributeContentV3;
import com.otilm.api.model.common.attribute.v3.mapping.ExtensionMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.FieldMapping;
import com.otilm.api.model.common.attribute.v3.mapping.MappedField;
import com.otilm.api.model.common.attribute.v3.mapping.ObjectType;
import com.otilm.api.model.common.attribute.v3.mapping.RdnMappedField;
import com.otilm.api.model.common.attribute.v3.mapping.SanMappedField;
import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
import com.otilm.api.model.connector.v3.certificate.RequestedExtension;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.core.model.request.CertificateRequest;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.util.AttributeDefinitionUtils;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Validates a parsed {@link X509RequestContent} against the resolved request-attribute definitions.
 */
@Component
public class CertificateRequestContentValidator {

    /**
     * Parse the supplied CSR, validate against the resolved definitions, and throw on a strict-policy
     * failure. Whitelist enforcement is driven through {@link #validate(List, X509RequestContent, RequestAttributePolicy)}.
     */
    public void validate(CertificateRequest request, List<? extends BaseAttribute> definitions, boolean lenient)
            throws CertificateRequestValidationException {
        X509RequestContent content = X509RequestContentParser.parse(request);
        RequestAttributeValidationResult result =
                validate(definitions, content, new RequestAttributePolicy(!lenient, !lenient));
        if (result.hasErrors()) {
            throw new CertificateRequestValidationException(
                    "Uploaded certificate request does not satisfy the request-attribute policy",
                    result.getErrors());
        }
    }

    public static RequestAttributeValidationResult validate(List<? extends BaseAttribute> definitions,
                                                            X509RequestContent content,
                                                            RequestAttributePolicy policy) {
        RequestAttributeValidationResult result = new RequestAttributeValidationResult();

        List<RdnEntry> subject = content.getSubject() == null ? List.of() : content.getSubject();
        List<GeneralNameEntry> sans = content.getSubjectAltNames() == null ? List.of() : content.getSubjectAltNames();
        List<RequestedExtension> extensions = content.getExtensions() == null ? List.of() : content.getExtensions();

        // Canonicalize to OID before comparing
        Map<String, String> codeToOid = OidHandler.getCodeToOidMap();

        Set<String> mappedRdnKeys = new HashSet<>();
        Set<GeneralNameType> mappedSanTypes = new HashSet<>();
        Set<String> mappedExtensionOids = new HashSet<>();

        for (BaseAttribute def : definitions) {
            if (!(def instanceof DataAttributeV3 v3) || v3.getFieldMapping() == null) {
                continue;
            }
            FieldMapping mapping = v3.getFieldMapping();
            if (mapping.getObjectType() != ObjectType.X509_CERTIFICATE || mapping.getFields() == null) {
                continue;
            }
            boolean required = v3.getProperties() != null && v3.getProperties().isRequired();

            for (MappedField field : mapping.getFields()) {
                List<String> matchedValues = collectMatchedValues(field, subject, sans, extensions,
                        mappedRdnKeys, mappedSanTypes, mappedExtensionOids, codeToOid);

                if (required && matchedValues.isEmpty()) {
                    record(result, policy, "Missing required mapped field for attribute '%s' (%s)"
                            .formatted(label(v3), describe(field)));
                }
                if (!matchedValues.isEmpty()) {
                    validateConstraints(v3, matchedValues, policy, result);
                }
            }
        }

        if (policy.whitelist()) {
            checkWhitelist(subject, sans, extensions, mappedRdnKeys, mappedSanTypes, mappedExtensionOids,
                    codeToOid, policy, result);
        }
        return result;
    }

    /**
     * Canonicalizes an RDN identifier to its OID form for matching: a dotted OID is returned as-is,
     * a known short code is resolved via {@code codeToOid}, and an unknown code falls back to itself
     * (so code-vs-code comparison still works when the OID registry is unseeded).
     */
    private static String canonicalRdnKey(String rdn, Map<String, String> codeToOid) {
        if (rdn == null || rdn.isBlank()) {
            return null;
        }
        if (OidHandler.isOid(rdn)) {
            return rdn;
        }
        for (Map.Entry<String, String> e : codeToOid.entrySet()) {
            if (e.getKey().equalsIgnoreCase(rdn)) {
                return e.getValue();
            }
        }
        return rdn;
    }

    /**
     * Routes a violation to {@link RequestAttributeValidationResult#addError(String)} when the
     * policy is strict, or to {@link RequestAttributeValidationResult#addWarning(String)} otherwise,
     * so every violation honors {@link RequestAttributePolicy#strict()} uniformly.
     */
    private static void record(RequestAttributeValidationResult result, RequestAttributePolicy policy,
                               String message) {
        if (policy.strict()) {
            result.addError(message);
        } else {
            result.addWarning(message);
        }
    }

    private static List<String> collectMatchedValues(MappedField field,
                                                     List<RdnEntry> subject,
                                                     List<GeneralNameEntry> sans,
                                                     List<RequestedExtension> extensions,
                                                     Set<String> mappedRdnKeys,
                                                     Set<GeneralNameType> mappedSanTypes,
                                                     Set<String> mappedExtensionOids,
                                                     Map<String, String> codeToOid) {
        List<String> values = new ArrayList<>();
        switch (field) {
            case RdnMappedField rdn -> {
                String key = canonicalRdnKey(rdn.getRdn(), codeToOid);
                if (key != null) {
                    mappedRdnKeys.add(key);
                    for (RdnEntry e : subject) {
                        if (key.equalsIgnoreCase(canonicalRdnKey(e.getType(), codeToOid))) {
                            values.add(e.getValue());
                        }
                    }
                }
            }
            case SanMappedField san -> {
                GeneralNameType type = san.getGeneralNameType();
                if (type != null) {
                    mappedSanTypes.add(type);
                    for (GeneralNameEntry e : sans) {
                        if (type == e.getType()) {
                            values.add(e.getValue());
                        }
                    }
                }
            }
            case ExtensionMappedField ext -> {
                String oid = ext.getExtensionOid();
                if (oid != null) {
                    mappedExtensionOids.add(oid);
                    for (RequestedExtension e : extensions) {
                        if (oid.equals(e.getOid())) {
                            values.add(e.getValue());
                        }
                    }
                }
            }
            default -> { /* non-X.509 mapped-field kinds carry no target here */ }
        }
        return values;
    }

    private static void validateConstraints(DataAttributeV3 def, List<String> values,
                                            RequestAttributePolicy policy, RequestAttributeValidationResult result) {
        List<AttributeContent> contents = new ArrayList<>(values.size());
        for (String v : values) {
            contents.add(new StringAttributeContentV3(v));
        }
        for (ValidationError error : AttributeDefinitionUtils.validateConstraints(def, contents)) {
            record(result, policy, error.getErrorDescription());
        }
    }

    private static void checkWhitelist(List<RdnEntry> subject,
                                       List<GeneralNameEntry> sans,
                                       List<RequestedExtension> extensions,
                                       Set<String> mappedRdnKeys,
                                       Set<GeneralNameType> mappedSanTypes,
                                       Set<String> mappedExtensionOids,
                                       Map<String, String> codeToOid,
                                       RequestAttributePolicy policy,
                                       RequestAttributeValidationResult result) {
        for (RdnEntry e : subject) {
            String key = canonicalRdnKey(e.getType(), codeToOid);
            if (mappedRdnKeys.stream().noneMatch(c -> c.equalsIgnoreCase(key))) {
                record(result, policy,
                        "Subject RDN '%s' is not allowed by the request-attribute set".formatted(e.getType()));
            }
        }
        for (GeneralNameEntry e : sans) {
            if (!mappedSanTypes.contains(e.getType())) {
                record(result, policy, "SAN %s '%s' is not allowed by the request-attribute set"
                        .formatted(asn1FieldName(e.getType()), e.getValue()));
            }
        }
        for (RequestedExtension e : extensions) {
            if (!mappedExtensionOids.contains(e.getOid())) {
                record(result, policy,
                        "Extension '%s' is not allowed by the request-attribute set".formatted(e.getOid()));
            }
        }
    }

    private static String label(DataAttributeV3 def) {
        if (def.getProperties() != null && def.getProperties().getLabel() != null) {
            return def.getProperties().getLabel();
        }
        return def.getName();
    }

    /**
     * Maps a {@link GeneralNameType} to the BouncyCastle ASN.1 {@code GeneralName} field name used
     * in error messages, mirroring {@code X509RequestContentParser}'s inverse mapping so whitelist
     * violations are reported using the same vocabulary as the rest of the CSR-parsing pipeline.
     */
    private static String asn1FieldName(GeneralNameType type) {
        return switch (type) {
            case EMAIL -> "rfc822Name";
            case DNS -> "dNSName";
            case DIRECTORY_NAME -> "directoryName";
            case URI -> "uniformResourceIdentifier";
            case IP -> "iPAddress";
            case REGISTERED_ID -> "registeredID";
            // Unreachable in practice: X509RequestContentParser filters otherName SANs before they
            // reach the validator. Retained for switch exhaustiveness over GeneralNameType.
            case OTHER_NAME -> "otherName";
        };
    }

    private static String describe(MappedField field) {
        return switch (field) {
            case RdnMappedField rdn -> "RDN " + rdn.getRdn();
            case SanMappedField san ->
                    "SAN " + (san.getGeneralNameType() == null ? "?" : asn1FieldName(san.getGeneralNameType()));
            case ExtensionMappedField ext -> "extension " + ext.getExtensionOid();
            default -> field.getClass().getSimpleName();
        };
    }
}
