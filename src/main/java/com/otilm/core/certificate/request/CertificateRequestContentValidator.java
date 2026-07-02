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
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.TreeSet;
import java.util.function.BiPredicate;
import java.util.function.Function;

/**
 * Validates a parsed {@link X509RequestContent} against the resolved request-attribute definitions.
 */
@Slf4j
@Component
public class CertificateRequestContentValidator {

    /**
     * Parse the supplied CSR, validate against the resolved definitions, and throw on a strict-policy
     * failure. Whitelist enforcement is driven through {@link #validate(List, X509RequestContent, RequestAttributePolicy)}.
     */
    public void validate(CertificateRequest request, List<? extends BaseAttribute> definitions, boolean lenient)
            throws CertificateRequestValidationException {
        RequestAttributeValidationResult result;
        try {
            ParsedRequestContent parsed = X509RequestContentParser.parse(request);
            result = validate(definitions, parsed, new RequestAttributePolicy(!lenient, !lenient));
        } catch (RuntimeException e) {
            // Malformed ASN.1 surfaces as unchecked BC exceptions whose messages may carry internals; log it only.
            log.warn("Certificate request could not be parsed for request-attribute validation", e);
            throw new CertificateRequestValidationException(
                    "Certificate request could not be processed for validation", null);
        }
        if (result.hasErrors()) {
            throw new CertificateRequestValidationException(
                    "Uploaded certificate request does not satisfy the request-attribute policy",
                    result.getErrors());
        }
    }

    /**
     * Validates a full parse result.
     */
    public static RequestAttributeValidationResult validate(List<? extends BaseAttribute> definitions,
                                                            ParsedRequestContent parsed,
                                                            RequestAttributePolicy policy) {
        RequestAttributeValidationResult result = validate(definitions, parsed.content(), policy);
        if (policy.whitelist()) {
            for (String sanKind : parsed.unsupportedSans()) {
                recordViolation(result, policy,
                        "SAN %s cannot be represented for validation and is not allowed by the request-attribute set"
                                .formatted(sanKind));
            }
        }
        return result;
    }

    /**
     * Validates parsed CSR {@code content} against the resolved request-attribute {@code definitions}.
     *
     * For every X.509-mapped definition it:
     * <ol>
     *     <li>records a violation when a {@code required} mapped field has no matching target,</li>
     *     <li>runs the definition's constraints against matched RDN/SAN values, and</li>
     *     <li>when {@code policy.whitelist()} — records a violation for any RDN code / SAN type / extension OID present in the content but not mapped by the set</li>
     * </ol>
     *
     * Violations are routed by {@link RequestAttributePolicy#strict()}: errors in strict mode, warnings in lenient.
     * As a side effect it accumulates the mapped RDN/SAN/extension identifiers used by the whitelist pass.
     * Extension values are DER-encoded opaque blobs, so string constraints are not applied to them (see the loop).
     */
    public static RequestAttributeValidationResult validate(List<? extends BaseAttribute> definitions,
                                                            X509RequestContent content,
                                                            RequestAttributePolicy policy) {
        RequestAttributeValidationResult result = new RequestAttributeValidationResult();

        List<RdnEntry> subject = content.getSubject() == null ? List.of() : content.getSubject();
        List<GeneralNameEntry> sans = content.getSubjectAltNames() == null ? List.of() : content.getSubjectAltNames();
        List<RequestedExtension> extensions = content.getExtensions() == null ? List.of() : content.getExtensions();

        // Canonicalize to OID before comparing; case-insensitive so code casing never matters
        Map<String, String> codeToOid = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
        codeToOid.putAll(OidHandler.getCodeToOidMap());

        Set<String> mappedRdnKeys = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        Set<GeneralNameType> mappedSanTypes = new HashSet<>();
        Set<String> mappedOtherNameOids = new HashSet<>();
        Set<String> mappedExtensionOids = new HashSet<>();

        for (BaseAttribute def : definitions) {
            if (!(def instanceof DataAttributeV3 v3) || !isX509CertificateMapping(v3.getFieldMapping())) {
                continue;
            }
            boolean required = v3.getProperties() != null && v3.getProperties().isRequired();

            for (MappedField field : v3.getFieldMapping().getFields()) {
                List<String> matchedValues = collectMatchedValues(field, subject, sans, extensions,
                        mappedRdnKeys, mappedSanTypes, mappedOtherNameOids, mappedExtensionOids, codeToOid);

                if (required && matchedValues.isEmpty()) {
                    recordViolation(result, policy, "Missing required mapped field for attribute '%s' (%s)"
                            .formatted(label(v3), describe(field)));
                }
                // Extension values are stored as Base64(DER) by X509RequestContentParser; running the definition's
                // REGEXP/RANGE constraints against that opaque blob would reject valid CSRs, so only RDN/SAN
                // (logical string) values are constraint-checked. Extension presence is still enforced above.
                if (!matchedValues.isEmpty() && !(field instanceof ExtensionMappedField)) {
                    validateConstraints(v3, matchedValues, policy, result);
                }
            }
        }

        if (policy.whitelist()) {
            checkWhitelist(subject, sans, extensions, mappedRdnKeys, mappedSanTypes, mappedOtherNameOids,
                    mappedExtensionOids, codeToOid, policy, result);
        }
        return result;
    }

    private static boolean isX509CertificateMapping(FieldMapping mapping) {
        return mapping != null
                && mapping.getObjectType() == ObjectType.X509_CERTIFICATE
                && mapping.getFields() != null;
    }

    /**
     * Canonicalizes an RDN identifier to its OID form for matching: a dotted OID is returned as-is,
     * a known short code is resolved via {@code codeToOid}, and an unknown code falls back to itself.
     */
    private static String canonicalRdnKey(String rdn, Map<String, String> codeToOid) {
        if (rdn == null || rdn.isBlank()) {
            return null;
        }
        if (OidHandler.isOid(rdn)) {
            return rdn;
        }
        return codeToOid.getOrDefault(rdn, rdn);
    }

    /**
     * Routes a violation to {@link RequestAttributeValidationResult#addError(String)} when the
     * policy is strict, or to {@link RequestAttributeValidationResult#addWarning(String)} otherwise,
     * so every violation honors {@link RequestAttributePolicy#strict()} uniformly.
     */
    private static void recordViolation(RequestAttributeValidationResult result, RequestAttributePolicy policy,
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
                                                     Set<String> mappedOtherNameOids,
                                                     Set<String> mappedExtensionOids,
                                                     Map<String, String> codeToOid) {
        return switch (field) {
            case RdnMappedField rdn -> collectMatched(
                    canonicalRdnKey(rdn.getRdn(), codeToOid), mappedRdnKeys, subject,
                    (key, e) -> key.equalsIgnoreCase(canonicalRdnKey(e.getType(), codeToOid)), RdnEntry::getValue);
            // An otherName mapping claims only its own type-id OID, never the whole OTHER_NAME kind.
            case SanMappedField san when san.getGeneralNameType() == GeneralNameType.OTHER_NAME -> collectMatched(
                    san.getOtherNameOid(), mappedOtherNameOids, sans,
                    (oid, e) -> e.getType() == GeneralNameType.OTHER_NAME && oid.equals(e.getOtherNameOid()),
                    GeneralNameEntry::getValue);
            case SanMappedField san -> collectMatched(
                    san.getGeneralNameType(), mappedSanTypes, sans,
                    (type, e) -> type == e.getType(), GeneralNameEntry::getValue);
            case ExtensionMappedField ext -> collectMatched(
                    ext.getExtensionOid(), mappedExtensionOids, extensions,
                    (oid, e) -> oid.equals(e.getOid()), RequestedExtension::getValue);
            default -> List.of(); // non-X.509 mapped-field kinds carry no target here
        };
    }

    /**
     * Registers {@code key} as a mapped identifier (for the later whitelist pass) and returns every
     * source-entry value whose identifier matches it. A null key maps nothing and matches nothing.
     */
    private static <K, E> List<String> collectMatched(K key, Set<K> mappedKeys, List<E> entries,
                                                      BiPredicate<K, E> matches, Function<E, String> value) {
        if (key == null) {
            return List.of();
        }
        mappedKeys.add(key);
        List<String> values = new ArrayList<>();
        for (E entry : entries) {
            if (matches.test(key, entry)) {
                values.add(value.apply(entry));
            }
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
            recordViolation(result, policy, error.getErrorDescription());
        }
    }

    private static void checkWhitelist(List<RdnEntry> subject,
                                       List<GeneralNameEntry> sans,
                                       List<RequestedExtension> extensions,
                                       Set<String> mappedRdnKeys,
                                       Set<GeneralNameType> mappedSanTypes,
                                       Set<String> mappedOtherNameOids,
                                       Set<String> mappedExtensionOids,
                                       Map<String, String> codeToOid,
                                       RequestAttributePolicy policy,
                                       RequestAttributeValidationResult result) {
        for (RdnEntry e : subject) {
            String key = canonicalRdnKey(e.getType(), codeToOid);
            if (key == null || !mappedRdnKeys.contains(key)) {
                recordViolation(result, policy,
                        "Subject RDN '%s' is not allowed by the request-attribute set".formatted(e.getType()));
            }
        }
        for (GeneralNameEntry e : sans) {
            if (!isWhitelistedSan(e, mappedSanTypes, mappedOtherNameOids)) {
                recordViolation(result, policy, "SAN %s '%s' is not allowed by the request-attribute set"
                        .formatted(describeSan(e), e.getValue()));
            }
        }
        for (RequestedExtension e : extensions) {
            if (!mappedExtensionOids.contains(e.getOid())) {
                recordViolation(result, policy,
                        "Extension '%s' is not allowed by the request-attribute set".formatted(e.getOid()));
            }
        }
    }

    /** An otherName is allowed only when its own type-id OID is mapped; other kinds are allowed by type. */
    private static boolean isWhitelistedSan(GeneralNameEntry entry,
                                            Set<GeneralNameType> mappedSanTypes,
                                            Set<String> mappedOtherNameOids) {
        if (entry.getType() == GeneralNameType.OTHER_NAME) {
            return entry.getOtherNameOid() != null && mappedOtherNameOids.contains(entry.getOtherNameOid());
        }
        return mappedSanTypes.contains(entry.getType());
    }

    private static String describeSan(GeneralNameEntry entry) {
        if (entry.getType() == GeneralNameType.OTHER_NAME && entry.getOtherNameOid() != null) {
            return "otherName (type-id %s)".formatted(entry.getOtherNameOid());
        }
        return asn1FieldName(entry.getType());
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
