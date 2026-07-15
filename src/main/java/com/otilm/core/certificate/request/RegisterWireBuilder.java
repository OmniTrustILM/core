package com.otilm.core.certificate.request;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.connector.v3.certificate.CertificateExtension;
import com.otilm.api.model.connector.v3.certificate.CertificateRegistrationRequestDtoV3;
import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
import com.otilm.api.model.connector.v3.certificate.RequestedExtension;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.core.util.PlatformX500NameStyle;
import com.otilm.core.util.X509RequestContentRenderer;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Projects the operator-supplied flat identity into typed {@link X509RequestContent} and renders the v3 register
 * wire. Structured content rides the wire only when the connector advertises {@code CERTIFICATE_REQUEST_STRUCTURED}.
 */
public final class RegisterWireBuilder {

    private static final Logger logger = LoggerFactory.getLogger(RegisterWireBuilder.class);

    /** OpenSSL-convention textual SAN type prefixes (matched case-insensitively). */
    private static final Map<String, GeneralNameType> SAN_PREFIXES = Map.of(
            "dns", GeneralNameType.DNS,
            "ip", GeneralNameType.IP,
            "email", GeneralNameType.EMAIL,
            "uri", GeneralNameType.URI,
            "dirname", GeneralNameType.DIRECTORY_NAME,
            "rid", GeneralNameType.REGISTERED_ID,
            "othername", GeneralNameType.OTHER_NAME);

    private static final String OTHER_NAME_UTF8_TAG = "UTF8:";

    private RegisterWireBuilder() {
    }

    /**
     * Projects the operator-supplied flat registration identity into typed request content.
     *
     * @param subjectDn      RFC 4514 subject DN, may be blank (SAN-only identity per RFC 5280 §4.1.2.6)
     * @param subjectAltName textual SAN in OpenSSL convention ({@code DNS:foo,IP:1.2.3.4,email:x@y}), may be blank
     * @param extensions     structured extensions carrying base64 DER values, may be null
     * @throws ValidationException when the DN or SAN string is malformed
     */
    public static X509RequestContent buildContent(String subjectDn, String subjectAltName,
                                                  List<CertificateExtension> extensions) {
        X509RequestContent content = new X509RequestContent();
        content.setCertificateType(CertificateType.X509);
        content.setSubject(parseSubject(subjectDn));
        content.setSubjectAltNames(parseSubjectAltName(subjectAltName));
        content.setExtensions(mapExtensions(extensions));
        return content;
    }

    /**
     * Builds subject-only content for the connector-side identity override on a register-bound issue. The connector
     * resolves SAN and extensions from the replayed CA handle.
     */
    public static X509RequestContent buildIdentityContent(String subjectDn) {
        X509RequestContent content = new X509RequestContent();
        content.setCertificateType(CertificateType.X509);
        content.setSubject(parseSubject(subjectDn));
        return content;
    }

    /**
     * Renders the v3 register wire, choosing structured or flat form by the connector's
     * {@code CERTIFICATE_REQUEST_STRUCTURED} capability.
     */
    public static CertificateRegistrationRequestDtoV3 buildRegistration(X509RequestContent content,
                                                                        boolean connectorSupportsStructured) {
        CertificateRegistrationRequestDtoV3 dto = new CertificateRegistrationRequestDtoV3();
        dto.setSubjectDn(renderSubjectDn(content));
        dto.setSubjectAltName(renderSubjectAltName(content.getSubjectAltNames()));
        if (connectorSupportsStructured) {
            dto.setRequestContent(content);
        } else {
            // No structured wire carries the content here, so anything the flat wire cannot represent would be
            // silently dropped — fail closed rather than register an identity reduced below the operator's request.
            assertFlatRepresentable(content);
            dto.setExtensions(renderFlatExtensions(content.getExtensions()));
        }
        return dto;
    }

    // ── content building ────────────────────────────────────────────────────

    private static List<RdnEntry> parseSubject(String subjectDn) {
        try {
            return X509RequestContentParser.parseSubjectDn(subjectDn);
        } catch (IllegalArgumentException e) {
            // Keep the BouncyCastle parse message off the wire-facing exception (info-leak rule).
            throw new ValidationException("Invalid subject DN '%s'".formatted(subjectDn));
        }
    }

    private static List<GeneralNameEntry> parseSubjectAltName(String subjectAltName) {
        List<GeneralNameEntry> entries = new ArrayList<>();
        if (subjectAltName == null || subjectAltName.isBlank()) {
            return entries;
        }
        for (String segment : subjectAltName.split(",")) {
            String trimmed = segment.trim();
            if (!trimmed.isEmpty()) {
                appendSanSegment(entries, trimmed);
            }
        }
        return entries;
    }

    /** Parses one comma-split SAN segment: a typed entry, or a continuation of the previous entry's value. */
    private static void appendSanSegment(List<GeneralNameEntry> entries, String segment) {
        int colon = segment.indexOf(':');
        String prefix = colon > 0 ? segment.substring(0, colon) : null;
        GeneralNameType type = prefix == null ? null : SAN_PREFIXES.get(prefix.toLowerCase(Locale.ROOT));
        if (type != null) {
            entries.add(toGeneralNameEntry(type, segment.substring(colon + 1)));
            return;
        }
        if (prefix != null && prefix.matches("[A-Za-z0-9]+")) {
            throw new ValidationException(
                    "Unknown subject alternative name type prefix '%s' (expected one of DNS, IP, email, URI, dirName, RID, otherName)"
                            .formatted(prefix));
        }
        // No prefix: a continuation of the previous value whose text contains commas (e.g. dirName:CN=x,O=y).
        if (entries.isEmpty()) {
            throw new ValidationException(
                    "Subject alternative name segment '%s' has no type prefix (expected e.g. DNS:, IP:, email:)"
                            .formatted(segment));
        }
        GeneralNameEntry previous = entries.get(entries.size() - 1);
        previous.setValue(previous.getValue() + "," + segment);
    }

    private static GeneralNameEntry toGeneralNameEntry(GeneralNameType type, String value) {
        GeneralNameEntry entry = new GeneralNameEntry();
        entry.setType(type);
        if (type == GeneralNameType.OTHER_NAME) {
            int semicolon = value.indexOf(';');
            if (semicolon <= 0) {
                throw new ValidationException(
                        "otherName subject alternative name must use the 'otherName:<oid>;UTF8:<value>' form");
            }
            String tail = value.substring(semicolon + 1);
            if (!tail.regionMatches(true, 0, OTHER_NAME_UTF8_TAG, 0, OTHER_NAME_UTF8_TAG.length())) {
                throw new ValidationException(
                        "otherName subject alternative name supports only the UTF8 textual value form ('otherName:<oid>;UTF8:<value>')");
            }
            entry.setOtherNameOid(value.substring(0, semicolon).trim());
            entry.setValue(tail.substring(OTHER_NAME_UTF8_TAG.length()));
            entry.setValueEncoding(ExtensionValueEncoding.UTF8_STRING);
            return entry;
        }
        entry.setValue(value);
        return entry;
    }

    private static List<RequestedExtension> mapExtensions(List<CertificateExtension> extensions) {
        List<RequestedExtension> result = new ArrayList<>();
        if (extensions == null) {
            return result;
        }
        for (CertificateExtension extension : extensions) {
            RequestedExtension mapped = new RequestedExtension();
            mapped.setOid(extension.getOid());
            mapped.setCritical(extension.isCritical());
            mapped.setEncoding(ExtensionValueEncoding.DER);
            mapped.setValue(extension.getValueBase64());
            result.add(mapped);
        }
        return result;
    }

    // ── flat-wire rendering ─────────────────────────────────────────────────

    /**
     * Renders the RFC 4514 subject DN string for the given content, or null when it carries no subject.
     * Shared with the register orchestrator so the persisted placeholder DN matches the wire anchor exactly.
     */
    public static String renderSubjectDn(X509RequestContent content) {
        if (content.getSubject() == null || content.getSubject().isEmpty()) {
            return null;
        }
        try {
            X500Principal principal = X509RequestContentRenderer.toX500Principal(content);
            return X500Name.getInstance(PlatformX500NameStyle.DEFAULT, principal.getEncoded()).toString();
        } catch (IOException | IllegalArgumentException e) {
            // Keep the renderer/encoder message off the wire-facing exception (info-leak rule).
            throw new ValidationException("Unable to render subject DN from the certificate request content");
        }
    }

    private static String renderSubjectAltName(List<GeneralNameEntry> subjectAltNames) {
        if (subjectAltNames == null || subjectAltNames.isEmpty()) {
            return null;
        }
        List<String> parts = new ArrayList<>(subjectAltNames.size());
        for (GeneralNameEntry entry : subjectAltNames) {
            String rendered = renderGeneralName(entry);
            if (rendered != null) {
                parts.add(rendered);
            }
        }
        return parts.isEmpty() ? null : String.join(",", parts);
    }

    private static String renderGeneralName(GeneralNameEntry entry) {
        return switch (entry.getType()) {
            case DNS -> "DNS:" + entry.getValue();
            case IP -> "IP:" + entry.getValue();
            case EMAIL -> "email:" + entry.getValue();
            case URI -> "URI:" + entry.getValue();
            case DIRECTORY_NAME -> "dirName:" + entry.getValue();
            case REGISTERED_ID -> "RID:" + entry.getValue();
            case OTHER_NAME -> renderOtherName(entry);
        };
    }

    private static String renderOtherName(GeneralNameEntry entry) {
        if (entry.getValueEncoding() != null && entry.getValueEncoding() != ExtensionValueEncoding.UTF8_STRING) {
            logger.warn("otherName SAN {} has non-textual value encoding {} and cannot ride the flat "
                    + "subjectAltName string; it is carried only on the structured wire",
                    entry.getOtherNameOid(), entry.getValueEncoding());
            return null;
        }
        return "otherName:" + entry.getOtherNameOid() + ";UTF8:" + entry.getValue();
    }

    /**
     * Fails closed when projected content cannot be represented on the flat register wire.
     *
     * <p>Rejects a non-DER extension value, or an otherName SAN with a non-UTF8 encoding — throwing
     * rather than dropping it.
     *
     * <p><b>Only reached</b> for connectors without {@code CERTIFICATE_REQUEST_STRUCTURED}, where the
     * flat renderers would otherwise silently drop such entries (warn-log only) and register an identity
     * weaker than the operator asked for.
     *
     * <p>Flat operator input never trips this — {@link #buildContent} forces DER extensions and UTF8 otherNames.
     */
    public static void assertFlatRepresentable(X509RequestContent content) {
        if (content.getExtensions() != null) {
            for (RequestedExtension ext : content.getExtensions()) {
                if (ext.getEncoding() != null && ext.getEncoding() != ExtensionValueEncoding.DER) {
                    throw new ValidationException(("Extension %s has %s value encoding, which the flat register wire "
                            + "cannot represent; the authority must advertise CERTIFICATE_REQUEST_STRUCTURED")
                            .formatted(ext.getOid(), ext.getEncoding()));
                }
            }
        }
        if (content.getSubjectAltNames() != null) {
            for (GeneralNameEntry san : content.getSubjectAltNames()) {
                if (san.getType() == GeneralNameType.OTHER_NAME
                        && san.getValueEncoding() != null && san.getValueEncoding() != ExtensionValueEncoding.UTF8_STRING) {
                    throw new ValidationException(("otherName SAN %s has %s value encoding, which the flat register "
                            + "wire cannot represent; the authority must advertise CERTIFICATE_REQUEST_STRUCTURED")
                            .formatted(san.getOtherNameOid(), san.getValueEncoding()));
                }
            }
        }
    }

    private static List<CertificateExtension> renderFlatExtensions(List<RequestedExtension> extensions) {
        if (extensions == null || extensions.isEmpty()) {
            return null;
        }
        List<CertificateExtension> result = new ArrayList<>(extensions.size());
        for (RequestedExtension extension : extensions) {
            // null encoding means the value already carries base64 DER (contract default).
            if (extension.getEncoding() != null && extension.getEncoding() != ExtensionValueEncoding.DER) {
                logger.warn("Extension {} has non-DER value encoding {} and cannot ride the flat wire; "
                        + "it is carried only on the structured wire", extension.getOid(), extension.getEncoding());
                continue;
            }
            CertificateExtension flat = new CertificateExtension();
            flat.setOid(extension.getOid());
            flat.setCritical(Boolean.TRUE.equals(extension.getCritical()));
            flat.setValueBase64(extension.getValue());
            result.add(flat);
        }
        return result.isEmpty() ? null : result;
    }
}
