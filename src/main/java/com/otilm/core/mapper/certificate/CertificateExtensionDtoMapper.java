package com.otilm.core.mapper.certificate;

import com.otilm.api.model.core.certificate.CertificateExtensionDto;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.extension.ExtensionType;
import com.otilm.core.extension.ExtensionTypes;
import com.otilm.core.extension.JerDecoder;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CertificateExtensionDtoMapper {

    private static final Logger logger = LoggerFactory.getLogger(CertificateExtensionDtoMapper.class);

    private CertificateExtensionDtoMapper() {
    }

    /**
     * Lists every extension with its DER value and, for an OID the registry knows, its display name. {@code jer} is
     * filled when a module describes the extension and the value decodes against it, and left null otherwise, so one
     * extension that cannot be read does not hide the rest.
     */
    public static List<CertificateExtensionDto> toDtos(Extensions extensions) {
        List<CertificateExtensionDto> dtos = new ArrayList<>();
        if (extensions == null) {
            return dtos;
        }
        for (ASN1ObjectIdentifier oid : extensions.getExtensionOIDs()) {
            dtos.add(toDto(oid.getId(), extensions.getExtension(oid)));
        }
        return dtos;
    }

    private static CertificateExtensionDto toDto(String oid, Extension extension) {
        byte[] octets = extension.getExtnValue().getOctets();
        CertificateExtensionDto dto = new CertificateExtensionDto();
        dto.setOid(oid);
        dto.setName(displayName(oid));
        dto.setCritical(extension.isCritical());
        dto.setDer(Base64.getEncoder().encodeToString(octets));
        try {
            Optional<ExtensionType> type = ExtensionTypes.resolve(oid);
            if (type.isPresent()) {
                dto.setJer(JerDecoder.decode(octets, type.get()));
            }
        } catch (RuntimeException | StackOverflowError e) {
            // The decoder parses the whole value recursively; guard against stack exhaustion on pathologically nested
            // input.
            logger.warn("Extension {} is listed without its decoded form", oid, e);
        }
        return dto;
    }

    private static String displayName(String oid) {
        Map<String, OidRecord> registry = OidHandler.getOidCache(OidCategory.CERTIFICATE_EXTENSION);
        OidRecord entry = registry == null ? null : registry.get(oid);
        return entry == null ? null : entry.displayName();
    }
}
