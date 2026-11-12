package com.otilm.core.certificate.type;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import org.springframework.stereotype.Component;

/** Finds the handler of a certificate type, by its code or by recognising the content of an uploaded certificate. */
@Component
public class CertificateTypeHandlerRegistry {

    private final Map<String, CertificateTypeHandler> handlersByTypeCode = new LinkedHashMap<>();

    public CertificateTypeHandlerRegistry(List<CertificateTypeHandler> handlers) {
        for (CertificateTypeHandler handler : handlers) {
            CertificateTypeHandler registered = handlersByTypeCode.putIfAbsent(handler.typeCode(), handler);
            if (registered != null) {
                throw new IllegalStateException(
                        "Two certificate type handlers are registered for the type " + handler.typeCode() + ": "
                                + registered.getClass().getName() + " and " + handler.getClass().getName());
            }
        }
    }

    public Optional<CertificateTypeHandler> find(String typeCode) {
        return Optional.ofNullable(handlersByTypeCode.get(typeCode));
    }

    /** @throws UnsupportedCertificateTypeException naming the type, when no handler is registered for it */
    public CertificateTypeHandler require(String typeCode) {
        return find(typeCode).orElseThrow(() -> UnsupportedCertificateTypeException.unknownType(typeCode));
    }

    /** The first handler that recognises the content as a certificate, with what it read. */
    public Optional<DetectedCertificate> detectCertificate(byte[] content) {
        for (CertificateTypeHandler handler : handlersByTypeCode.values()) {
            Optional<ParsedCertificate> parsed = handler.parseCertificate(content);
            if (parsed.isPresent()) {
                return Optional.of(new DetectedCertificate(handler, parsed.get()));
            }
        }
        return Optional.empty();
    }

    /** The first handler that recognises the content as a certificate request, with what it read. */
    public Optional<DetectedRequest> detectRequest(byte[] content) {
        for (CertificateTypeHandler handler : handlersByTypeCode.values()) {
            Optional<ParsedRequest> parsed = handler.parseRequest(content);
            if (parsed.isPresent()) {
                return Optional.of(new DetectedRequest(handler, parsed.get()));
            }
        }
        return Optional.empty();
    }

    public record DetectedCertificate(CertificateTypeHandler handler, ParsedCertificate certificate) {
    }

    public record DetectedRequest(CertificateTypeHandler handler, ParsedRequest request) {
    }
}
