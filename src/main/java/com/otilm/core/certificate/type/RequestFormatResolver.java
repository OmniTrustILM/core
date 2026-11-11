package com.otilm.core.certificate.type;

import com.otilm.api.model.core.certificate.CertificateType;
import com.otilm.api.model.core.enums.CertificateRequestFormat;
import org.springframework.stereotype.Component;

/** Gives a request without a format the default format of its certificate type. */
@Component
public class RequestFormatResolver {

    private final CertificateTypeHandlerRegistry registry;

    public RequestFormatResolver(CertificateTypeHandlerRegistry registry) {
        this.registry = registry;
    }

    /**
     * @param requested the format the client named, or null
     * @param type the type of the certificate the request is for; X.509 when null
     * @throws UnsupportedCertificateTypeException when the format is absent and no handler is registered for the type
     */
    public CertificateRequestFormat resolve(CertificateRequestFormat requested, CertificateType type) {
        if (requested != null) {
            return requested;
        }
        CertificateType effectiveType = type != null ? type : CertificateType.X509;
        return registry.require(effectiveType.getCode()).defaultRequestFormat();
    }
}
