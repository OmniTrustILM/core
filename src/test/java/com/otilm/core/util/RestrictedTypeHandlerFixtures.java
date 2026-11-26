package com.otilm.core.util;

import com.otilm.api.model.core.certificate.CertificateOperation;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.certificate.type.X509CertificateTypeHandler;
import java.util.EnumSet;
import java.util.List;

import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.spy;

/** Registries in which X.509 lacks an operation, for tests of what Core does with a type that does not support it. */
public final class RestrictedTypeHandlerFixtures {

    private RestrictedTypeHandlerFixtures() {
    }

    /** A registry whose only handler is the X.509 one, declaring every operation except the given one. */
    public static CertificateTypeHandlerRegistry registryWithX509Lacking(X509CertificateTypeHandler x509Handler,
            CertificateOperation unsupported) {
        X509CertificateTypeHandler restricted = spy(x509Handler);
        doReturn(EnumSet.complementOf(EnumSet.of(unsupported))).when(restricted).supportedOperations();
        return new CertificateTypeHandlerRegistry(List.of(restricted));
    }
}
