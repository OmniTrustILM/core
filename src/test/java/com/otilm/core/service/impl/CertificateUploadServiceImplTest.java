package com.otilm.core.service.impl;

import com.otilm.api.exception.ValidationException;
import com.otilm.core.certificate.type.CertificateTypeHandlerRegistry;
import com.otilm.core.certificate.type.X509CertificateTypeHandler;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.List;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

class CertificateUploadServiceImplTest {

    private CertificateUploadServiceImpl service;

    @BeforeEach
    void createServiceWithTheX509Handler() {
        service = new CertificateUploadServiceImpl();
        service
                .setCertificateTypeHandlerRegistry(
                        new CertificateTypeHandlerRegistry(List.of(new X509CertificateTypeHandler())));
    }

    @Test
    void refusesNamingThePemType_whenTheFirstPemObjectIsAPrivateKey() {
        // given — text precedes a private key, which a certificate in the same file follows
        String bundle = """
                Bag Attributes
                    friendlyName: holder
                -----BEGIN PRIVATE KEY-----
                AAAA
                -----END PRIVATE KEY-----
                -----BEGIN CERTIFICATE-----
                AAAA
                -----END CERTIFICATE-----
                """;
        String encodedBundle = Base64.getEncoder().encodeToString(bundle.getBytes(StandardCharsets.UTF_8));

        // when
        ThrowingCallable upload = () -> service.upload(encodedBundle, List.of(), true);

        // then
        assertThatThrownBy(upload).isInstanceOf(ValidationException.class).hasMessageContaining("PRIVATE KEY");
    }

    @Test
    void refusesAsAnUnsupportedFormat_whenTheContentIsNotACertificate() {
        // given
        String encodedGarbage = Base64
                .getEncoder()
                .encodeToString("not a certificate".getBytes(StandardCharsets.UTF_8));

        // when
        ThrowingCallable upload = () -> service.upload(encodedGarbage, List.of(), true);

        // then
        assertThatThrownBy(upload).isInstanceOf(ValidationException.class).hasMessageContaining("unsupported format");
    }
}
