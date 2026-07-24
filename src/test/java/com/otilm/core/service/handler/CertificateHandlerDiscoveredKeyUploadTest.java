package com.otilm.core.service.handler;

import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.dao.repository.CertificateRepository;
import com.otilm.core.service.CryptographicKeyInternalService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateHandlerDiscoveredKeyUploadTest {

    @Mock
    private CertificateRepository certificateRepository;

    @Mock
    private CryptographicKeyInternalService cryptographicKeyService;

    private CertificateHandler handler;
    private PublicKey publicKey;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException {
        handler = new CertificateHandler();
        handler.setCertificateRepository(certificateRepository);
        handler.setCryptographicKeyInternalService(cryptographicKeyService);

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        publicKey = generator.generateKeyPair().getPublic();
    }

    @Test
    void uploadDiscoveredCertificateKey_whenNoCommittedCertificate_skipsUploadAndAssociation() {
        List<UUID> uuids = List.of(UUID.randomUUID());
        when(cryptographicKeyService.findKeyByFingerprint(anyString())).thenReturn(null);
        when(certificateRepository.findFirstByUuidIn(uuids)).thenReturn(null);

        assertThatCode(() -> handler.uploadDiscoveredCertificateKey(publicKey, uuids))
                .doesNotThrowAnyException();

        verify(cryptographicKeyService, never()).uploadCertificatePublicKey(anyString(), any(), anyInt(), anyString());
        verify(certificateRepository, never()).setKeyUuid(any(), anyList());
    }

    @Test
    void uploadDiscoveredCertificateAltKey_whenNoCommittedCertificate_skipsUploadAndAssociation() {
        List<UUID> uuids = List.of(UUID.randomUUID());
        when(cryptographicKeyService.findKeyByFingerprint(anyString())).thenReturn(null);
        when(certificateRepository.findFirstByUuidIn(uuids)).thenReturn(null);

        assertThatCode(() -> handler.uploadDiscoveredCertificateAltKey(publicKey, uuids))
                .doesNotThrowAnyException();

        verify(cryptographicKeyService, never()).uploadCertificatePublicKey(anyString(), any(), anyInt(), anyString());
        verify(certificateRepository, never()).setAltKeyUuidAndHybridCertificate(any(), anyList());
    }

    @Test
    void uploadDiscoveredCertificateKey_whenCertificateCommitted_uploadsKeyAndAssociates() throws NoSuchAlgorithmException {
        List<UUID> uuids = List.of(UUID.randomUUID());
        UUID keyUuid = UUID.randomUUID();
        Certificate certificate = new Certificate();
        certificate.setCommonName("example.com");

        when(cryptographicKeyService.findKeyByFingerprint(anyString())).thenReturn(null);
        when(certificateRepository.findFirstByUuidIn(uuids)).thenReturn(certificate);
        when(cryptographicKeyService.uploadCertificatePublicKey(eq("certKey_example.com"), any(), anyInt(), anyString()))
                .thenReturn(keyUuid);

        handler.uploadDiscoveredCertificateKey(publicKey, uuids);

        verify(certificateRepository).setKeyUuid(keyUuid, uuids);
    }

    @Test
    void uploadDiscoveredCertificateKey_whenKeyAlreadyExists_skipsUploadButAssociates() throws NoSuchAlgorithmException {
        List<UUID> uuids = List.of(UUID.randomUUID());
        UUID keyUuid = UUID.randomUUID();
        when(cryptographicKeyService.findKeyByFingerprint(anyString())).thenReturn(keyUuid);

        handler.uploadDiscoveredCertificateKey(publicKey, uuids);

        verify(certificateRepository, never()).findFirstByUuidIn(anyList());
        verify(cryptographicKeyService, never()).uploadCertificatePublicKey(anyString(), any(), anyInt(), anyString());
        verify(certificateRepository).setKeyUuid(keyUuid, uuids);
    }
}
