package com.otilm.core.signing.engine.resolver;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedScheme;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.model.signing.scheme.DelegatedSigning;
import com.otilm.core.model.signing.scheme.SigningSchemeModel;
import com.otilm.core.model.signing.scheme.StaticKeyManagedSigning;
import com.otilm.core.service.CertificateInternalService;
import com.otilm.core.service.CryptographicKeyInternalService;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.util.CertificateTestUtil;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ManagedSchemeResolverTest {

    @Mock
    private CertificateInternalService certificateService;
    @Mock
    private CryptographicKeyInternalService cryptographicKeyService;

    @InjectMocks
    private ManagedSchemeResolver resolver;

    private static final String PROFILE_NAME = "a-profile";
    private static final UUID CERTIFICATE_UUID = UUID.fromString("11111111-1111-1111-1111-111111111111");

    private static StaticKeyManagedSigning staticKeyScheme() {
        return new StaticKeyManagedSigning(CERTIFICATE_UUID, List.of());
    }

    private static X509Certificate someX509() throws Exception {
        // CertificateChain rejects anything but an end-entity certificate at index 0, so a mock will not do
        return CertificateTestUtil.createTimestampingCertificate();
    }

    @Test
    void resolvesTheCertificateKeyItemsAndChain() throws Exception {
        // given
        UUID keyItemUuid = UUID.fromString("44444444-4444-4444-4444-444444444444");
        SigningCertificate certificate = SigningCertificateBuilder
                .aSigningCertificate()
                .uuid(CERTIFICATE_UUID)
                .keyItemUuids(List.of(keyItemUuid))
                .build();
        CryptographicKeyItemOperationModel keyItem = CryptographicKeyItemModelFixtures
                .activeSigningPrivateKey(KeyAlgorithm.RSA);
        List<X509Certificate> chain = List.of(someX509());

        when(certificateService.getSigningCertificate(CERTIFICATE_UUID)).thenReturn(certificate);
        when(cryptographicKeyService.getKeyItemModel(keyItemUuid)).thenReturn(keyItem);
        when(certificateService.getCertificateChainForSigning(CERTIFICATE_UUID, true)).thenReturn(chain);

        // when
        ResolvedManagedScheme result = resolver.resolve(PROFILE_NAME, staticKeyScheme());

        // then
        assertThat(result).isInstanceOf(ResolvedStaticKeyManagedSigning.class);
        ResolvedStaticKeyManagedSigning resolved = (ResolvedStaticKeyManagedSigning) result;
        assertThat(resolved.certificate()).isSameAs(certificate);
        assertThat(resolved.keyItems()).containsExactly(keyItem);
        assertThat(resolved.chain().chain()).isEqualTo(chain);
        verify(certificateService, never()).getCertificateEntity(any());
    }

    @Test
    void throwsMisconfigured_whenSchemeIsNotStaticKey() {
        // given — a delegated scheme is not resolvable by this resolver
        SigningSchemeModel delegated = new DelegatedSigning(UUID.randomUUID(), List.of());

        // when / then
        assertThatThrownBy(() -> resolver.resolve(PROFILE_NAME, delegated))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                        .isEqualTo(SigningEngineFailure.MISCONFIGURED));
    }

    @Test
    void throwsMisconfigured_whenCertificateNotFound() throws Exception {
        // given
        when(certificateService.getSigningCertificate(any())).thenThrow(new NotFoundException("certificate not found"));

        // when / then
        assertThatThrownBy(() -> resolver.resolve(PROFILE_NAME, staticKeyScheme()))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                        .isEqualTo(SigningEngineFailure.MISCONFIGURED));
    }

    @Test
    void throwsMisconfigured_whenKeyItemNotFound() throws Exception {
        // given
        UUID keyItemUuid = UUID.fromString("55555555-5555-5555-5555-555555555555");
        when(certificateService.getSigningCertificate(any()))
                .thenReturn(SigningCertificateBuilder.aSigningCertificate().keyItemUuids(List.of(keyItemUuid)).build());
        when(cryptographicKeyService.getKeyItemModel(keyItemUuid))
                .thenThrow(new NotFoundException("key item not found"));

        // when / then
        assertThatThrownBy(() -> resolver.resolve(PROFILE_NAME, staticKeyScheme()))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                        .isEqualTo(SigningEngineFailure.MISCONFIGURED))
                .satisfies(ex -> assertThat(((SigningEngineException) ex).operatorMessage())
                        .contains(keyItemUuid.toString()));
    }

    @Test
    void throwsMisconfigured_whenCertificateChainCannotBeParsed() throws Exception {
        // given
        when(certificateService.getSigningCertificate(any())).thenReturn(SigningCertificateBuilder.valid());
        when(certificateService.getCertificateChainForSigning(any(), eq(true)))
                .thenThrow(new CertificateException("bad DER"));

        // when / then
        assertThatThrownBy(() -> resolver.resolve(PROFILE_NAME, staticKeyScheme()))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                        .isEqualTo(SigningEngineFailure.MISCONFIGURED));
    }

    @Test
    void throwsMisconfigured_whenCertificateChainIsEmpty() throws Exception {
        // given — the resolver is the single place that validates the chain
        when(certificateService.getSigningCertificate(any())).thenReturn(SigningCertificateBuilder.valid());
        when(certificateService.getCertificateChainForSigning(any(), eq(true))).thenReturn(List.of());

        // when / then
        assertThatThrownBy(() -> resolver.resolve(PROFILE_NAME, staticKeyScheme()))
                .isInstanceOf(SigningEngineException.class)
                .satisfies(ex -> assertThat(((SigningEngineException) ex).failure())
                        .isEqualTo(SigningEngineFailure.MISCONFIGURED));
    }
}
