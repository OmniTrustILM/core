package com.otilm.core.service.impl;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.client.signing.nativesigning.SignRawItemDto;
import com.otilm.api.model.client.signing.nativesigning.SignRawRequestDto;
import com.otilm.api.model.client.signing.nativesigning.SignRawResponseDto;
import com.otilm.api.model.client.signing.nativesigning.SignRawResultDto;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureInputMode;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.signing.SigningProfileModel;
import com.otilm.core.model.signing.resolved.ResolvedManagedRawSigningProfile;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.signing.contentsigning.ManagedContentSigningEngine;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.resolver.SigningProfileResolverFactory;
import com.otilm.core.signing.nativesigning.IlmNativeProfileResolver;
import com.otilm.core.signing.nativesigning.NativeOperation;
import com.otilm.core.signing.rawsigning.ManagedRawSigningEngine;
import com.otilm.core.signing.rawsigning.RawSignedItem;
import com.otilm.core.signing.rawsigning.RawSigningItem;
import com.otilm.core.signing.rawsigning.RawSigningRequest;
import com.otilm.core.signing.rawsigning.RawSigningResult;
import com.otilm.core.util.CertificateUtil;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.ResolvedManagedContentSigningProfileBuilder.aResolvedContentSigningProfile;
import static com.otilm.core.util.builders.ResolvedManagedRawSigningProfileBuilder.aResolvedRawSigningProfile;
import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.tuple;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.same;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NativeSigningServiceImplTest {

    private static final UUID PROFILE_UUID = UUID.fromString("00000000-0000-0000-0000-0000000000d7");
    private static final String PROFILE_NAME = "raw-profile";

    @Mock
    IlmNativeProfileResolver nativeProfileResolver;
    @Mock
    SigningProfileResolverFactory signingProfileResolverFactory;
    @Mock
    ManagedContentSigningEngine contentSigningEngine;
    @Mock
    ManagedRawSigningEngine rawSigningEngine;
    @InjectMocks
    NativeSigningServiceImpl service;

    private final SigningProfileModel<?, ?> model = aSigningProfile()
            .withUuid(PROFILE_UUID)
            .withName(PROFILE_NAME)
            .build();
    private final ResolvedManagedRawSigningProfile profile = aResolvedRawSigningProfile()
            .withUuid(PROFILE_UUID)
            .withName(PROFILE_NAME)
            .build();

    @BeforeEach
    void resolveTheRawProfile() throws Exception {
        doReturn(model).when(nativeProfileResolver).resolve(PROFILE_UUID, NativeOperation.SIGN_RAW);
    }

    @Test
    void answersEachItemsSignatureAndRecordInRequestOrder_whenTheRunSigns() throws Exception {
        // given
        when(signingProfileResolverFactory.resolve(model)).thenReturn(profile);
        var recordOfFirst = UUID.fromString("00000000-0000-0000-0000-0000000000a1");
        var signedFirst = new RawSignedItem("first", new byte[]{1}, recordOfFirst);
        var signedSecond = new RawSignedItem("second", new byte[]{2}, null);
        List<X509Certificate> chain = profile.resolvedScheme().chain().chain();
        when(rawSigningEngine.sign(any(), any(), any(), any()))
                .thenReturn(new RawSigningResult(SignatureAlgorithm.SHA256_WITH_RSA, chain,
                        List.of(signedFirst, signedSecond)));

        // when
        SignRawResponseDto response = service
                .signRaw(SecuredUUID.fromUUID(PROFILE_UUID), buildRequest(null, "first", "second"));

        // then
        assertThat(response.getSignatureAlgorithm()).isEqualTo(SignatureAlgorithm.SHA256_WITH_RSA);
        assertThat(response.getSignerCertificateChain()).containsExactly(chain.getFirst().getEncoded());
        assertThat(response.getResults())
                .extracting(SignRawResultDto::getIdentifier, SignRawResultDto::getSigningRecordUuid,
                        SignRawResultDto::getSignature)
                .containsExactly(tuple("first", recordOfFirst, new byte[]{1}), tuple("second", null, new byte[]{2}));
    }

    @Test
    void handsTheRunTheRequestAsStatedOnTheIlmNativeProtocol_whenNoFingerprintIsGiven() throws Exception {
        // given
        when(signingProfileResolverFactory.resolve(model)).thenReturn(profile);
        var statedMode = SignatureInputMode.DATA;
        SignRawRequestDto request = buildRequest(null, "first");
        request.setSignatureInputMode(statedMode);
        stubTheRunSigning("first");

        // when
        service.signRaw(SecuredUUID.fromUUID(PROFILE_UUID), request);

        // then
        ArgumentCaptor<RawSigningRequest> handedOver = ArgumentCaptor.forClass(RawSigningRequest.class);
        verify(rawSigningEngine)
                .sign(handedOver.capture(), same(model), same(profile), same(SigningProtocol.ILM_NATIVE));
        RawSigningRequest runRequest = handedOver.getValue();
        assertThat(runRequest.inputMode()).isEqualTo(statedMode);
        assertThat(runRequest.digestAlgorithm()).isEqualTo(DigestAlgorithm.SHA_256);
        assertThat(runRequest.items()).containsExactly(new RawSigningItem("first", buildDigest("first")));
    }

    @Test
    void signs_whenTheFingerprintDiffersFromTheSigningCertificatesOnlyInCase() throws Exception {
        // given
        when(signingProfileResolverFactory.resolve(model)).thenReturn(profile);
        String upperCaseFingerprint = getSigningCertificateFingerprint().toUpperCase(Locale.ROOT);
        stubTheRunSigning("first");

        // when
        service.signRaw(SecuredUUID.fromUUID(PROFILE_UUID), buildRequest(upperCaseFingerprint, "first"));

        // then
        verify(rawSigningEngine).sign(any(), any(), any(), any());
    }

    @Test
    void throwsValidationException_whenTheFingerprintNamesAnotherCertificate() throws Exception {
        // given
        when(signingProfileResolverFactory.resolve(model)).thenReturn(profile);
        var anotherCertificatesFingerprint = "3f9a1c0e5b7d2e4f6a8c0b1d3e5f7a9c1b3d5e7f9a0c2e4b6d8f0a1c3e5b7d9f";

        // when
        ThrowingCallable sign = () -> service
                .signRaw(SecuredUUID.fromUUID(PROFILE_UUID), buildRequest(anotherCertificatesFingerprint, "first"));

        // then
        assertThatThrownBy(sign)
                .isInstanceOf(ValidationException.class)
                .hasMessageContaining("Signing Profile '%s' is not the one the request names".formatted(PROFILE_NAME));
        verifyNoInteractions(rawSigningEngine);
    }

    @Test
    void throwsMisconfigured_whenTheProfileResolvesToAnotherWorkflow() throws Exception {
        // given
        when(signingProfileResolverFactory.resolve(model)).thenReturn(aResolvedContentSigningProfile().build());

        // when
        ThrowingCallable sign = () -> service.signRaw(SecuredUUID.fromUUID(PROFILE_UUID), buildRequest(null, "first"));

        // then
        assertThatThrownBy(sign)
                .isInstanceOfSatisfying(SigningEngineException.class,
                        e -> assertThat(e.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED));
        verifyNoInteractions(rawSigningEngine);
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private void stubTheRunSigning(String identifier) throws Exception {
        var signed = new RawSignedItem(identifier, new byte[]{1}, null);
        when(rawSigningEngine.sign(any(), any(), any(), any()))
                .thenReturn(new RawSigningResult(SignatureAlgorithm.SHA256_WITH_RSA,
                        profile.resolvedScheme().chain().chain(), List.of(signed)));
    }

    private String getSigningCertificateFingerprint() throws Exception {
        return CertificateUtil.getThumbprint(profile.resolvedScheme().chain().signingCertificate());
    }

    private static SignRawRequestDto buildRequest(String certificateFingerprint, String... identifiers) {
        var request = new SignRawRequestDto();
        request.setSignatureInputMode(SignatureInputMode.DATA_DIGEST);
        request.setDigestAlgorithm(DigestAlgorithm.SHA_256);
        request.setCertificateFingerprint(certificateFingerprint);
        request.setItems(Arrays.stream(identifiers).map(id -> new SignRawItemDto(id, buildDigest(id))).toList());
        return request;
    }

    private static byte[] buildDigest(String identifier) {
        byte[] digest = new byte[32];
        digest[0] = (byte) identifier.length();
        return digest;
    }
}
