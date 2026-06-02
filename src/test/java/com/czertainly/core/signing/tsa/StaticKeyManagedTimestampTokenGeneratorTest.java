package com.czertainly.core.signing.tsa;

import com.czertainly.api.interfaces.core.tsp.error.TspException;
import com.czertainly.api.interfaces.core.tsp.error.TspFailureInfo;
import com.czertainly.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.czertainly.api.model.core.signing.SigningProtocol;
import com.czertainly.core.model.signing.SigningCertificateBuilder;
import com.czertainly.core.model.signing.resolved.ResolvedManagedTimestampingProfile;
import com.czertainly.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.czertainly.core.model.signing.timequality.LocalClockTimeQualityConfiguration;
import com.czertainly.core.signing.tsa.formatter.SignatureFormatterClient;
import com.czertainly.core.signing.tsa.signer.Signer;
import com.czertainly.core.signing.tsa.signer.SignerFactory;
import org.bouncycastle.tsp.TimeStampToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static com.czertainly.core.signing.tsa.messages.TspRequestBuilder.aTspRequest;
import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class StaticKeyManagedTimestampTokenGeneratorTest {

    @Mock SignerFactory signerFactory;
    @Mock SignatureFormatterClient formatter;
    @Mock Signer signer;

    @InjectMocks
    StaticKeyManagedTimestampTokenGenerator generator;

    /**
     * A real, parseable DER-encoded TimeStampToken used in happy-path tests.
     * Generated once via BouncyCastle so the unit tests do not need a live connector.
     */
    private static byte[] validTokenBytes;

    @BeforeAll
    static void generateValidTokenBytes() throws Exception {
        validTokenBytes = TimestampTokenTestUtil.createTimestampToken().getEncoded();
    }

    private ResolvedManagedTimestampingProfile aTimestampingProfile() {
        return new ResolvedManagedTimestampingProfile(
                UUID.randomUUID(),
                "test-profile",
                null,
                1,
                true,
                List.of(SigningProtocol.TSP),
                Boolean.FALSE,
                "1.2.3.4.5",
                List.of(),
                List.of(),
                false,
                List.of(),
                LocalClockTimeQualityConfiguration.INSTANCE,
                null,
                new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(), List.of(), null, List.of()));
    }

    @BeforeEach
    void wireSigner() throws TspException {
        lenient().when(signerFactory.create(any())).thenReturn(signer);
        lenient().when(signer.getSignatureAlgorithm()).thenReturn(SignatureAlgorithm.SHA256_WITH_RSA);
    }

    @Test
    void generate_returnsTimestampToken_whenAllDependenciesSucceed() throws Exception {
        // given
        var request = aTspRequest().build();
        var profile = aTimestampingProfile();
        var chain = mock(CertificateChain.class);
        var serialNumber = BigInteger.ONE;
        var genTime = Instant.parse("2024-01-01T00:00:00Z");
        byte[] dtbs = {1, 2, 3};
        byte[] signature = {4, 5, 6};

        when(formatter.formatDtbs(eq(request), eq(profile), eq(serialNumber), eq(genTime), eq(chain), eq(SignatureAlgorithm.SHA256_WITH_RSA)))
                .thenReturn(dtbs);
        when(signer.sign(eq(dtbs))).thenReturn(signature);
        when(formatter.formatSigningResponse(eq(request), eq(profile), eq(serialNumber), eq(genTime), eq(chain), eq(dtbs), eq(signature), eq(SignatureAlgorithm.SHA256_WITH_RSA)))
                .thenReturn(validTokenBytes);

        // when
        TimeStampToken token = generator.generate(request, profile, chain, serialNumber, genTime);

        // then
        assertThat(token).isNotNull();
    }

    @Test
    void generate_usesSigningSchemeFromProfile_toCreateSigner() throws Exception {
        // given — the factory must receive the scheme from the profile, not a default
        var profile = aTimestampingProfile();
        when(formatter.formatDtbs(any(), any(), any(), any(), any(), any())).thenReturn(new byte[1]);
        when(signer.sign(any())).thenReturn(new byte[1]);
        when(formatter.formatSigningResponse(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(validTokenBytes);

        // when
        generator.generate(aTspRequest().build(), profile, mock(CertificateChain.class), BigInteger.ONE, Instant.now());

        // then
        verify(signerFactory).create(profile.resolvedScheme());
    }

    @Test
    void generate_passesAlgorithmFromSigner_toBothFormatterPhases() throws Exception {
        // given — the formatter must receive the signer's reported algorithm in both the DTBS and signing-response phases
        when(signer.getSignatureAlgorithm()).thenReturn(SignatureAlgorithm.SHA384_WITH_ECDSA);
        when(formatter.formatDtbs(any(), any(), any(), any(), any(), any())).thenReturn(new byte[1]);
        when(signer.sign(any())).thenReturn(new byte[1]);
        when(formatter.formatSigningResponse(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(validTokenBytes);

        // when
        generator.generate(aTspRequest().build(), aTimestampingProfile(),
                mock(CertificateChain.class), BigInteger.ONE, Instant.now());

        // then
        verify(formatter).formatDtbs(any(), any(), any(), any(), any(), eq(SignatureAlgorithm.SHA384_WITH_ECDSA));
        verify(formatter).formatSigningResponse(any(), any(), any(), any(), any(), any(), any(),
                eq(SignatureAlgorithm.SHA384_WITH_ECDSA));
    }

    @Test
    void generate_passesDtbsBytesToSigner_andSignatureToFormatterSigningResponse() throws Exception {
        // given — the DTBS from phase 1 must be fed to the signer, and the resulting signature must reach phase 2
        byte[] dtbs = {10, 20, 30};
        byte[] signature = {40, 50, 60};
        when(formatter.formatDtbs(any(), any(), any(), any(), any(), any())).thenReturn(dtbs);
        when(signer.sign(dtbs)).thenReturn(signature);
        when(formatter.formatSigningResponse(any(), any(), any(), any(), any(), eq(dtbs), eq(signature), any()))
                .thenReturn(validTokenBytes);

        // when
        generator.generate(aTspRequest().build(), aTimestampingProfile(),
                mock(CertificateChain.class), BigInteger.ONE, Instant.now());

        // then
        verify(signer).sign(dtbs);
        verify(formatter).formatSigningResponse(any(), any(), any(), any(), any(), eq(dtbs), eq(signature), any());
    }

    @Test
    void generate_throwsTspExceptionWithSystemFailure_whenTokenBytesAreNotParseable() throws Exception {
        // given — the formatter.formatSigningResponse returns garbage bytes; BouncyCastle fails to parse them as a CMS SignedData
        when(formatter.formatDtbs(any(), any(), any(), any(), any(), any())).thenReturn(new byte[1]);
        when(signer.sign(any())).thenReturn(new byte[1]);
        when(formatter.formatSigningResponse(any(), any(), any(), any(), any(), any(), any(), any()))
                .thenReturn(new byte[]{0x00, 0x01, 0x02, 0x03});

        // when / then
        var exception = assertThrows(TspException.class,
                () -> generator.generate(aTspRequest().build(), aTimestampingProfile(),
                        mock(CertificateChain.class), BigInteger.ONE, Instant.now()));

        assertThat(exception.getFailureInfo()).isEqualTo(TspFailureInfo.SYSTEM_FAILURE);
        assertThat(exception.getCause()).isNotNull();
    }

    @Test
    void generate_propagatesTspException_fromSignerFactory() throws Exception {
        // given — the factory cannot find a compatible signer for the profile's signing scheme
        var cause = new TspException(TspFailureInfo.SYSTEM_FAILURE, "no signer found", "system misconfigured");
        when(signerFactory.create(any())).thenThrow(cause);

        // when / then
        var thrown = assertThrows(TspException.class,
                () -> generator.generate(aTspRequest().build(), aTimestampingProfile(),
                        mock(CertificateChain.class), BigInteger.ONE, Instant.now()));

        assertThat(thrown).isSameAs(cause);
    }

    @Test
    void generate_propagatesTspException_fromFormatterDtbs() throws Exception {
        // given — the formatter fails to build the DTBS (e.g. malformed certificate)
        var cause = new TspException(TspFailureInfo.BAD_REQUEST, "cannot build DTBS", "bad request");
        when(formatter.formatDtbs(any(), any(), any(), any(), any(), any())).thenThrow(cause);

        // when / then
        var thrown = assertThrows(TspException.class,
                () -> generator.generate(aTspRequest().build(), aTimestampingProfile(),
                        mock(CertificateChain.class), BigInteger.ONE, Instant.now()));

        assertThat(thrown).isSameAs(cause);
    }

    @Test
    void generate_propagatesTspException_fromSigner() throws Exception {
        // given — the signing connector is unavailable
        var cause = new TspException(TspFailureInfo.SYSTEM_FAILURE, "signing failed", "signing connector error");
        when(formatter.formatDtbs(any(), any(), any(), any(), any(), any())).thenReturn(new byte[1]);
        when(signer.sign(any())).thenThrow(cause);

        // when / then
        var thrown = assertThrows(TspException.class,
                () -> generator.generate(aTspRequest().build(), aTimestampingProfile(),
                        mock(CertificateChain.class), BigInteger.ONE, Instant.now()));

        assertThat(thrown).isSameAs(cause);
    }

    @Test
    void generate_propagatesTspException_fromFormatterSigningResponse() throws Exception {
        // given — the formatter fails to assemble the final token from the signature
        var cause = new TspException(TspFailureInfo.SYSTEM_FAILURE, "cannot assemble token", "internal error");
        when(formatter.formatDtbs(any(), any(), any(), any(), any(), any())).thenReturn(new byte[1]);
        when(signer.sign(any())).thenReturn(new byte[1]);
        when(formatter.formatSigningResponse(any(), any(), any(), any(), any(), any(), any(), any())).thenThrow(cause);

        // when / then
        var thrown = assertThrows(TspException.class,
                () -> generator.generate(aTspRequest().build(), aTimestampingProfile(),
                        mock(CertificateChain.class), BigInteger.ONE, Instant.now()));

        assertThat(thrown).isSameAs(cause);
    }
}
