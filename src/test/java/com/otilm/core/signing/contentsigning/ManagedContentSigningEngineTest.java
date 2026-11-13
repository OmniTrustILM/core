package com.otilm.core.signing.contentsigning;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.api.model.common.signature.DocumentTransferMode;
import com.otilm.api.model.common.signature.SignatureFamily;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.common.signature.parameters.SignatureParametersDto;
import com.otilm.api.model.common.signature.parameters.pades.PadesSignatureParametersDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DigestOnlyDocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.EmbedSignatureValueRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.EmbedTimestampRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.InlineDocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.SignedDocumentRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.SignedDocumentResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.TimestampImprintResponseDto;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.crypto.CryptographicKeyItemOperationModel;
import com.otilm.core.model.signing.CertificatePurposeRequirements;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.signing.contentsigning.acquisition.ContentSigningAcquisitions;
import com.otilm.core.signing.contentsigning.formatting.ContentSigningFormattingClient;
import com.otilm.core.signing.engine.CertificateChain;
import com.otilm.core.signing.engine.batch.BatchRecordStager;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidator;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidatorFactory;
import com.otilm.core.signing.engine.certificate.StaticKeyManagedSigningCertificateValidator;
import com.otilm.core.signing.engine.certificate.ValidationResult;
import com.otilm.core.signing.engine.error.ItemSigningException;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.record.SigningRecordInputSource;
import com.otilm.core.signing.record.SigningRecordStrategy;
import com.otilm.core.signing.record.SigningRecordStrategyFactory;
import com.otilm.core.signing.tsa.messages.IssuedTimestamp;
import com.otilm.core.signing.tsa.messages.TimestampImprint;
import com.otilm.core.util.clocksource.TestClockSource;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.IntStream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatcher;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

import static com.otilm.core.util.CertificateTestData.DOCUMENT_SIGNING_OID;
import static com.otilm.core.util.builders.PadesSignatureParametersDtoBuilder.aPadesParameters;
import static com.otilm.core.util.builders.ResolvedManagedContentSigningProfileBuilder.aResolvedContentSigningProfile;
import static com.otilm.core.util.builders.SignatureFamilyDeclarationDtoBuilder.aFamilyDeclaration;
import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.AdditionalMatchers.aryEq;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ManagedContentSigningEngineTest {

    private static final byte[] DOCUMENT = "a document".getBytes();

    private static final String DOCUMENT_IDENTIFIER = "document-1";

    private static final Instant PLATFORM_TIME = Instant.parse("2026-03-04T11:25:00Z");

    private static final SignatureAlgorithm SIGNATURE_ALGORITHM = SignatureAlgorithm.SHA256_WITH_RSA_PSS;

    @Mock
    ContentSigningFormattingClient formattingClient;
    @Mock
    ContentSigningAcquisitions acquisitions;
    @Mock
    SigningCertificateValidatorFactory signingCertificateValidatorFactory;
    @Mock
    SigningCertificateValidator signingCertificateValidator;
    @Mock
    SigningRecordStrategyFactory signingRecordStrategyFactory;
    @Mock
    SigningRecordStrategy signingRecordStrategy;
    @Mock
    ContentSigningRecordFactory recordFactory;

    ManagedContentSigningEngine engine;

    @BeforeEach
    void createEngine() throws Exception {
        engine = new ManagedContentSigningEngine(formattingClient, acquisitions, signingCertificateValidatorFactory,
                TestClockSource.ofWallTime(PLATFORM_TIME), recordFactory,
                new BatchRecordStager(signingRecordStrategyFactory));
        lenient().when(acquisitions.signatureAlgorithm(any())).thenReturn(SIGNATURE_ALGORITHM);
        lenient().when(signingRecordStrategyFactory.strategyFor(any())).thenReturn(signingRecordStrategy);
        lenient().when(signingCertificateValidatorFactory.getValidator(any())).thenReturn(signingCertificateValidator);
        lenient()
                .when(signingCertificateValidator.validate(any(), any(), anyBoolean(), any()))
                .thenReturn(ValidationResult.ok());
    }

    // ── SignedPath ────────────────────────────────────────────────────────────

    @Nested
    class SignedPath {

        @Test
        void signsToSignedLevel_throughComputeAndEmbed() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(eq(profile), argThat(dtbsListOf("dtbs".getBytes()))))
                    .thenReturn(List.of("signature".getBytes()));
            var signedDocument = "signed document".getBytes();
            stubEmbedSignatureValue(signedDocument);

            // when
            SignedContent signed = engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API)
                    .getFirst()
                    .content();

            // then
            assertThat(signed.signedDocument()).isEqualTo(signedDocument);
            assertThat(signed.level()).isEqualTo(SignatureLevel.SIGNED);
            assertThat(signed.timestampSerials()).isEmpty();
            verify(formattingClient, never()).computeSignatureTimestampImprint(any(), any());
        }

        @Test
        void passesThePlatformsSigningTimeAndTheProfilesAttributesToComputeDtbs() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            engine.sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<ComputeDtbsRequestDto> captured = ArgumentCaptor.forClass(ComputeDtbsRequestDto.class);
            verify(formattingClient).computeDtbs(any(), captured.capture());
            assertThat(captured.getValue().getFamily()).isEqualTo(profile.family());
            assertThat(captured.getValue().getSigningTime().toInstant()).isEqualTo(PLATFORM_TIME);
            assertThat(captured.getValue().getFormattingAttributes())
                    .isEqualTo(profile.signatureFormattingConnectorAttributes());
            assertThat(captured.getValue().getSignerCertificateChain()).isNotEmpty();
        }

        @Test
        void replaysTheFormattingContextVerbatim_whenEmbeddingTheSignature() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            var signature = "signature".getBytes();
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of(signature));
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            engine.sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<EmbedSignatureValueRequestDto> captured = ArgumentCaptor
                    .forClass(EmbedSignatureValueRequestDto.class);
            verify(formattingClient).embedSignatureValue(any(), captured.capture());
            assertThat(captured.getValue().getFormattingContext()).isEqualTo("context".getBytes());
            assertThat(captured.getValue().getSignatureValue()).isEqualTo(signature);
            assertThat(captured.getValue().getFamily()).isEqualTo(profile.family());
        }

        @Test
        void namesTheResolvedSignersAlgorithmOnBothHalvesOfThePair() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            engine.sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<ComputeDtbsRequestDto> compute = ArgumentCaptor.forClass(ComputeDtbsRequestDto.class);
            ArgumentCaptor<EmbedSignatureValueRequestDto> embed = ArgumentCaptor
                    .forClass(EmbedSignatureValueRequestDto.class);
            verify(formattingClient).computeDtbs(any(), compute.capture());
            verify(formattingClient).embedSignatureValue(any(), embed.capture());
            assertThat(compute.getValue().getSignatureAlgorithm()).isEqualTo(SIGNATURE_ALGORITHM);
            assertThat(embed.getValue().getSignatureAlgorithm()).isEqualTo(compute.getValue().getSignatureAlgorithm());
        }

        @Test
        void resolvesTheSignersAlgorithmOnceForTheRun() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            engine.sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            verify(acquisitions).signatureAlgorithm(profile);
        }

        /**
         * A scheme whose algorithm cannot be resolved has no signature the connector could prepare for, so the run
         * stops before the connector is asked to format anything.
         */
        @Test
        void refusesBeforeComputeDtbs_whenTheSignersAlgorithmCannotBeResolved() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            when(acquisitions.signatureAlgorithm(profile))
                    .thenThrow(new SigningEngineException(SigningEngineFailure.MISCONFIGURED,
                            "no SignerCreator supports the scheme", "The system is misconfigured."));

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            });
            verify(formattingClient, never()).computeDtbs(any(), any());
            verify(acquisitions, never()).signDtbs(any(), any());
        }

        /**
         * v1 policy pins the authorized digest to the one the signer's algorithm signs, so a profile that disagrees
         * with the request can be satisfied by no connector. The run stops before it asks one, which is what keeps the
         * binding gate from reporting an operator's misconfiguration as a connector fault.
         */
        @Test
        void refusesBeforeComputeDtbs_whenTheAuthorizedDigestIsNotTheOneTheSignerSigns() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            when(acquisitions.signatureAlgorithm(profile)).thenReturn(SignatureAlgorithm.SHA512_WITH_RSA);

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
                assertThat(thrown.operatorMessage()).contains("SHA512withRSA", "SHA-256");
            });
            verify(formattingClient, never()).computeDtbs(any(), any());
            verify(acquisitions, never()).signDtbs(any(), any());
        }

        @Test
        void refuses_whenTheConnectorAnswersTheEmbedWithNoSignedDocument() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            when(formattingClient.embedSignatureValue(any(), any(EmbedSignatureValueRequestDto.class)))
                    .thenReturn(new SignedDocumentResponseDto());

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                assertThat(thrown.step()).isEqualTo("embedSignatureValue");
                assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
            });
        }

        @Test
        void refuses_whenTheProfilesSigningChainCannotBeEncoded() throws Exception {
            // given: a certificate whose encoding fails, which no connector request can carry
            X509Certificate unencodable = mock(X509Certificate.class);
            when(unencodable.getBasicConstraints()).thenReturn(-1);
            when(unencodable.getEncoded()).thenThrow(new CertificateEncodingException("unencodable"));
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(SignatureLevel.SIGNED)
                    .withResolvedScheme(new ResolvedStaticKeyManagedSigning(SigningCertificateBuilder.valid(),
                            List.of(), CertificateChain.of(unencodable), List.of()))
                    .build();

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
                assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
                assertThat(thrown.itemIdentifier()).isNull();
            });
            verify(acquisitions, never()).signDtbs(any(), any());
        }
    }

    // ── TimestampedPath ───────────────────────────────────────────────────────

    @Nested
    class TimestampedPath {

        @Test
        void raisesTheSignatureToTimestamped_throughTheInProcessBridge() throws Exception {
            // given: the ceiling admits TIMESTAMPED, so both gates pass and the leg itself carries the run
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32]);
            var issuedSerial = BigInteger.valueOf(0x2a);
            stubIssuedTimestamp(issuedSerial);
            var timestampedDocument = "timestamped document".getBytes();
            stubEmbedSignatureTimestamp(timestampedDocument);

            // when
            SignedContent signed = engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API)
                    .getFirst()
                    .content();

            // then: the document is the embed's output and the serial is traceable to its timestamp record
            assertThat(signed.signedDocument()).isEqualTo(timestampedDocument);
            assertThat(signed.level()).isEqualTo(SignatureLevel.TIMESTAMPED);
            assertThat(signed.timestampSerials()).containsExactly(issuedSerial);
        }

        @Test
        void timestampsExactlyTheImprintTheConnectorReturned() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            byte[] imprintValue = new byte[32];
            imprintValue[0] = 7;
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(imprintValue);
            stubIssuedTimestamp(BigInteger.ONE);
            stubEmbedSignatureTimestamp("timestamped document".getBytes());

            // when
            engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<TimestampImprint> captured = ArgumentCaptor.forClass(TimestampImprint.class);
            verify(acquisitions).timestampSignature(eq(profile), captured.capture(), any());
            assertThat(captured.getValue().algorithm()).isEqualTo(DigestAlgorithm.SHA_256);
            assertThat(captured.getValue().value()).isEqualTo(imprintValue);
        }

        @Test
        void embedsTheTokenTheTimestampSourceIssuedIntoTheSignedDocument() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            var signedDocument = "signed document".getBytes();
            stubEmbedSignatureValue(signedDocument);
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.ONE);
            stubEmbedSignatureTimestamp("timestamped document".getBytes());

            // when
            engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<EmbedTimestampRequestDto> captured = ArgumentCaptor.forClass(EmbedTimestampRequestDto.class);
            verify(formattingClient).embedSignatureTimestamp(any(), captured.capture());
            assertThat(captured.getValue().getTimestampToken()).isEqualTo("token".getBytes());
            assertThat(captured.getValue().getSignedDocument()).isEqualTo(signedDocument);
            assertThat(captured.getValue().getFamily()).isEqualTo(profile.family());
        }

        @Test
        void stopsAtSigned_whenThatIsWhatWasAskedForOnATimestampingProfile() throws Exception {
            // given: the ceiling permits TIMESTAMPED but the request asks for SIGNED
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            SignedContent signed = engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API)
                    .getFirst()
                    .content();

            // then
            assertThat(signed.level()).isEqualTo(SignatureLevel.SIGNED);
            verify(acquisitions, never()).timestampSignature(any(), any(), any());
        }

        @Test
        void sendsTheOriginalContentAlongsideADetachedSignature() throws Exception {
            // given: a detached signature does not envelop what it signs, so the imprint needs the content beside it
            ResolvedManagedContentSigningProfile profile = aTimestampingProfileOf(SignatureFamily.CADES);
            DigestOnlyDocumentTransferDto digestOnly = new DigestOnlyDocumentTransferDto(digestOf(DOCUMENT),
                    DigestAlgorithm.SHA_256);
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.ONE);
            stubEmbedSignatureTimestamp("timestamped document".getBytes());

            // when
            engine
                    .sign(requestFor(SignatureLevel.TIMESTAMPED, DocumentTransferMode.DIGEST_ONLY, null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<SignedDocumentRequestDto> captured = ArgumentCaptor.forClass(SignedDocumentRequestDto.class);
            verify(formattingClient).computeSignatureTimestampImprint(any(), captured.capture());
            assertThat(captured.getValue().getDetachedContent()).isEqualTo(digestOnly);
        }

        @Test
        void sendsNoDetachedContentAlongsideAnEnvelopedSignature() throws Exception {
            // given: an enveloped document already carries its content, so repeating it would be redundant
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.ONE);
            stubEmbedSignatureTimestamp("timestamped document".getBytes());

            // when
            engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<SignedDocumentRequestDto> captured = ArgumentCaptor.forClass(SignedDocumentRequestDto.class);
            verify(formattingClient).computeSignatureTimestampImprint(any(), captured.capture());
            assertThat(captured.getValue().getDetachedContent()).isNull();
        }

        @Test
        void refuses_whenTheConnectorAnswersTheImprintWithNothingToStamp() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(null);

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                assertThat(thrown.step()).isEqualTo("computeSignatureTimestampImprint");
                assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
            });
            verify(acquisitions, never()).timestampSignature(any(), any(), any());
        }

        @Test
        void refuses_whenTheConnectorNamesNoAlgorithmForTheImprint() throws Exception {
            // given: a digest cannot be stamped without knowing which algorithm produced it
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32], null);

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                assertThat(thrown.step()).isEqualTo("computeSignatureTimestampImprint");
            });
            verify(acquisitions, never()).timestampSignature(any(), any(), any());
        }

        @Test
        void refuses_whenTheConnectorAnswersTheTimestampEmbedWithNoSignedDocument() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.ONE);
            when(formattingClient.embedSignatureTimestamp(any(), any())).thenReturn(new SignedDocumentResponseDto());

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                assertThat(thrown.step()).isEqualTo("embedSignatureTimestamp");
                assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
            });
        }
    }

    // ── FamilyBinding ─────────────────────────────────────────────────────────

    @Nested
    class FamilyBinding {

        @Test
        void carriesTheEffectiveParametersOnTheComputeDtbsRequest() throws Exception {
            // given: a run carrying an effective PAdES parameters object
            PadesSignatureParametersDto effective = aPadesParameters().withReason("Contract approval").build();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            engine
                    .sign(requestFor(SignatureLevel.SIGNED, DocumentTransferMode.INLINE, effective),
                            aSigningProfile().build(), aSignedOnlyProfile(), SigningProtocol.CSC_API);

            // then: the connector received them on the PAdES request, unchanged
            ArgumentCaptor<ComputeDtbsRequestDto> captured = ArgumentCaptor.forClass(ComputeDtbsRequestDto.class);
            verify(formattingClient).computeDtbs(any(), captured.capture());
            assertThat(captured.getValue().getFamily()).isEqualTo(SignatureFamily.PADES);
            assertThat(captured.getValue().getSignatureParameters()).isSameAs(effective);
        }

        @Test
        void leavesTheFieldUnset_whenTheRunCarriesNoParameters() throws Exception {
            // given
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), aSignedOnlyProfile(),
                            SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<ComputeDtbsRequestDto> captured = ArgumentCaptor.forClass(ComputeDtbsRequestDto.class);
            verify(formattingClient).computeDtbs(any(), captured.capture());
            assertThat(captured.getValue().getSignatureParameters()).isNull();
        }

        @Test
        void refusesADigestOnlyDocumentBeforeResolvingTheSigner_whenTheFamilyIsPades() {
            // given
            DocumentTransferMode refusedByPades = DocumentTransferMode.DIGEST_ONLY;

            // when
            ThrowingCallable sign = () -> engine
                    .sign(requestFor(SignatureLevel.SIGNED, refusedByPades, null), aSigningProfile().build(),
                            aSignedOnlyProfile(), SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign)
                    .hasMessageContaining("PAdES signing needs the document itself, not only its digest")
                    .isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
                        assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
                        assertThat(refusal.operatorMessage()).contains("transferMode digestOnly");
                    });
            verifyNoInteractions(signingCertificateValidatorFactory, acquisitions, formattingClient);
        }

        @Test
        void asksForTheDigest_whenTheRefusedModeIsInline() {
            // given
            DocumentTransferMode refused = DocumentTransferMode.INLINE;

            // when
            String message = ManagedContentSigningEngine.clientRefusal("CAdES", refused);

            // then
            assertThat(message).isEqualTo("CAdES signing needs only the document's digest, not the document itself");
        }

        @Test
        void acceptsADigestOnlyDocument_whenTheFamilyIsDetached() throws Exception {
            // given
            DigestOnlyDocumentTransferDto digestOnly = new DigestOnlyDocumentTransferDto(digestOf(DOCUMENT),
                    DigestAlgorithm.SHA_256);
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            engine
                    .sign(requestFor(SignatureLevel.SIGNED, DocumentTransferMode.DIGEST_ONLY, null),
                            aSigningProfile().build(), aSignedOnlyProfileOf(SignatureFamily.CADES),
                            SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<ComputeDtbsRequestDto> captured = ArgumentCaptor.forClass(ComputeDtbsRequestDto.class);
            verify(formattingClient).computeDtbs(any(), captured.capture());
            assertThat(captured.getValue().getFamily()).isEqualTo(SignatureFamily.CADES);
            assertThat(captured.getValue().getDocument()).isEqualTo(digestOnly);
        }

        @Test
        void refusesAnInlineDocumentBeforeResolvingTheSigner_whenTheFamilyDeclaresOnlyDigestOnly() {
            // given
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(SignatureLevel.SIGNED)
                    .withFamilyDeclaration(aFamilyDeclaration(new SignatureFamily("mrtd"))
                            .withTransferModes(Set.of(DocumentTransferMode.DIGEST_ONLY))
                            .build())
                    .build();

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign)
                    .hasMessageContaining("mrtd signing needs only the document's digest, not the document itself")
                    .isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
                        assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
                        assertThat(refusal.operatorMessage()).contains("transferMode inline");
                    });
            verifyNoInteractions(signingCertificateValidatorFactory, acquisitions, formattingClient);
        }
    }

    // ── Gates ─────────────────────────────────────────────────────────────────

    @Nested
    class Gates {

        @Test
        void refusesToSign_whenTheEchoedDigestIsNotTheAuthorizedOne() throws Exception {
            // given: the connector echoes a digest of a different document
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf("another document".getBytes()));

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then: the binding violation is its own failure class, and no key was used
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.BINDING_VIOLATION);
            });
            verify(acquisitions, never()).signDtbs(any(), any());
            verify(formattingClient, never()).embedSignatureValue(any(), any());
        }

        @Test
        void refusesToSign_whenTheConnectorReturnsNoFormattingContext() throws Exception {
            // given: a response whose dtbs and echo are usable but whose formatting context is missing
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            ComputeDtbsResponseDto incomplete = new ComputeDtbsResponseDto();
            incomplete.setDtbs("dtbs".getBytes());
            incomplete.setDocumentDigest(digestOf(DOCUMENT));
            incomplete.setDocumentDigestAlgorithm(DigestAlgorithm.SHA_256);
            when(formattingClient.computeDtbs(any(), any())).thenReturn(incomplete);

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then: the connector broke its contract, and no key was used
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                assertThat(thrown.step()).isEqualTo("computeDtbs");
            });
            verify(acquisitions, never()).signDtbs(any(), any());
            verify(formattingClient, never()).embedSignatureValue(any(), any());
        }

        @Test
        void refusesToSign_whenTheConnectorAnswersComputeDtbsWithNothing() throws Exception {
            // given: a 200 carrying no body at all
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            when(formattingClient.computeDtbs(any(), any())).thenReturn(null);

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
            });
            verify(acquisitions, never()).signDtbs(any(), any());
        }

        @Test
        void refusesToSign_whenTheConnectorReturnsNoDtbsToSign() throws Exception {
            // given: an echo that binds correctly, but nothing to sign
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            ComputeDtbsResponseDto incomplete = new ComputeDtbsResponseDto();
            incomplete.setDocumentDigest(digestOf(DOCUMENT));
            incomplete.setDocumentDigestAlgorithm(DigestAlgorithm.SHA_256);
            incomplete.setFormattingContext("context".getBytes());
            when(formattingClient.computeDtbs(any(), any())).thenReturn(incomplete);

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
            });
            verify(acquisitions, never()).signDtbs(any(), any());
        }

        @Test
        void refusesToSign_whenTheConnectorReturnsAnEmptyDtbs() throws Exception {
            // given: an echo that binds correctly, over a DTBS with no bytes
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            byte[] emptyDtbs = new byte[0];
            ComputeDtbsResponseDto response = new ComputeDtbsResponseDto();
            response.setDtbs(emptyDtbs);
            response.setDocumentDigest(digestOf(DOCUMENT));
            response.setDocumentDigestAlgorithm(DigestAlgorithm.SHA_256);
            response.setFormattingContext("context".getBytes());
            when(formattingClient.computeDtbs(any(), any())).thenReturn(response);

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                assertThat(thrown.itemIdentifier()).isEqualTo(DOCUMENT_IDENTIFIER);
            });
            verify(acquisitions, never()).signDtbs(any(), any());
        }

        @Test
        void refuses_whenTheTargetIsAboveTheProfileCeiling() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            var aboveTheCeiling = SignatureLevel.TIMESTAMPED;

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(aboveTheCeiling), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
                assertThat(thrown.clientMessage()).contains(aboveTheCeiling.name());
            });
            verify(formattingClient, never()).computeDtbs(any(), any());
        }

        @Test
        void refuses_whenTheTargetIsAboveTheRungsTheEngineExecutes() throws Exception {
            // given: a profile whose ceiling is LONG_TERM, which no step reaches yet
            var unreachedLevel = SignatureLevel.LONG_TERM;
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(unreachedLevel)
                    .build();

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(unreachedLevel), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
                assertThat(thrown.clientMessage()).contains(unreachedLevel.name());
            });
            verify(formattingClient, never()).computeDtbs(any(), any());
        }

        @Test
        void accepts_whenTheTargetIsBelowTheProfileCeiling() throws Exception {
            // given: a ceiling above the target must not be mistaken for an over-rung request
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(SignatureLevel.TIMESTAMPED)
                    .build();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            SignedContent signed = engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API)
                    .getFirst()
                    .content();

            // then
            assertThat(signed.level()).isEqualTo(SignatureLevel.SIGNED);
        }
    }

    // ── DeclarationGate ──────────────────────────────────────────────────────

    @Nested
    class DeclarationGate {

        @Test
        void refusesBeforeComputeDtbs_whenTheConnectorNoLongerDeclaresTheProfileCeiling() {
            // given — a reconnect lowered the family's levels below the profile's ceiling
            var withdrawnCeiling = SignatureLevel.TIMESTAMPED;
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(withdrawnCeiling)
                    .withFamilyDeclaration(
                            aFamilyDeclaration(SignatureFamily.PADES).withHighestLevel(SignatureLevel.SIGNED).build())
                    .build();

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(withdrawnCeiling), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
                assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
                assertThat(refusal.operatorMessage()).contains(withdrawnCeiling.name());
            });
            verifyNoInteractions(formattingClient, acquisitions);
        }

        @Test
        void refusesBeforeComputeDtbs_whenTheTargetIsBelowTheWithdrawnCeiling() {
            // given — a reconnect lowered the family's levels to SIGNED, which the request still targets
            var withdrawnCeiling = SignatureLevel.TIMESTAMPED;
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(withdrawnCeiling)
                    .withFamilyDeclaration(
                            aFamilyDeclaration(SignatureFamily.PADES).withHighestLevel(SignatureLevel.SIGNED).build())
                    .build();

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
                assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
                assertThat(refusal.operatorMessage()).contains(withdrawnCeiling.name());
            });
            verifyNoInteractions(formattingClient, acquisitions);
        }

        @Test
        void refusesToAugment_whenTheConnectorNoLongerDeclaresTheProfileCeiling() {
            // given
            var withdrawnCeiling = SignatureLevel.TIMESTAMPED;
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(withdrawnCeiling)
                    .withFamilyDeclaration(
                            aFamilyDeclaration(SignatureFamily.PADES).withHighestLevel(SignatureLevel.SIGNED).build())
                    .build();

            // when
            ThrowingCallable augment = () -> engine
                    .augment(new AugmentationRequest(withdrawnCeiling, "foreign document".getBytes(), null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(augment).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
                assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
                assertThat(refusal.operatorMessage()).contains(withdrawnCeiling.name());
            });
            verifyNoInteractions(formattingClient, acquisitions);
        }

        @Test
        void refusesToReleaseTheKey_whenTheFamilyNoLongerAcceptsTheSignersAlgorithm() throws Exception {
            // given
            var onlyAcceptedAlgorithm = SignatureAlgorithm.SHA512_WITH_RSA;
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(SignatureLevel.SIGNED)
                    .withFamilyDeclaration(aFamilyDeclaration(SignatureFamily.PADES)
                            .withSignatureAlgorithms(Set.of(onlyAcceptedAlgorithm))
                            .build())
                    .build();

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, refusal -> {
                assertThat(refusal.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
                assertThat(refusal.operatorMessage()).contains(SIGNATURE_ALGORITHM.getCode());
            });
            verifyNoInteractions(formattingClient);
            verify(acquisitions, never()).signDtbs(any(), any());
        }

        @Test
        void signs_whenTheFamilyAcceptsTheSignersAlgorithm() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(SignatureLevel.SIGNED)
                    .withFamilyDeclaration(aFamilyDeclaration(SignatureFamily.PADES)
                            .withSignatureAlgorithms(Set.of(SIGNATURE_ALGORITHM))
                            .build())
                    .build();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            SignedContent signed = engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API)
                    .getFirst()
                    .content();

            // then
            assertThat(signed.level()).isEqualTo(SignatureLevel.SIGNED);
        }
    }

    // ── Augmentation ──────────────────────────────────────────────────────────

    @Nested
    class Augmentation {

        @Test
        void timestampsAForeignSignedDocumentWithoutSigningIt() throws Exception {
            // given: a document signed elsewhere, entering at the signature-timestamp imprint
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubSignatureTimestampImprint(new byte[32]);
            var issuedSerial = BigInteger.ONE;
            stubIssuedTimestamp(issuedSerial);
            stubEmbedSignatureTimestamp("timestamped foreign document".getBytes());

            // when
            SignedContent signed = engine
                    .augment(new AugmentationRequest(SignatureLevel.TIMESTAMPED, "foreign document".getBytes(), null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then: the profile's key signed nothing and no DTBS was computed
            assertThat(signed.level()).isEqualTo(SignatureLevel.TIMESTAMPED);
            assertThat(signed.timestampSerials()).containsExactly(issuedSerial);
            verify(formattingClient, never()).computeDtbs(any(), any());
            verify(acquisitions, never()).signDtbs(any(), any());
        }

        @Test
        void augments_whenTheSigningCertificateIsNoLongerFitToSign() throws Exception {
            // given: a certificate a signing run would refuse, on a path where the profile's own key signs nothing
            ResolvedManagedContentSigningProfile profile = profileWithCertificate(
                    SigningCertificateBuilder.aContentSigningCertificate().state(CertificateState.REVOKED).build());
            stubSignatureTimestampImprint(new byte[32]);
            var issuedSerial = BigInteger.ONE;
            stubIssuedTimestamp(issuedSerial);
            stubEmbedSignatureTimestamp("timestamped foreign document".getBytes());

            // when
            SignedContent signed = engine
                    .augment(new AugmentationRequest(SignatureLevel.TIMESTAMPED, "foreign document".getBytes(), null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThat(signed.level()).isEqualTo(SignatureLevel.TIMESTAMPED);
            assertThat(signed.timestampSerials()).containsExactly(issuedSerial);
            verify(signingCertificateValidatorFactory, never()).getValidator(any());
        }

        @Test
        void recordsTheAugmentation() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.ONE);
            stubEmbedSignatureTimestamp("timestamped foreign document".getBytes());
            var recordSource = stubRecordSource();

            // when
            engine
                    .augment(new AugmentationRequest(SignatureLevel.TIMESTAMPED, "foreign document".getBytes(), null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            verify(signingRecordStrategy).recordSigning(any(), eq(List.of(recordSource)));
        }

        @Test
        void keepsTheTimestampedDocument_whenRecordingFails() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.ONE);
            var timestamped = "timestamped foreign document".getBytes();
            stubEmbedSignatureTimestamp(timestamped);
            stubRecordSource();
            doThrow(new RuntimeException("outbox down")).when(signingRecordStrategy).recordSigning(any(), any());

            // when
            SignedContent signed = engine
                    .augment(new AugmentationRequest(SignatureLevel.TIMESTAMPED, "foreign document".getBytes(), null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThat(signed.signedDocument()).isEqualTo(timestamped);
        }

        @Test
        void refuses_whenTheAugmentationTargetIsSignedAndTheDocumentAlreadyIs() {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();

            // when
            ThrowingCallable augment = () -> engine
                    .augment(new AugmentationRequest(SignatureLevel.SIGNED, "foreign document".getBytes(), null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(augment).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            });
        }

        @Test
        void refuses_whenTheAugmentationTargetIsAboveTheRungsTheEngineExecutes() {
            // given
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(SignatureLevel.ARCHIVAL)
                    .build();

            // when
            ThrowingCallable augment = () -> engine
                    .augment(new AugmentationRequest(SignatureLevel.ARCHIVAL, "foreign document".getBytes(), null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(augment).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            });
        }
    }

    // ── SigningCertificateGate ────────────────────────────────────────────────

    @Nested
    class SigningCertificateGate {

        private static final String REFUSAL_DETAIL = "Signing certificate is not acceptable for content_signing";

        @BeforeEach
        void useTheRealValidator() throws Exception {
            when(signingCertificateValidatorFactory.getValidator(any()))
                    .thenReturn(new StaticKeyManagedSigningCertificateValidator());
        }

        @Test
        void refusesToSign_whenTheCertificateIsRevoked() {
            // given
            ResolvedManagedContentSigningProfile profile = profileWithCertificate(
                    SigningCertificateBuilder.aContentSigningCertificate().state(CertificateState.REVOKED).build());

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign)
                    .isInstanceOfSatisfying(SigningEngineException.class,
                            thrown -> assertMisconfigurationRefusal(thrown, profile.name()));
        }

        @Test
        void refusesToSign_whenTheCertificateIsArchived() {
            // given
            ResolvedManagedContentSigningProfile profile = profileWithCertificate(
                    SigningCertificateBuilder.aContentSigningCertificate().archived(true).build());

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign)
                    .isInstanceOfSatisfying(SigningEngineException.class,
                            thrown -> assertMisconfigurationRefusal(thrown, profile.name()));
        }

        @Test
        void refusesToSign_whenTheSigningKeyIsDeactivated() {
            // given
            ResolvedManagedContentSigningProfile profile = profileWithKeyItems(
                    SigningCertificateBuilder.aContentSigningCertificate().build(),
                    List
                            .of(CryptographicKeyItemModelFixtures
                                    .keyItem(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, KeyState.DEACTIVATED,
                                            List.of(KeyUsage.SIGN)),
                                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)));

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign)
                    .isInstanceOfSatisfying(SigningEngineException.class,
                            thrown -> assertMisconfigurationRefusal(thrown, profile.name()));
        }

        @Test
        void refusesToSign_whenTheCertificateMissesTheRequiredKeyUsage() {
            // given: a certificate that satisfies the default purpose rule but not the profile's own demand
            ResolvedManagedContentSigningProfile profile = profileWithCertificatePurpose(
                    SigningCertificateBuilder.aContentSigningCertificate().build(),
                    new CertificatePurposeRequirements(true, Set.of()));

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign)
                    .isInstanceOfSatisfying(SigningEngineException.class,
                            thrown -> assertMisconfigurationRefusal(thrown, profile.name()));
        }

        @Test
        void refusesToSign_whenTheCertificateMissesTheRequiredExtendedKeyUsage() {
            // given
            ResolvedManagedContentSigningProfile profile = profileWithCertificatePurpose(
                    SigningCertificateBuilder.aContentSigningCertificate().build(),
                    new CertificatePurposeRequirements(false, Set.of(DOCUMENT_SIGNING_OID)));

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign)
                    .isInstanceOfSatisfying(SigningEngineException.class,
                            thrown -> assertMisconfigurationRefusal(thrown, profile.name()));
        }

        @Test
        void signsNothing_whenTheCertificateIsUnacceptable() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = profileWithCertificate(
                    SigningCertificateBuilder.aContentSigningCertificate().state(CertificateState.REVOKED).build());

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOf(SigningEngineException.class);
            verify(acquisitions, never()).signDtbs(any(), any());
            verify(formattingClient, never()).computeDtbs(any(), any());
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private static void assertMisconfigurationRefusal(SigningEngineException thrown, String profileName) {
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            assertThat(thrown.operatorMessage()).contains(REFUSAL_DETAIL).contains(profileName);
            assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
            assertThat(thrown.clientMessage()).doesNotContain(REFUSAL_DETAIL).doesNotContain(profileName);
        }
    }

    // ── FailureLogging ────────────────────────────────────────────────────────

    @Nested
    class FailureLogging {

        private ListAppender<ILoggingEvent> logged;

        @BeforeEach
        void captureEngineLogs() {
            logged = new ListAppender<>();
            logged.start();
            engineLogger().addAppender(logged);
        }

        /** The logger is a process-wide singleton, so a capturing appender left on it would follow the next test. */
        @AfterEach
        void releaseEngineLogger() {
            engineLogger().detachAndStopAllAppenders();
        }

        @Test
        void logsTheStepLevelAndSerial_whenAFailureFollowsTheKeySigning() throws Exception {
            // given: the run dies embedding a timestamp that has already been issued
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            var targetLevel = SignatureLevel.TIMESTAMPED;
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32]);
            var issuedSerial = BigInteger.valueOf(0x2a);
            stubIssuedTimestamp(issuedSerial);
            when(formattingClient.embedSignatureTimestamp(any(), any())).thenReturn(new SignedDocumentResponseDto());

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(targetLevel), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOf(SigningEngineException.class);
            assertThat(messagesLoggedAt(Level.ERROR))
                    .anySatisfy(message -> assertThat(message)
                            .contains(profile.name())
                            .contains("embedSignatureTimestamp")
                            .contains(targetLevel.name())
                            .contains(issuedSerial.toString(16)));
        }

        @Test
        void logsTheFailingDocumentBesideEverySerialTheRunIssued() throws Exception {
            // given: the second document's timestamp embed fails after both timestamps were issued
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubBatchSignedUpToTheTimestampEmbed();
            when(formattingClient.embedSignatureTimestamp(any(), any()))
                    .thenReturn(signedDocumentResponse("timestamped document".getBytes()),
                            new SignedDocumentResponseDto());

            // when
            ThrowingCallable sign = () -> engine
                    .sign(batchOf(SignatureLevel.TIMESTAMPED, "first", "second"), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOf(SigningEngineException.class);
            assertThat(messagesLoggedAt(Level.ERROR))
                    .anySatisfy(message -> assertThat(message).contains("'second'").contains("2a").contains("2b"));
        }

        @Test
        void keepsTheSignedDocumentOutOfTheFailureLog() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            var foreignDocument = "foreign document";
            stubSignatureTimestampImprint(null);

            // when
            ThrowingCallable augment = () -> engine
                    .augment(new AugmentationRequest(SignatureLevel.TIMESTAMPED, foreignDocument.getBytes(), null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then: the augmentation path logs, and never the bytes it was handed
            assertThatThrownBy(augment).isInstanceOf(SigningEngineException.class);
            assertThat(messagesLoggedAt(Level.ERROR))
                    .isNotEmpty()
                    .allSatisfy(message -> assertThat(message).doesNotContain(foreignDocument));
        }

        @Test
        void logsTheSerialAlreadyIssued_whenAnUncheckedFailureFollowsTheKeySigning() throws Exception {
            // given: the run dies unchecked embedding a timestamp that has already been issued
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32]);
            var issuedSerial = BigInteger.valueOf(0x2a);
            stubIssuedTimestamp(issuedSerial);
            when(formattingClient.embedSignatureTimestamp(any(), any()))
                    .thenThrow(new IllegalStateException("connector client lookup failed"));

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOf(SigningEngineException.class);
            assertThat(messagesLoggedAt(Level.ERROR))
                    .anySatisfy(message -> assertThat(message)
                            .contains(profile.name())
                            .contains(issuedSerial.toString(16)));
        }

        @Test
        void funnelsAnUncheckedAugmentationFailureIntoAStepFailure_withoutLeakingItsDetail() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            var internalDetail = "attribute cache is down";
            when(formattingClient.computeSignatureTimestampImprint(any(), any()))
                    .thenThrow(new IllegalStateException(internalDetail));

            // when
            ThrowingCallable augment = () -> engine
                    .augment(new AugmentationRequest(SignatureLevel.TIMESTAMPED, "foreign document".getBytes(), null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(augment).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.STEP_FAILED);
                assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
                assertThat(thrown.getCause()).hasMessage(internalDetail);
            });
            assertThat(messagesLoggedAt(Level.ERROR)).isNotEmpty();
        }

        /** A ceiling a request overshot is the caller's mistake, not a platform fault, so it must not page anyone. */
        @Test
        void logsARefusalAsAWarning() {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            var aboveTheCeiling = SignatureLevel.TIMESTAMPED;

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(aboveTheCeiling), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOf(SigningEngineException.class);
            assertThat(messagesLoggedAt(Level.WARN))
                    .anySatisfy(
                            message -> assertThat(message).contains(profile.name()).contains(aboveTheCeiling.name()));
            assertThat(messagesLoggedAt(Level.ERROR)).isEmpty();
        }

        @Test
        void namesTheWholeBatch_whenABatchWideGateRefuses() {
            // given: a target above the ceiling every document shares
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();

            // when
            ThrowingCallable sign = () -> engine
                    .sign(batchOf(SignatureLevel.TIMESTAMPED, "first", "second"), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOf(SigningEngineException.class);
            assertThat(messagesLoggedAt(Level.WARN))
                    .anySatisfy(message -> assertThat(message).contains("of the batch"));
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        private List<String> messagesLoggedAt(Level level) {
            return logged.list
                    .stream()
                    .filter(event -> event.getLevel() == level)
                    .map(ILoggingEvent::getFormattedMessage)
                    .toList();
        }

        private static Logger engineLogger() {
            return (Logger) LoggerFactory.getLogger(ManagedContentSigningEngine.class);
        }
    }

    // ── Recording ─────────────────────────────────────────────────────────────

    @Nested
    class Recording {

        @Test
        void recordsTheSigning_whenTheDocumentIsSigned() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            var recordSource = stubRecordSource();

            // when
            engine.sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            verify(signingRecordStrategy).recordSigning(any(), eq(List.of(recordSource)));
        }

        @Test
        void recordsTheSigningTimeTheSignatureWasBuiltWith() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            engine.sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<Instant> captured = ArgumentCaptor.forClass(Instant.class);
            verify(recordFactory).source(any(), any(), any(), any(), any(), captured.capture(), any());
            assertThat(captured.getValue()).isEqualTo(PLATFORM_TIME);
        }

        @Test
        void returnsEachDocumentsRecordReference_whenTheProfileRecords() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbsEchoingEachDocument();
            when(acquisitions.signDtbs(any(), any()))
                    .thenReturn(List.of("signature-1".getBytes(), "signature-2".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubRecordSource();
            var firstRecord = UUID.randomUUID();
            var secondRecord = UUID.randomUUID();
            when(signingRecordStrategy.recordSigning(any(), any())).thenReturn(List.of(firstRecord, secondRecord));

            // when
            List<SignedItem> signed = engine
                    .sign(batchOf(SignatureLevel.SIGNED, "first", "second"), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThat(signed).extracting(SignedItem::signingRecordUuid).containsExactly(firstRecord, secondRecord);
        }

        @Test
        void returnsNoRecordReference_whenTheProfileRecordsNothing() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbsEchoingEachDocument();
            when(acquisitions.signDtbs(any(), any()))
                    .thenReturn(List.of("signature-1".getBytes(), "signature-2".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubRecordSource();
            when(signingRecordStrategy.recordSigning(any(), any())).thenReturn(List.of());

            // when
            List<SignedItem> signed = engine
                    .sign(batchOf(SignatureLevel.SIGNED, "first", "second"), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThat(signed).extracting(SignedItem::signingRecordUuid).containsOnlyNulls();
        }

        @Test
        void recordsNoDocument_whenALaterDocumentFailsToComplete() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubBatchSignedUpToTheTimestampEmbed();
            when(formattingClient.embedSignatureTimestamp(any(), any()))
                    .thenReturn(signedDocumentResponse("timestamped document".getBytes()),
                            new SignedDocumentResponseDto());
            stubRecordSource();

            // when
            ThrowingCallable sign = () -> engine
                    .sign(batchOf(SignatureLevel.TIMESTAMPED, "first", "second"), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOf(SigningEngineException.class);
            verify(signingRecordStrategy, never()).recordSigning(any(), any());
        }

        @Test
        void failsTheRun_whenStagingFails() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signDtbs(any(), any())).thenReturn(List.of("signature".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubRecordSource();
            doThrow(new RuntimeException("outbox down")).when(signingRecordStrategy).recordSigning(any(), any());

            // when
            ThrowingCallable sign = () -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.STEP_FAILED);
                assertThat(thrown.step()).isEqualTo("stageSigningRecords");
                assertThat(thrown.itemIdentifier()).isNull();
            });
        }
    }

    // ── Batches ───────────────────────────────────────────────────────────────

    @Nested
    class Batches {

        @Test
        void signsEveryDocumentWithOneSignerCall() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbsEchoingEachDocument();
            when(acquisitions.signDtbs(any(), any()))
                    .thenReturn(List.of("signature-1".getBytes(), "signature-2".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            List<SignedItem> signed = engine
                    .sign(batchOf(SignatureLevel.SIGNED, "first", "second"), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThat(signed).extracting(SignedItem::identifier).containsExactly("first", "second");
            verify(acquisitions).signDtbs(eq(profile), argThat(dtbsListOf(dtbsOf("first"), dtbsOf("second"))));
        }

        @Test
        void refusesBeforeAnyConnectorCall_whenAnIdentifierRepeats() {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            var repeated = "same";

            // when
            ThrowingCallable sign = () -> engine
                    .sign(batchOf(SignatureLevel.SIGNED, repeated, repeated), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
                assertThat(thrown.itemIdentifier()).isEqualTo(repeated);
            });
            verifyNoInteractions(formattingClient);
        }

        @Test
        void namesTheDocument_whenItsBindingFails() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            var foreignEchoed = "second";
            stubComputeDtbsEchoingForeignDigestFor(foreignEchoed);

            // when
            ThrowingCallable sign = () -> engine
                    .sign(batchOf(SignatureLevel.SIGNED, "first", foreignEchoed), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.BINDING_VIOLATION);
                assertThat(thrown.itemIdentifier()).isEqualTo(foreignEchoed);
            });
            verify(acquisitions, never()).signDtbs(any(), any());
        }

        @Test
        void namesTheDocument_whenItsTimestampEmbedFails() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            var failingDocument = "second";
            stubBatchSignedUpToTheTimestampEmbed();
            when(formattingClient.embedSignatureTimestamp(any(), any()))
                    .thenReturn(signedDocumentResponse("timestamped document".getBytes()),
                            new SignedDocumentResponseDto());

            // when
            ThrowingCallable sign = () -> engine
                    .sign(batchOf(SignatureLevel.TIMESTAMPED, "first", failingDocument), aSigningProfile().build(),
                            profile, SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
                assertThat(thrown.itemIdentifier()).isEqualTo(failingDocument);
            });
        }

        @Test
        void namesTheDocument_whenAnUncheckedFailureBreaksIt() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            var brokenDocument = "second";
            stubComputeDtbsEchoingEachDocument();
            when(acquisitions.signDtbs(any(), any()))
                    .thenReturn(List.of("signature-1".getBytes(), "signature-2".getBytes()));
            when(formattingClient.embedSignatureValue(any(), any(EmbedSignatureValueRequestDto.class)))
                    .thenReturn(signedDocumentResponse("signed document".getBytes()))
                    .thenThrow(new IllegalStateException("connector client lookup failed"));

            // when
            ThrowingCallable sign = () -> engine
                    .sign(batchOf(SignatureLevel.SIGNED, "first", brokenDocument), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.STEP_FAILED);
                assertThat(thrown.itemIdentifier()).isEqualTo(brokenDocument);
            });
        }

        @Test
        void namesTheDocument_whenTheProviderFailsToSignIt() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            var unsignedDocument = "second";
            var unsignedIndex = 1;
            stubComputeDtbsEchoingEachDocument();
            when(acquisitions.signDtbs(any(), any()))
                    .thenThrow(new ItemSigningException(SigningEngineFailure.SIGNER_FAULT, unsignedIndex,
                            "no signature for item " + unsignedIndex, "Internal signing error"));

            // when
            ThrowingCallable sign = () -> engine
                    .sign(batchOf(SignatureLevel.SIGNED, "first", unsignedDocument), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThatThrownBy(sign).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
                assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.SIGNER_FAULT);
                assertThat(thrown.itemIdentifier()).isEqualTo(unsignedDocument);
            });
        }

        @Test
        void keepsEachDocumentsOwnTimestampSerial() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbsEchoingEachDocument();
            when(acquisitions.signDtbs(any(), any()))
                    .thenReturn(List.of("signature-1".getBytes(), "signature-2".getBytes()));
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32]);
            var firstSerial = BigInteger.valueOf(0x2a);
            var secondSerial = BigInteger.valueOf(0x2b);
            stubIssuedTimestamps(firstSerial, secondSerial);
            stubEmbedSignatureTimestamp("timestamped document".getBytes());

            // when
            List<SignedItem> signed = engine
                    .sign(batchOf(SignatureLevel.TIMESTAMPED, "first", "second"), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThat(signed)
                    .extracting(item -> item.content().timestampSerials())
                    .containsExactly(List.of(firstSerial), List.of(secondSerial));
        }

        @Test
        void embedsEachDocumentsOwnSignature() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbsEchoingEachDocument();
            stubSignatureOverEachDtbs();
            stubEmbedSignatureValueNamingItsInputs();

            // when
            List<SignedItem> signed = engine
                    .sign(batchOf(SignatureLevel.SIGNED, "first", "second"), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            assertThat(signed)
                    .extracting(item -> new String(item.content().signedDocument()))
                    .containsExactly(signedDocumentOf("first"), signedDocumentOf("second"));
        }

        @Test
        void recordsEachDocumentWithItsOwnSignature() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbsEchoingEachDocument();
            stubSignatureOverEachDtbs();
            stubEmbedSignatureValueNamingItsInputs();
            stubRecordSource();

            // when
            engine
                    .sign(batchOf(SignatureLevel.SIGNED, "first", "second"), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            verifyRecordedWithItsOwnSignature("first");
            verifyRecordedWithItsOwnSignature("second");
        }

        // ── Helpers ───────────────────────────────────────────────────────────

        /** Each signature names the DTBS it signs. A signature handed to another document thus shows in its result. */
        private void stubSignatureOverEachDtbs() throws SigningEngineException {
            when(acquisitions.signDtbs(any(), any())).thenAnswer(invocation -> {
                List<byte[]> dtbsList = invocation.getArgument(1);
                return dtbsList.stream().map(Batches::signatureOver).toList();
            });
        }

        private void stubEmbedSignatureValueNamingItsInputs() throws SigningEngineException {
            when(formattingClient.embedSignatureValue(any(), any(EmbedSignatureValueRequestDto.class)))
                    .thenAnswer(invocation -> {
                        EmbedSignatureValueRequestDto embed = invocation.getArgument(1);
                        String signedDocument = documentSignedWith(embed.getFormattingContext(),
                                embed.getSignatureValue());
                        return signedDocumentResponse(signedDocument.getBytes());
                    });
        }

        private void verifyRecordedWithItsOwnSignature(String identifier) {
            byte[] dtbs = dtbsOf(identifier);
            verify(recordFactory)
                    .source(any(), any(), argThat(
                            content -> new String(content.signedDocument()).equals(signedDocumentOf(identifier))),
                            aryEq(dtbs), aryEq(signatureOver(dtbs)), any(), any());
        }

        private static String signedDocumentOf(String identifier) {
            return documentSignedWith(contextOf(identifier), signatureOver(dtbsOf(identifier)));
        }

        private static String documentSignedWith(byte[] formattingContext, byte[] signatureValue) {
            return new String(formattingContext) + " signed with " + new String(signatureValue);
        }

        private static byte[] signatureOver(byte[] dtbs) {
            return ("signature over " + new String(dtbs)).getBytes();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ResolvedManagedContentSigningProfile aSignedOnlyProfile() {
        return aSignedOnlyProfileOf(SignatureFamily.PADES);
    }

    private static ResolvedManagedContentSigningProfile aSignedOnlyProfileOf(SignatureFamily family) {
        return aResolvedContentSigningProfile().withMaxLevel(SignatureLevel.SIGNED).withFamily(family).build();
    }

    private static ResolvedManagedContentSigningProfile aTimestampingProfile() {
        return aTimestampingProfileOf(SignatureFamily.PADES);
    }

    private static ResolvedManagedContentSigningProfile aTimestampingProfileOf(SignatureFamily family) {
        return aResolvedContentSigningProfile()
                .withMaxLevel(SignatureLevel.TIMESTAMPED)
                .withTimestampSourceProfileName("internal-tsa")
                .withFamily(family)
                .build();
    }

    private static List<CryptographicKeyItemOperationModel> signingKeyItems() {
        return List
                .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                        CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA));
    }

    private static ResolvedManagedContentSigningProfile profileWithCertificate(SigningCertificate certificate) {
        return profileWithKeyItems(certificate, signingKeyItems());
    }

    private static ResolvedManagedContentSigningProfile profileWithKeyItems(SigningCertificate certificate,
            List<CryptographicKeyItemOperationModel> keyItems) {
        return profileWithKeyItems(certificate, keyItems, CertificatePurposeRequirements.NONE);
    }

    private static ResolvedManagedContentSigningProfile profileWithCertificatePurpose(SigningCertificate certificate,
            CertificatePurposeRequirements certificatePurpose) {
        return profileWithKeyItems(certificate, signingKeyItems(), certificatePurpose);
    }

    private static ResolvedManagedContentSigningProfile profileWithKeyItems(SigningCertificate certificate,
            List<CryptographicKeyItemOperationModel> keyItems, CertificatePurposeRequirements certificatePurpose) {
        return aResolvedContentSigningProfile()
                .withMaxLevel(SignatureLevel.TIMESTAMPED)
                .withTimestampSourceProfileName("internal-tsa")
                .withCertificatePurpose(certificatePurpose)
                .withResolvedScheme(new ResolvedStaticKeyManagedSigning(certificate, keyItems, null, List.of()))
                .build();
    }

    private static ContentSigningRequest request(SignatureLevel target) {
        return requestFor(target, DocumentTransferMode.INLINE, null);
    }

    /** The document travels inline, or as its SHA-256 digest. */
    private static ContentSigningRequest requestFor(SignatureLevel target, DocumentTransferMode transferMode,
            SignatureParametersDto signatureParameters) {
        byte[] content = transferMode == DocumentTransferMode.INLINE ? DOCUMENT : digestOf(DOCUMENT);
        ContentSigningItem item = new ContentSigningItem(DOCUMENT_IDENTIFIER, content, digestOf(DOCUMENT));
        return new ContentSigningRequest(target, transferMode, DigestAlgorithm.SHA_256, List.of(item),
                signatureParameters);
    }

    private static ContentSigningRequest batchOf(SignatureLevel target, String... identifiers) {
        List<ContentSigningItem> items = Arrays
                .stream(identifiers)
                .map(identifier -> new ContentSigningItem(identifier, documentNamed(identifier),
                        digestOf(documentNamed(identifier))))
                .toList();
        return new ContentSigningRequest(target, DocumentTransferMode.INLINE, DigestAlgorithm.SHA_256, items, null);
    }

    private static byte[] documentNamed(String identifier) {
        return ("document " + identifier).getBytes();
    }

    private static byte[] dtbsOf(String identifier) {
        return ("dtbs of " + identifier).getBytes();
    }

    private static byte[] contextOf(String identifier) {
        return ("context of " + identifier).getBytes();
    }

    private static ArgumentMatcher<List<byte[]>> dtbsListOf(byte[]... expected) {
        return dtbsList -> dtbsList.size() == expected.length
                && IntStream.range(0, expected.length).allMatch(i -> Arrays.equals(dtbsList.get(i), expected[i]));
    }

    private void stubComputeDtbs(byte[] echoedDigest) throws SigningEngineException {
        when(formattingClient.computeDtbs(any(), any())).thenReturn(dtbsResponse("dtbs".getBytes(), echoedDigest));
    }

    /**
     * Answers each document's {@code computeDtbs} with a DTBS and formatting context of its own and an echo of its own
     * digest.
     */
    private void stubComputeDtbsEchoingEachDocument() throws SigningEngineException {
        when(formattingClient.computeDtbs(any(), any())).thenAnswer(invocation -> {
            byte[] document = documentOf(invocation.getArgument(1));
            return ownDtbsResponse(identifierOf(document), digestOf(document));
        });
    }

    /** Answers like {@link #stubComputeDtbsEchoingEachDocument()}, except that one document's echo is foreign. */
    private void stubComputeDtbsEchoingForeignDigestFor(String identifier) throws SigningEngineException {
        when(formattingClient.computeDtbs(any(), any())).thenAnswer(invocation -> {
            byte[] document = documentOf(invocation.getArgument(1));
            String documentIdentifier = identifierOf(document);
            byte[] echoed = documentIdentifier.equals(identifier)
                    ? digestOf("another document".getBytes())
                    : digestOf(document);
            return ownDtbsResponse(documentIdentifier, echoed);
        });
    }

    private SigningRecordInputSource stubRecordSource() {
        var recordSource = mock(SigningRecordInputSource.class);
        when(recordFactory.source(any(), any(), any(), any(), any(), any(), any())).thenReturn(recordSource);
        return recordSource;
    }

    /** Stubs a two-document batch through both signatures and both issued timestamps, serials 0x2a and 0x2b. */
    private void stubBatchSignedUpToTheTimestampEmbed() throws SigningEngineException {
        stubComputeDtbsEchoingEachDocument();
        when(acquisitions.signDtbs(any(), any()))
                .thenReturn(List.of("signature-1".getBytes(), "signature-2".getBytes()));
        stubEmbedSignatureValue("signed document".getBytes());
        stubSignatureTimestampImprint(new byte[32]);
        stubIssuedTimestamps(BigInteger.valueOf(0x2a), BigInteger.valueOf(0x2b));
    }

    private static byte[] documentOf(ComputeDtbsRequestDto request) {
        return ((InlineDocumentTransferDto) request.getDocument()).document();
    }

    private static String identifierOf(byte[] document) {
        return new String(document).substring("document ".length());
    }

    private static ComputeDtbsResponseDto ownDtbsResponse(String identifier, byte[] echoedDigest) {
        ComputeDtbsResponseDto response = dtbsResponse(dtbsOf(identifier), echoedDigest);
        response.setFormattingContext(contextOf(identifier));
        return response;
    }

    private static ComputeDtbsResponseDto dtbsResponse(byte[] dtbs, byte[] echoedDigest) {
        ComputeDtbsResponseDto response = new ComputeDtbsResponseDto();
        response.setDtbs(dtbs);
        response.setDocumentDigest(echoedDigest);
        response.setDocumentDigestAlgorithm(DigestAlgorithm.SHA_256);
        response.setFormattingContext("context".getBytes());
        return response;
    }

    private void stubEmbedSignatureValue(byte[] signedDocument) throws SigningEngineException {
        when(formattingClient.embedSignatureValue(any(), any(EmbedSignatureValueRequestDto.class)))
                .thenReturn(signedDocumentResponse(signedDocument));
    }

    private void stubSignatureTimestampImprint(byte[] imprint) throws SigningEngineException {
        stubSignatureTimestampImprint(imprint, DigestAlgorithm.SHA_256);
    }

    private void stubSignatureTimestampImprint(byte[] imprint, DigestAlgorithm algorithm)
            throws SigningEngineException {
        TimestampImprintResponseDto response = new TimestampImprintResponseDto();
        response.setImprint(imprint);
        response.setDigestAlgorithm(algorithm);
        when(formattingClient.computeSignatureTimestampImprint(any(), any())).thenReturn(response);
    }

    private void stubIssuedTimestamp(BigInteger serialNumber) throws SigningEngineException {
        when(acquisitions.timestampSignature(any(), any(), any())).thenReturn(issuedTimestamp(serialNumber));
    }

    private void stubIssuedTimestamps(BigInteger firstSerial, BigInteger secondSerial) throws SigningEngineException {
        when(acquisitions.timestampSignature(any(), any(), any()))
                .thenReturn(issuedTimestamp(firstSerial), issuedTimestamp(secondSerial));
    }

    private static IssuedTimestamp issuedTimestamp(BigInteger serialNumber) {
        return new IssuedTimestamp("token".getBytes(), serialNumber, Instant.EPOCH);
    }

    private void stubEmbedSignatureTimestamp(byte[] document) throws SigningEngineException {
        when(formattingClient.embedSignatureTimestamp(any(), any())).thenReturn(signedDocumentResponse(document));
    }

    private static SignedDocumentResponseDto signedDocumentResponse(byte[] document) {
        SignedDocumentResponseDto response = new SignedDocumentResponseDto();
        response.setSignedDocument(document);
        return response;
    }

    private static byte[] digestOf(byte[] content) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(content);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
