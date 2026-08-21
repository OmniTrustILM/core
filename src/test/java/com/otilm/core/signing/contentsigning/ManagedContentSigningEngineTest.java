package com.otilm.core.signing.contentsigning;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsRequestDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.ComputeDtbsResponseDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DigestOnlyDocumentTransferDto;
import com.otilm.api.model.connector.signatures.contentsigning.common.DocumentTransferDto;
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
import com.otilm.api.model.messaging.timequality.TimeQualityStatus;
import com.otilm.core.model.crypto.CryptographicKeyItemModel;
import com.otilm.core.model.crypto.CryptographicKeyItemModelFixtures;
import com.otilm.core.model.signing.SigningCertificate;
import com.otilm.core.model.signing.SigningCertificateBuilder;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.model.signing.resolved.ResolvedStaticKeyManagedSigning;
import com.otilm.core.signing.contentsigning.acquisition.ContentSigningAcquisitions;
import com.otilm.core.signing.contentsigning.formatting.ContentSigningFormattingClient;
import com.otilm.core.signing.engine.CertificateChain;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidator;
import com.otilm.core.signing.engine.certificate.SigningCertificateValidatorFactory;
import com.otilm.core.signing.engine.certificate.StaticKeyManagedSigningCertificateValidator;
import com.otilm.core.signing.engine.certificate.ValidationResult;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.record.SigningRecordStrategy;
import com.otilm.core.signing.record.SigningRecordStrategyFactory;
import com.otilm.core.signing.tsa.messages.IssuedTimestamp;
import com.otilm.core.signing.tsa.messages.TimestampImprint;
import com.otilm.core.signing.tsa.timequality.TimeQualityRegister;
import com.otilm.core.util.clocksource.TestClockSource;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.slf4j.LoggerFactory;

import static com.otilm.core.util.builders.ResolvedManagedContentSigningProfileBuilder.aResolvedContentSigningProfile;
import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.catchThrowableOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ManagedContentSigningEngineTest {

    private static final byte[] DOCUMENT = "a document".getBytes();

    private static final Instant PLATFORM_TIME = Instant.parse("2026-03-04T11:25:00Z");

    @Mock
    ContentSigningFormattingClient formattingClient;
    @Mock
    ContentSigningAcquisitions acquisitions;
    @Mock
    TimeQualityRegister timeQualityRegister;
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
    void createEngine() throws SigningEngineException {
        engine = new ManagedContentSigningEngine(formattingClient, acquisitions, timeQualityRegister,
                signingCertificateValidatorFactory, TestClockSource.ofWallTime(PLATFORM_TIME),
                signingRecordStrategyFactory, recordFactory);
        lenient().when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.OK);
        lenient().when(signingRecordStrategyFactory.strategyFor(any())).thenReturn(signingRecordStrategy);
        lenient().when(signingCertificateValidatorFactory.getValidator(any())).thenReturn(signingCertificateValidator);
        lenient()
                .when(signingCertificateValidator.validate(any(), any(), anyBoolean()))
                .thenReturn(ValidationResult.ok());
    }

    @Nested
    class SignedPath {

        @Test
        void signsToSignedLevelThroughComputeAndEmbed() throws SigningEngineException {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(profile, "dtbs".getBytes())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            SignedContent signed = engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThat(signed.signedDocument()).isEqualTo("signed document".getBytes());
            assertThat(signed.level()).isEqualTo(SignatureLevel.SIGNED);
            assertThat(signed.timestampSerials()).isEmpty();
            verify(formattingClient, never()).computeSignatureTimestampImprint(any(), any());
        }

        @Test
        void passesThePlatformsSigningTimeAndTheProfilesAttributesToComputeDtbs() throws SigningEngineException {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
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
        void replaysTheFormattingContextVerbatimWhenEmbeddingTheSignature() throws SigningEngineException {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            engine.sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<EmbedSignatureValueRequestDto> captured = ArgumentCaptor
                    .forClass(EmbedSignatureValueRequestDto.class);
            verify(formattingClient).embedSignatureValue(any(), captured.capture());
            assertThat(captured.getValue().getFormattingContext()).isEqualTo("context".getBytes());
            assertThat(captured.getValue().getSignatureValue()).isEqualTo("signature".getBytes());
            assertThat(captured.getValue().getFamily()).isEqualTo(profile.family());
        }

        @Test
        void refusesWhenTheConnectorAnswersTheEmbedWithNoSignedDocument() throws SigningEngineException {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            when(formattingClient.embedSignatureValue(any(), any(EmbedSignatureValueRequestDto.class)))
                    .thenReturn(new SignedDocumentResponseDto());

            // when
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
            assertThat(thrown.step()).isEqualTo("embedSignatureValue");
            assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
        }

        @Test
        void refusesWhenTheProfilesSigningChainCannotBeEncoded() throws Exception {
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
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
            verify(acquisitions, never()).signatureValue(any(), any());
        }
    }

    @Nested
    class TimestampedPath {

        @Test
        void raisesTheSignatureToTimestampedThroughTheInProcessBridge() throws SigningEngineException {
            // given: the ceiling admits TIMESTAMPED, so both gates pass and the leg itself carries the run
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.valueOf(0x2a));
            stubEmbedSignatureTimestamp("timestamped document".getBytes());

            // when
            SignedContent signed = engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then: the document is the embed's output and the serial is traceable to its timestamp record
            assertThat(signed.signedDocument()).isEqualTo("timestamped document".getBytes());
            assertThat(signed.level()).isEqualTo(SignatureLevel.TIMESTAMPED);
            assertThat(signed.timestampSerials()).containsExactly(BigInteger.valueOf(0x2a));
        }

        @Test
        void timestampsExactlyTheImprintTheConnectorReturned() throws SigningEngineException {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            byte[] imprintValue = new byte[32];
            imprintValue[0] = 7;
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
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
            verify(acquisitions).signatureTimestamp(eq(profile), captured.capture(), any());
            assertThat(captured.getValue().algorithm()).isEqualTo(DigestAlgorithm.SHA_256);
            assertThat(captured.getValue().value()).isEqualTo(imprintValue);
        }

        @Test
        void embedsTheTokenTheTimestampSourceIssuedIntoTheSignedDocument() throws SigningEngineException {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());
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
            assertThat(captured.getValue().getSignedDocument()).isEqualTo("signed document".getBytes());
            assertThat(captured.getValue().getFamily()).isEqualTo(profile.family());
        }

        @Test
        void stopsAtSignedWhenThatIsWhatWasAskedForEvenOnATimestampingProfile() throws SigningEngineException {
            // given: the ceiling permits TIMESTAMPED but the request asks for SIGNED
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            SignedContent signed = engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThat(signed.level()).isEqualTo(SignatureLevel.SIGNED);
            verify(acquisitions, never()).signatureTimestamp(any(), any(), any());
        }

        @Test
        void sendsTheOriginalContentAlongsideADetachedSignature() throws SigningEngineException {
            // given: a detached signature does not envelop what it signs, so the imprint needs the content beside it
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            DigestOnlyDocumentTransferDto digestOnly = new DigestOnlyDocumentTransferDto(digestOf(DOCUMENT),
                    DigestAlgorithm.SHA_256);
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.ONE);
            stubEmbedSignatureTimestamp("timestamped document".getBytes());

            // when
            engine
                    .sign(requestFor(SignatureLevel.TIMESTAMPED, digestOnly), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<SignedDocumentRequestDto> captured = ArgumentCaptor.forClass(SignedDocumentRequestDto.class);
            verify(formattingClient).computeSignatureTimestampImprint(any(), captured.capture());
            assertThat(captured.getValue().getDetachedContent()).isEqualTo(digestOnly);
        }

        @Test
        void sendsNoDetachedContentAlongsideAnEnvelopedSignature() throws SigningEngineException {
            // given: an enveloped document already carries its content, so repeating it would be redundant
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
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
        void refusesWhenTheConnectorAnswersTheImprintWithNothingToStamp() throws SigningEngineException {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(null);

            // when
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
            assertThat(thrown.step()).isEqualTo("computeSignatureTimestampImprint");
            assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
            verify(acquisitions, never()).signatureTimestamp(any(), any(), any());
        }

        @Test
        void refusesWhenTheConnectorNamesNoAlgorithmForTheImprint() throws SigningEngineException {
            // given: a digest cannot be stamped without knowing which algorithm produced it
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32], null);

            // when
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
            assertThat(thrown.step()).isEqualTo("computeSignatureTimestampImprint");
            verify(acquisitions, never()).signatureTimestamp(any(), any(), any());
        }

        @Test
        void refusesWhenTheConnectorAnswersTheTimestampEmbedWithNoSignedDocument() throws SigningEngineException {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.ONE);
            when(formattingClient.embedSignatureTimestamp(any(), any())).thenReturn(new SignedDocumentResponseDto());

            // when
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.CONNECTOR_FAULT);
            assertThat(thrown.step()).isEqualTo("embedSignatureTimestamp");
            assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
        }
    }

    @Nested
    class Gates {

        @Test
        void refusesToReleaseTheKeyWhenTheEchoedDigestIsNotTheAuthorizedOne() throws SigningEngineException {
            // given: the connector echoes a digest of a different document
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf("another document".getBytes()));

            // when
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then: the binding violation is its own failure class, and no key was used
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.BINDING_VIOLATION);
            verify(acquisitions, never()).signatureValue(any(), any());
            verify(formattingClient, never()).embedSignatureValue(any(), any());
        }

        @Test
        void refusesATargetAboveTheProfileCeiling() throws SigningEngineException {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();

            // when
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            assertThat(thrown.clientMessage()).contains("TIMESTAMPED");
            verify(formattingClient, never()).computeDtbs(any(), any());
        }

        @Test
        void refusesATargetAboveTheRungsTheEngineExecutes() throws SigningEngineException {
            // given: a profile whose ceiling is LONG_TERM, which no step reaches yet
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(SignatureLevel.LONG_TERM)
                    .build();

            // when
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.LONG_TERM), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
            assertThat(thrown.clientMessage()).contains("LONG_TERM");
            verify(formattingClient, never()).computeDtbs(any(), any());
        }

        @Test
        void acceptsATargetBelowTheProfileCeiling() throws SigningEngineException {
            // given: a ceiling above the target must not be mistaken for an over-rung request
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(SignatureLevel.TIMESTAMPED)
                    .build();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            SignedContent signed = engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThat(signed.level()).isEqualTo(SignatureLevel.SIGNED);
        }

        @Test
        void refusesToSignWhenTheTimeReferenceIsNotTrustworthy() throws SigningEngineException {
            // given: signingTime is minted by the platform, so an untrustworthy clock must stop the run
            when(timeQualityRegister.getStatus(any())).thenReturn(TimeQualityStatus.DEGRADED);
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();

            // when
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.TIME_UNAVAILABLE);
            assertThat(thrown.clientMessage()).doesNotContain("DEGRADED");
            verify(formattingClient, never()).computeDtbs(any(), any());
        }
    }

    @Nested
    class Augmentation {

        @Test
        void timestampsAForeignSignedDocumentWithoutSigningIt() throws SigningEngineException {
            // given: a document signed elsewhere, entering at the signature-timestamp imprint
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.ONE);
            stubEmbedSignatureTimestamp("timestamped foreign document".getBytes());

            // when
            SignedContent signed = engine
                    .augment(new AugmentationRequest(SignatureLevel.TIMESTAMPED, "foreign document".getBytes(), null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then: no key was released and no DTBS was computed
            assertThat(signed.level()).isEqualTo(SignatureLevel.TIMESTAMPED);
            assertThat(signed.timestampSerials()).containsExactly(BigInteger.ONE);
            verify(formattingClient, never()).computeDtbs(any(), any());
            verify(acquisitions, never()).signatureValue(any(), any());
        }

        /**
         * Augmentation exists to raise a signature after the fact, so the profile's own certificate no longer being fit
         * to sign must not block it: this path releases no key of that certificate's scheme.
         */
        @Test
        void augmentsWithASigningCertificateThatIsNoLongerFitToSign() throws SigningEngineException {
            // given: a certificate a signing run would refuse, on a path that releases none of the profile's own keys
            ResolvedManagedContentSigningProfile profile = profileWithCertificate(
                    SigningCertificateBuilder.aSigningCertificate().state(CertificateState.REVOKED).build());
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.ONE);
            stubEmbedSignatureTimestamp("timestamped foreign document".getBytes());

            // when
            SignedContent signed = engine
                    .augment(new AugmentationRequest(SignatureLevel.TIMESTAMPED, "foreign document".getBytes(), null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThat(signed.level()).isEqualTo(SignatureLevel.TIMESTAMPED);
            assertThat(signed.timestampSerials()).containsExactly(BigInteger.ONE);
            verify(signingCertificateValidatorFactory, never()).getValidator(any());
        }

        @Test
        void refusesAnAugmentationTargetOfSignedBecauseTheDocumentIsAlreadySigned() {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();

            // when
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .augment(new AugmentationRequest(SignatureLevel.SIGNED, "foreign document".getBytes(), null),
                            aSigningProfile().build(), profile, SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
        }

        @Test
        void refusesAnAugmentationTargetAboveTheRungsTheEngineExecutes() {
            // given
            ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                    .withMaxLevel(SignatureLevel.ARCHIVAL)
                    .build();

            // when
            SigningEngineException thrown = catchThrowableOfType(
                    () -> engine
                            .augment(new AugmentationRequest(SignatureLevel.ARCHIVAL, "foreign document".getBytes(),
                                    null), aSigningProfile().build(), profile, SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.INVALID_INPUT);
        }
    }

    /**
     * The Signing Profile model a run reads is cached, so these conditions are the ones that can arise after the
     * profile was saved with an acceptable certificate. The real validator stands in for the mock, so each condition is
     * a certificate state rather than a canned verdict.
     */
    @Nested
    class SigningCertificateGate {

        private static final String REFUSAL_DETAIL = "Signing certificate is not acceptable for content_signing";

        @BeforeEach
        void useTheRealValidator() throws SigningEngineException {
            when(signingCertificateValidatorFactory.getValidator(any()))
                    .thenReturn(new StaticKeyManagedSigningCertificateValidator());
        }

        @Test
        void refusesToSignWithARevokedCertificate() {
            // given
            ResolvedManagedContentSigningProfile profile = profileWithCertificate(
                    SigningCertificateBuilder.aSigningCertificate().state(CertificateState.REVOKED).build());

            // when
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            assertThat(thrown.operatorMessage()).contains(REFUSAL_DETAIL).contains(profile.name());
            assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
            assertThat(thrown.clientMessage()).doesNotContain(REFUSAL_DETAIL).doesNotContain(profile.name());
        }

        @Test
        void refusesToSignWithAnArchivedCertificate() {
            // given
            ResolvedManagedContentSigningProfile profile = profileWithCertificate(
                    SigningCertificateBuilder.aSigningCertificate().archived(true).build());

            // when
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            assertThat(thrown.operatorMessage()).contains(REFUSAL_DETAIL).contains(profile.name());
            assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
            assertThat(thrown.clientMessage()).doesNotContain(REFUSAL_DETAIL).doesNotContain(profile.name());
        }

        @Test
        void refusesToSignWithADeactivatedSigningKey() {
            // given
            ResolvedManagedContentSigningProfile profile = profileWithKeyItems(SigningCertificateBuilder.valid(),
                    List
                            .of(CryptographicKeyItemModelFixtures
                                    .keyItem(KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, KeyState.DEACTIVATED,
                                            List.of(KeyUsage.SIGN)),
                                    CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)));

            // when
            SigningEngineException thrown = catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            assertThat(thrown.operatorMessage()).contains(REFUSAL_DETAIL).contains(profile.name());
            assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
            assertThat(thrown.clientMessage()).doesNotContain(REFUSAL_DETAIL).doesNotContain(profile.name());
        }

        @Test
        void releasesNoKeyWhenTheCertificateIsUnacceptable() throws SigningEngineException {
            // given
            ResolvedManagedContentSigningProfile profile = profileWithCertificate(
                    SigningCertificateBuilder.aSigningCertificate().state(CertificateState.REVOKED).build());

            // when
            catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            verify(acquisitions, never()).signatureValue(any(), any());
            verify(formattingClient, never()).computeDtbs(any(), any());
        }

    }

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
        void logsAFailureAfterTheKeySignedWithTheStepTheLevelAndTheSerialAlreadyIssued() throws Exception {
            // given: the run dies embedding a timestamp that has already been issued
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.valueOf(0x2a));
            when(formattingClient.embedSignatureTimestamp(any(), any())).thenReturn(new SignedDocumentResponseDto());

            // when
            catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(messagesLoggedAt(Level.ERROR))
                    .anySatisfy(message -> assertThat(message)
                            .contains(profile.name())
                            .contains("embedSignatureTimestamp")
                            .contains("TIMESTAMPED")
                            .contains("2a"));
        }

        @Test
        void keepsTheSignedDocumentOutOfTheFailureLog() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubSignatureTimestampImprint(null);

            // when
            catchThrowableOfType(
                    () -> engine
                            .augment(new AugmentationRequest(SignatureLevel.TIMESTAMPED, "foreign document".getBytes(),
                                    null), aSigningProfile().build(), profile, SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then: the augmentation path logs, and never the bytes it was handed
            assertThat(messagesLoggedAt(Level.ERROR))
                    .isNotEmpty()
                    .allSatisfy(message -> assertThat(message).doesNotContain("foreign document"));
        }

        @Test
        void logsAnUncheckedFailureAfterTheKeySignedWithTheSerialAlreadyIssued() throws Exception {
            // given: the run dies unchecked embedding a timestamp that has already been issued
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());
            stubSignatureTimestampImprint(new byte[32]);
            stubIssuedTimestamp(BigInteger.valueOf(0x2a));
            when(formattingClient.embedSignatureTimestamp(any(), any()))
                    .thenThrow(new IllegalStateException("connector client lookup failed"));

            // when
            catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(messagesLoggedAt(Level.ERROR))
                    .anySatisfy(message -> assertThat(message).contains(profile.name()).contains("2a"));
        }

        @Test
        void funnelsAnUncheckedAugmentationFailureIntoAStepFailureWithoutLeakingItsDetail() throws Exception {
            // given
            ResolvedManagedContentSigningProfile profile = aTimestampingProfile();
            when(formattingClient.computeSignatureTimestampImprint(any(), any()))
                    .thenThrow(new IllegalStateException("attribute cache is down"));

            // when
            SigningEngineException thrown = catchThrowableOfType(
                    () -> engine
                            .augment(new AugmentationRequest(SignatureLevel.TIMESTAMPED, "foreign document".getBytes(),
                                    null), aSigningProfile().build(), profile, SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.STEP_FAILED);
            assertThat(thrown.clientMessage()).isEqualTo("Internal error during signing");
            assertThat(thrown.getCause()).hasMessage("attribute cache is down");
            assertThat(messagesLoggedAt(Level.ERROR)).isNotEmpty();
        }

        /** A ceiling a request overshot is the caller's mistake, not a platform fault, so it must not page anyone. */
        @Test
        void logsARefusalAsAWarning() {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();

            // when
            catchThrowableOfType(() -> engine
                    .sign(request(SignatureLevel.TIMESTAMPED), aSigningProfile().build(), profile,
                            SigningProtocol.CSC_API),
                    SigningEngineException.class);

            // then
            assertThat(messagesLoggedAt(Level.WARN))
                    .anySatisfy(message -> assertThat(message).contains(profile.name()).contains("TIMESTAMPED"));
            assertThat(messagesLoggedAt(Level.ERROR)).isEmpty();
        }

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

    @Nested
    class Recording {

        @Test
        void recordsTheSigningOnceTheDocumentIsSigned() throws SigningEngineException {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            engine.sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            verify(recordFactory).source(any(), any(), any(), any(), any(), any(), any());
            verify(signingRecordStrategy).recordSigning(any());
        }

        @Test
        void recordsTheSigningTimeTheSignatureWasBuiltWith() throws SigningEngineException {
            // given
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());

            // when
            engine.sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            ArgumentCaptor<Instant> captured = ArgumentCaptor.forClass(Instant.class);
            verify(recordFactory).source(any(), any(), any(), any(), any(), captured.capture(), any());
            assertThat(captured.getValue()).isEqualTo(PLATFORM_TIME);
        }

        @Test
        void keepsTheSignedDocumentWhenRecordingFails() throws SigningEngineException {
            // given: the signature is already made, so a recording failure must not withdraw it
            ResolvedManagedContentSigningProfile profile = aSignedOnlyProfile();
            stubComputeDtbs(digestOf(DOCUMENT));
            when(acquisitions.signatureValue(any(), any())).thenReturn("signature".getBytes());
            stubEmbedSignatureValue("signed document".getBytes());
            doThrow(new RuntimeException("outbox down")).when(signingRecordStrategy).recordSigning(any());

            // when
            SignedContent signed = engine
                    .sign(request(SignatureLevel.SIGNED), aSigningProfile().build(), profile, SigningProtocol.CSC_API);

            // then
            assertThat(signed.signedDocument()).isEqualTo("signed document".getBytes());
        }
    }

    private static ResolvedManagedContentSigningProfile aSignedOnlyProfile() {
        return aResolvedContentSigningProfile().withMaxLevel(SignatureLevel.SIGNED).build();
    }

    private static ResolvedManagedContentSigningProfile aTimestampingProfile() {
        return aResolvedContentSigningProfile()
                .withMaxLevel(SignatureLevel.TIMESTAMPED)
                .withTimestampSourceProfileName("internal-tsa")
                .build();
    }

    private static ResolvedManagedContentSigningProfile profileWithCertificate(SigningCertificate certificate) {
        return profileWithKeyItems(certificate,
                List
                        .of(CryptographicKeyItemModelFixtures.activeSigningPrivateKey(KeyAlgorithm.RSA),
                                CryptographicKeyItemModelFixtures.publicKey(KeyAlgorithm.RSA)));
    }

    private static ResolvedManagedContentSigningProfile profileWithKeyItems(SigningCertificate certificate,
            List<CryptographicKeyItemModel> keyItems) {
        return aResolvedContentSigningProfile()
                .withMaxLevel(SignatureLevel.TIMESTAMPED)
                .withTimestampSourceProfileName("internal-tsa")
                .withResolvedScheme(new ResolvedStaticKeyManagedSigning(certificate, keyItems, null, List.of()))
                .build();
    }

    private static ContentSigningRequest request(SignatureLevel target) {
        return requestFor(target, new InlineDocumentTransferDto(DOCUMENT));
    }

    private static ContentSigningRequest requestFor(SignatureLevel target, DocumentTransferDto document) {
        return new ContentSigningRequest(target, document,
                new DocumentDigest(DigestAlgorithm.SHA_256, digestOf(DOCUMENT)));
    }

    private void stubComputeDtbs(byte[] echoedDigest) throws SigningEngineException {
        ComputeDtbsResponseDto response = new ComputeDtbsResponseDto();
        response.setDtbs("dtbs".getBytes());
        response.setDocumentDigest(echoedDigest);
        response.setDocumentDigestAlgorithm(DigestAlgorithm.SHA_256);
        response.setFormattingContext("context".getBytes());
        when(formattingClient.computeDtbs(any(), any())).thenReturn(response);
    }

    private void stubEmbedSignatureValue(byte[] signedDocument) throws SigningEngineException {
        SignedDocumentResponseDto response = new SignedDocumentResponseDto();
        response.setSignedDocument(signedDocument);
        when(formattingClient.embedSignatureValue(any(), any(EmbedSignatureValueRequestDto.class)))
                .thenReturn(response);
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
        when(acquisitions.signatureTimestamp(any(), any(), any()))
                .thenReturn(new IssuedTimestamp("token".getBytes(), serialNumber, Instant.EPOCH));
    }

    private void stubEmbedSignatureTimestamp(byte[] document) throws SigningEngineException {
        SignedDocumentResponseDto response = new SignedDocumentResponseDto();
        response.setSignedDocument(document);
        when(formattingClient.embedSignatureTimestamp(any(), any())).thenReturn(response);
    }

    private static byte[] digestOf(byte[] content) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(content);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
