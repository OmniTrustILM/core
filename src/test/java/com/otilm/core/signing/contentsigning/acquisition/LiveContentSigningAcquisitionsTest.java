package com.otilm.core.signing.contentsigning.acquisition;

import com.otilm.api.model.common.enums.cryptography.DigestAlgorithm;
import com.otilm.api.model.common.enums.cryptography.SignatureAlgorithm;
import com.otilm.core.model.signing.resolved.ResolvedManagedContentSigningProfile;
import com.otilm.core.signing.engine.error.SigningEngineException;
import com.otilm.core.signing.engine.error.SigningEngineFailure;
import com.otilm.core.signing.engine.signer.Signer;
import com.otilm.core.signing.engine.signer.SignerFactory;
import com.otilm.core.signing.tsa.InternalTimestampSource;
import com.otilm.core.signing.tsa.messages.IssuedTimestamp;
import com.otilm.core.signing.tsa.messages.TimestampImprint;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.builders.ResolvedManagedContentSigningProfileBuilder.aResolvedContentSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LiveContentSigningAcquisitionsTest {

    @Mock
    SignerFactory signerFactory;
    @Mock
    Signer signer;
    @Mock
    InternalTimestampSource timestampSource;

    /** The algorithm is asked before there is anything to sign, so answering it must sign nothing. */
    @Test
    void answersTheAlgorithmItWouldSignWithWithoutSigning() throws Exception {
        // given
        ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile().build();
        when(signerFactory.signatureAlgorithm(profile.resolvedScheme()))
                .thenReturn(SignatureAlgorithm.SHA256_WITH_RSA_PSS);

        // when
        SignatureAlgorithm algorithm = new LiveContentSigningAcquisitions(signerFactory, timestampSource)
                .signatureAlgorithm(profile);

        // then
        assertThat(algorithm).isEqualTo(SignatureAlgorithm.SHA256_WITH_RSA_PSS);
        verify(signerFactory, never()).create(any());
    }

    @Test
    void signsEveryDtbsWithTheProfilesManagedKey() throws Exception {
        // given
        ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile().build();
        List<byte[]> dtbsList = List.of("dtbs-1".getBytes(), "dtbs-2".getBytes());
        when(signerFactory.create(profile.resolvedScheme())).thenReturn(signer);
        when(signer.signAll(dtbsList)).thenReturn(List.of("signature-1".getBytes(), "signature-2".getBytes()));

        // when
        List<byte[]> signatures = new LiveContentSigningAcquisitions(signerFactory, timestampSource)
                .signDtbs(profile, dtbsList);

        // then
        assertThat(signatures).containsExactly("signature-1".getBytes(), "signature-2".getBytes());
    }

    @Test
    void issuesTheSignatureTimestampFromTheReferencedProfile() throws Exception {
        // given
        ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                .withTimestampSourceProfileName("internal-tsa")
                .build();
        TimestampImprint imprint = new TimestampImprint(DigestAlgorithm.SHA_256, new byte[32]);
        IssuedTimestamp issued = new IssuedTimestamp("token".getBytes(), BigInteger.ONE, Instant.EPOCH);
        when(timestampSource.timestamp(imprint, "internal-tsa", "signatureTimestamp")).thenReturn(issued);

        // when
        IssuedTimestamp timestamp = new LiveContentSigningAcquisitions(signerFactory, timestampSource)
                .timestampSignature(profile, imprint, "signatureTimestamp");

        // then
        assertThat(timestamp).isEqualTo(issued);
    }

    @Test
    void refusesToTimestamp_whenTheProfileNamesNoSource() {
        // given: a SIGNED-only profile resolved without a timestamp source
        ResolvedManagedContentSigningProfile profile = aResolvedContentSigningProfile()
                .withTimestampSourceProfileName(null)
                .build();

        // when
        ThrowingCallable timestampSignature = () -> new LiveContentSigningAcquisitions(signerFactory, timestampSource)
                .timestampSignature(profile, new TimestampImprint(DigestAlgorithm.SHA_256, new byte[32]),
                        "signatureTimestamp");

        // then: the profile name is diagnostic detail, so it stays in the log and never reaches the wire
        assertThatThrownBy(timestampSignature).isInstanceOfSatisfying(SigningEngineException.class, thrown -> {
            assertThat(thrown.failure()).isEqualTo(SigningEngineFailure.MISCONFIGURED);
            assertThat(thrown.getMessage()).isEqualTo("Internal error while timestamping the signature");
            assertThat(thrown.operatorMessage()).contains(profile.name());
        });
    }
}
