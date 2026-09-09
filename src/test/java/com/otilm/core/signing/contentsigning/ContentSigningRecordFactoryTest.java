package com.otilm.core.signing.contentsigning;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.otilm.api.model.common.signature.SignatureLevel;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.api.model.core.signing.SigningProtocol;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.serialization.ObjectMapperFactory;
import com.otilm.core.signing.record.SigningRecordInput;
import com.otilm.core.signing.record.SigningRecordInputSource;
import java.math.BigInteger;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.context.SecurityContextHolder;

import static com.otilm.core.util.builders.ResolvedManagedContentSigningProfileBuilder.aResolvedContentSigningProfile;
import static com.otilm.core.util.builders.SigningProfileModelBuilder.aSigningProfile;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ContentSigningRecordFactoryTest {

    private final ContentSigningRecordFactory factory = new ContentSigningRecordFactory(ObjectMapperFactory.storage());

    @AfterEach
    void clearRequester() {
        SecurityContextHolder.clearContext();
    }

    @Nested
    class Requester {

        @Test
        void recordNamesTheUserWhoRequestedTheSignature() {
            // given
            UUID requesterUuid = UUID.randomUUID();
            SecurityContextHolder
                    .getContext()
                    .setAuthentication(new PlatformAuthenticationToken(new PlatformUserDetails(new AuthenticationInfo(
                            AuthMethod.USER_PROXY, requesterUuid.toString(), "operator", List.of()))));

            // when
            SigningRecordInput input = source(SignatureLevel.SIGNED, List.of()).build();

            // then
            assertThat(input.getRequestedBy()).isNotNull();
            assertThat(input.getRequestedBy().getUuid()).isEqualTo(requesterUuid.toString());
            assertThat(input.getRequestedBy().getName()).isEqualTo("operator");
        }

        @Test
        void recordNamesNobodyWhenTheSigningThreadCarriesNoIdentity() {
            // given
            SecurityContextHolder.clearContext();

            // when
            SigningRecordInput input = source(SignatureLevel.SIGNED, List.of()).build();

            // then
            assertThat(input.getRequestedBy()).isNull();
        }
    }

    @Nested
    class RecordedArtifacts {

        @Test
        void recordCarriesTheDocumentTheSignatureAndTheDtbs() {
            // given / when
            SigningRecordInput input = source(SignatureLevel.SIGNED, List.of()).build();

            // then
            assertThat(input.getSignedDocument()).isEqualTo("signed".getBytes());
            assertThat(input.getSignature()).isEqualTo("signature".getBytes());
            assertThat(input.getDtbs()).isEqualTo("dtbs".getBytes());
            assertThat(input.getProtocol()).isEqualTo(SigningProtocol.CSC_API);
            assertThat(input.getSigningTime()).isEqualTo(Instant.EPOCH);
        }

        @Test
        void recordsAnAugmentedDocumentWithNoDtbsOrSignatureOfItsOwn() {
            // given: the augmentation entry acquires a timestamp only

            // when
            SigningRecordInput input = factory
                    .source(aSigningProfile().build(), aResolvedContentSigningProfile().build(),
                            new SignedContent("timestamped".getBytes(), SignatureLevel.TIMESTAMPED,
                                    List.of(BigInteger.ONE)),
                            null, null, Instant.EPOCH, SigningProtocol.CSC_API)
                    .build();

            // then
            assertThat(input.getSignedDocument()).isEqualTo("timestamped".getBytes());
            assertThat(input.getSignature()).isNull();
            assertThat(input.getDtbs()).isNull();
        }

        /** The serials sit in a column of their own, because request metadata is behind an operator toggle. */
        @Test
        void theSerialsLandInTheRecordColumnRatherThanOnlyInTheMetadata() {
            // given / when
            SigningRecordInput input = source(SignatureLevel.TIMESTAMPED, List.of(BigInteger.valueOf(0x2a))).build();

            // then
            assertThat(input.getTimestampTokenSerialNumbers()).containsExactly("2a");
        }

        @Test
        void aSignedOnlyRunCarriesNoSerialsBecauseItEmbeddedNoTimestamp() {
            // given / when
            SigningRecordInput input = source(SignatureLevel.SIGNED, List.of()).build();

            // then
            assertThat(input.getTimestampTokenSerialNumbers()).isEmpty();
        }

        @Test
        void displayNameNamesTheProfileAndTheBaselineTheSignatureReached() {
            // given / when
            SigningRecordInput input = source(SignatureLevel.TIMESTAMPED, List.of()).build();

            // then
            assertThat(input.getDisplayName()).isEqualTo("test-profile PAdES-B-T");
        }
    }

    @Nested
    class RequestMetadata {

        @Test
        void metadataNamesTheLevelTheFamilyAndTheTimestampSerials() {
            // given / when
            SigningRecordInput input = source(SignatureLevel.TIMESTAMPED, List.of(BigInteger.valueOf(0x2a))).build();

            // then
            assertThat(input.getRequestMetadataJson())
                    .contains("\"signatureLevel\":\"TIMESTAMPED\"")
                    .contains("\"family\":\"PADES\"")
                    .contains("\"timestampTokenSerialNumbers\":[\"2a\"]");
        }

        @Test
        void metadataNamesTheProfileAndItsVersion() {
            // given / when
            SigningRecordInput input = source(SignatureLevel.SIGNED, List.of()).build();

            // then
            assertThat(input.getRequestMetadataJson())
                    .contains("\"signingProfileName\":\"test-profile\"")
                    .contains("\"signingProfileVersion\":1")
                    .contains("\"timestampTokenSerialNumbers\":[]");
        }

        @Test
        void aMetadataSerializationFailureIsAnInternalDefectRatherThanASilentlyEmptyRecord() throws Exception {
            // given
            ObjectMapper failingMapper = mock(ObjectMapper.class);
            when(failingMapper.writeValueAsString(any())).thenThrow(mock(JsonProcessingException.class));
            SigningRecordInputSource deferred = new ContentSigningRecordFactory(failingMapper)
                    .source(aSigningProfile().build(), aResolvedContentSigningProfile().build(),
                            new SignedContent("signed".getBytes(), SignatureLevel.SIGNED, List.of()), null, null,
                            Instant.EPOCH, SigningProtocol.CSC_API);

            // when / then
            assertThatThrownBy(deferred::build).isInstanceOf(IllegalStateException.class);
        }
    }

    @Nested
    class Deferral {

        @Test
        void exposesTheProfileBeforeAssemblingTheInput() {
            // given: the recording gate reads the profile without paying for metadata serialization
            SigningRecordInputSource deferred = source(SignatureLevel.SIGNED, List.of());

            // when / then
            assertThat(deferred.signingProfile()).isNotNull();
        }
    }

    private SigningRecordInputSource source(SignatureLevel level, List<BigInteger> serials) {
        return factory
                .source(aSigningProfile().build(), aResolvedContentSigningProfile().build(),
                        new SignedContent("signed".getBytes(), level, serials), "dtbs".getBytes(),
                        "signature".getBytes(), Instant.EPOCH, SigningProtocol.CSC_API);
    }
}
