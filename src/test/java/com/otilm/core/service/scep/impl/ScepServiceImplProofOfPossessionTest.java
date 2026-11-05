package com.otilm.core.service.scep.impl;

import com.otilm.api.exception.ScepException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.api.model.core.scep.MessageType;
import com.otilm.core.service.scep.ScepMessageTestData;
import com.otilm.core.service.scep.message.ScepRequest;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.Security;
import java.util.stream.Stream;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;

import static com.otilm.core.service.scep.ScepMessageTestData.passwordEnvelopedMessageWithCsrSignedBy;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.assertj.core.api.Assertions.catchThrowable;
import static org.junit.jupiter.api.Named.named;
import static org.junit.jupiter.params.provider.Arguments.arguments;

/** Covers {@link ScepServiceImpl#verifyProofOfPossession} for both message types that carry a PKCS#10 request. */
class ScepServiceImplProofOfPossessionTest {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private final ScepServiceImpl service = new ScepServiceImpl();

    @ParameterizedTest
    @EnumSource(value = MessageType.class, names = {"PKCS_REQ", "RENEWAL_REQ"})
    void acceptsRequest_whenCsrIsSignedWithTheKeyItNames(MessageType messageType) throws Exception {
        // given
        ScepRequest request = decryptRequest(ScepMessageTestData.passwordEnvelopedMessage(messageType, null));

        // when
        ThrowingCallable verify = () -> service.verifyProofOfPossession(request);

        // then
        assertThat(catchThrowable(verify)).isNull();
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("requestsWithCsrSignedByAnotherKey")
    void rejectsWithBadRequest_whenCsrIsSignedWithAnotherKey(byte[] message) throws Exception {
        // given
        ScepRequest request = decryptRequest(message);

        // when
        ThrowingCallable verify = () -> service.verifyProofOfPossession(request);

        // then
        assertThatThrownBy(verify)
                .isInstanceOfSatisfying(ScepException.class,
                        refusal -> assertThat(refusal.getFailInfo()).isEqualTo(FailInfo.BAD_REQUEST));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static Stream<Arguments> requestsWithCsrSignedByAnotherKey() throws Exception {
        PrivateKey anotherRsaKey = KeyPairGenerator.getInstance("RSA").generateKeyPair().getPrivate();
        PrivateKey ecKey = KeyPairGenerator.getInstance("EC").generateKeyPair().getPrivate();
        return Stream
                .of(arguments(named("RenewalReq whose CSR is signed with another RSA key",
                        passwordEnvelopedMessageWithCsrSignedBy(MessageType.RENEWAL_REQ, anotherRsaKey,
                                "SHA256withRSA"))),
                        arguments(named("RenewalReq whose CSR is signed with an EC key",
                                passwordEnvelopedMessageWithCsrSignedBy(MessageType.RENEWAL_REQ, ecKey,
                                        "SHA256withECDSA"))),
                        arguments(named("PKCSReq whose CSR is signed with another RSA key",
                                passwordEnvelopedMessageWithCsrSignedBy(MessageType.PKCS_REQ, anotherRsaKey,
                                        "SHA256withRSA"))),
                        arguments(named("PKCSReq whose CSR is signed with an EC key",
                                passwordEnvelopedMessageWithCsrSignedBy(MessageType.PKCS_REQ, ecKey,
                                        "SHA256withECDSA"))));
    }

    private static ScepRequest decryptRequest(byte[] message) throws Exception {
        ScepRequest request = new ScepRequest(message);
        request.decryptData(null, null, KeyAlgorithm.ECDSA, ScepMessageTestData.CHALLENGE_PASSWORD);
        return request;
    }
}
