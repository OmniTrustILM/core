package com.otilm.core.service.scep;

import com.otilm.api.exception.ScepException;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.api.model.core.scep.MessageType;
import com.otilm.core.service.scep.message.ScepRequest;
import org.bouncycastle.cms.CMSException;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class EcdsaCmsMessageTest {

    @Test
    public void testGenerateEcdsaSignedMessage() throws Exception {
        ScepRequest scepRequest = new ScepRequest(ScepMessageTestData.passwordEnvelopedPkcsReq());
        scepRequest.decryptData(null, null, KeyAlgorithm.ECDSA, ScepMessageTestData.CHALLENGE_PASSWORD);
        Assertions.assertEquals(scepRequest.getMessageType(), MessageType.PKCS_REQ);
        Assertions.assertEquals(ScepMessageTestData.SUBJECT_DN, scepRequest.getPkcs10Request().getSubject().toString());
    }

    @Test
    public void testGenerateEcdsaSignedMessage_wrongChallenge() throws Exception {
        ScepRequest scepRequest = new ScepRequest(ScepMessageTestData.passwordEnvelopedPkcsReq());

        Assertions
                .assertThrows(CMSException.class,
                        () -> scepRequest.decryptData(null, null, KeyAlgorithm.ECDSA, "wrongpassword"));
    }

    /**
     * A password-enveloped request cannot be decrypted at all when the profile has no challenge password configured:
     * that must surface as a SCEP rejection rather than a {@code NullPointerException}.
     */
    @Test
    public void testGenerateEcdsaSignedMessage_noChallengePasswordConfigured() throws Exception {
        ScepRequest scepRequest = new ScepRequest(ScepMessageTestData.passwordEnvelopedPkcsReq());

        ScepException thrown = Assertions
                .assertThrows(ScepException.class, () -> scepRequest.decryptData(null, null, KeyAlgorithm.ECDSA, null));
        Assertions.assertEquals(FailInfo.BAD_ALG, thrown.getFailInfo());
    }

    /**
     * An EnvelopedData with no recipientInfo leaves nothing to decrypt. That must be rejected explicitly rather than
     * reaching the PKCS#10 parse with no content — the bare {@code assert} that used to guard this is disabled in
     * production.
     */
    @Test
    public void testGenerateEcdsaSignedMessage_noRecipientInformation() throws Exception {
        ScepRequest scepRequest = new ScepRequest(ScepMessageTestData.recipientlessPkcsReq());

        ScepException thrown = Assertions
                .assertThrows(ScepException.class, () -> scepRequest
                        .decryptData(null, null, KeyAlgorithm.ECDSA, ScepMessageTestData.CHALLENGE_PASSWORD));
        Assertions.assertEquals(FailInfo.BAD_REQUEST, thrown.getFailInfo());
    }
}
