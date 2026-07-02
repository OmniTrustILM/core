package com.otilm.core.service.cmp.impl;

import com.otilm.api.interfaces.core.cmp.PkiMessageError;
import com.otilm.api.interfaces.core.cmp.error.CmpBaseException;
import com.otilm.api.interfaces.core.cmp.error.CmpConfigurationException;
import com.otilm.api.interfaces.core.cmp.error.CmpCrmfValidationException;
import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIFailureInfo;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;

import static org.assertj.core.api.Assertions.assertThat;

class CmpServiceImplValidateProfileTest {

    private static final String LEAKY_MESSAGE =
            "ERROR: duplicate key value violates unique constraint \"ra_profile_pkey\"";

    @Test
    void validateProfile_forwardsShapedConfigurationMessage_forEnrollmentRequest() throws Exception {
        // given: a service with no CMP profile resolved, so profile validation fails
        // with a Core-authored CmpConfigurationException
        CmpServiceImpl service = new CmpServiceImpl();

        // when: an enrollment request (cr) fails profile validation
        CmpBaseException thrown = invokeValidateProfile(service, PKIBody.TYPE_CERT_REQ);

        // then: the shaped message reaches the CRMF error body's PKIFreeText unchanged
        assertThat(thrown).isInstanceOf(CmpCrmfValidationException.class);
        assertThat(wireStatusText(thrown)).contains("Requested CMP Profile not found");
    }

    @Test
    void validateProfile_forwardsShapedConfigurationMessage_forNonEnrollmentRequest() throws Exception {
        // given
        CmpServiceImpl service = new CmpServiceImpl();

        // when: a non-enrollment request (rr) fails profile validation
        CmpBaseException thrown = invokeValidateProfile(service, PKIBody.TYPE_REVOCATION_REQ);

        // then: the shaped message reaches the error body's PKIFreeText unchanged
        assertThat(thrown)
                .isInstanceOf(CmpProcessingException.class)
                .isNotInstanceOf(CmpCrmfValidationException.class);
        assertThat(wireStatusText(thrown)).contains("Requested CMP Profile not found");
    }

    @Test
    void safeCmpDetail_returnsFallback_forNonDomainException() {
        // given: a non-domain exception carrying a sensitive, SQL-shaped message
        RuntimeException leaky = new RuntimeException(LEAKY_MESSAGE);

        // when
        String detail = CmpServiceImpl.safeCmpDetail(leaky, "CMP profile validation failed");

        // then: the sensitive message is not forwarded
        assertThat(detail)
                .isEqualTo("CMP profile validation failed")
                .doesNotContain("ra_profile_pkey");
    }

    @Test
    void safeCmpDetail_forwardsMessageUnchanged_forDomainException() {
        // given: a Core-shaped domain exception
        CmpConfigurationException domain =
                new CmpConfigurationException(PKIFailureInfo.systemFailure, "RA Profile is not enabled");

        // when
        String detail = CmpServiceImpl.safeCmpDetail(domain, "fallback");

        // then: the Core-authored message is forwarded unchanged
        assertThat(detail).isEqualTo(domain.getMessage()).contains("RA Profile is not enabled");
    }

    @Test
    void safeCmpDetail_returnsFallback_forDomainExceptionWithoutMessage() {
        // given: a domain-typed exception whose message is null
        CmpProcessingException withoutMessage = Mockito.mock(CmpProcessingException.class);

        // when
        String detail = CmpServiceImpl.safeCmpDetail(withoutMessage, "fallback");

        // then
        assertThat(detail).isEqualTo("fallback");
    }

    @Test
    void safeUnprotectedError_replacesRawMessageWithGenericDetail_forNonDomainException() {
        // given: a non-domain exception carrying a sensitive, SQL-shaped message, as would
        // reach the top-level catch-all in the request-handling flow
        RuntimeException leaky = new RuntimeException(LEAKY_MESSAGE);

        // when: the unprotected CMP error response is built for it
        PKIMessage response = CmpServiceImpl.safeUnprotectedError(PkiMessageError.generateHeader(), leaky);

        // then: the sensitive message never reaches the wire-visible PKIFreeText
        assertThat(wireStatusText(response))
                .isEqualTo("CMP request handling failed")
                .doesNotContain("ra_profile_pkey");
    }

    private static CmpBaseException invokeValidateProfile(CmpServiceImpl service, int bodyType) throws Exception {
        Method method = CmpServiceImpl.class.getDeclaredMethod(
                "validateProfile", ASN1OctetString.class, int.class, String.class);
        method.setAccessible(true);
        try {
            method.invoke(service, new DEROctetString("tid".getBytes(StandardCharsets.UTF_8)), bodyType, "missing-profile");
            throw new AssertionError("validateProfile was expected to throw");
        } catch (InvocationTargetException e) {
            return (CmpBaseException) e.getCause();
        }
    }

    /** Extracts the wire-visible {@code PKIFreeText} status string from the exception's response body. */
    private static String wireStatusText(CmpBaseException e) {
        return wireStatusText(e.toPKIBody());
    }

    /** Extracts the wire-visible {@code PKIFreeText} status string from a response message. */
    private static String wireStatusText(PKIMessage message) {
        return wireStatusText(message.getBody());
    }

    private static String wireStatusText(PKIBody body) {
        PKIStatusInfo statusInfo = body.getContent() instanceof ErrorMsgContent errorMsgContent
                ? errorMsgContent.getPKIStatusInfo()
                : ((CertRepMessage) body.getContent()).getResponse()[0].getStatus();
        return statusInfo.getStatusString().getStringAtUTF8(0).getString();
    }
}
