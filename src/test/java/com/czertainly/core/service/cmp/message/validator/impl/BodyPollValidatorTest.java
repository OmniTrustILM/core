package com.czertainly.core.service.cmp.message.validator.impl;

import com.czertainly.api.interfaces.core.cmp.error.CmpProcessingException;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PollRepContent;
import org.bouncycastle.asn1.cmp.PollReqContent;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for {@link BodyPollValidator} and {@link BodyValidator}'s routing of
 * {@code TYPE_POLL_REQ}/{@code TYPE_POLL_REP} bodies.
 *
 * <p>This is the regression test for the previous behaviour where {@link BodyValidator}
 * threw "is not implemented" for both poll types — that broke every async issue/renew/rekey
 * path that needed to emit a {@code pollRep} response, and every inbound {@code pollReq}
 * a CMP client sent when retrying a previously-pending operation.</p>
 */
class BodyPollValidatorTest {

    private static final ASN1Integer CERT_REQ_ID = new ASN1Integer(BigInteger.ZERO);
    private static final ASN1Integer CHECK_AFTER = new ASN1Integer(60L);

    @Test
    void pollReqValidator_acceptsBodyWithCertReqId() throws Exception {
        PKIMessage msg = pkiMessage(new PKIBody(PKIBody.TYPE_POLL_REQ,
                new PollReqContent(CERT_REQ_ID)));

        // No exception expected.
        new BodyPollValidator().validateIn(msg, null);
    }

    @Test
    void pollRepValidator_acceptsBodyWithCertReqIdAndCheckAfter() throws Exception {
        PKIMessage msg = pkiMessage(new PKIBody(PKIBody.TYPE_POLL_REP,
                new PollRepContent(CERT_REQ_ID, CHECK_AFTER)));

        // No exception expected.
        new BodyPollValidator().validateOut(msg, null);
    }

    @Test
    void pollRepValidator_rejectsNegativeCheckAfter() {
        PKIMessage msg = pkiMessage(new PKIBody(PKIBody.TYPE_POLL_REP,
                new PollRepContent(CERT_REQ_ID, new ASN1Integer(BigInteger.ONE.negate()))));

        assertThatThrownBy(() -> new BodyPollValidator().validateOut(msg, null))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("checkAfter must be a non-negative integer");
    }

    @Test
    void bodyValidator_routesPollReq_toValidatorInsteadOfNotImplementedError() throws Exception {
        // Regression: previously TYPE_POLL_REQ fell into the "not implemented" branch,
        // which caused every inbound pollReq to be rejected before the message handler
        // ever saw it.
        PKIMessage msg = pkiMessage(new PKIBody(PKIBody.TYPE_POLL_REQ,
                new PollReqContent(CERT_REQ_ID)));

        new BodyValidator().validate(msg, null);
    }

    @Test
    void bodyValidator_routesPollRep_toValidatorInsteadOfNotImplementedError() throws Exception {
        // Regression: previously TYPE_POLL_REP fell into the "not implemented" branch,
        // which caused every async-acceptance pollRep response to be converted into an
        // error during outbound validation in CmpServiceImpl.handlePost.
        PKIMessage msg = pkiMessage(new PKIBody(PKIBody.TYPE_POLL_REP,
                new PollRepContent(CERT_REQ_ID, CHECK_AFTER)));

        new BodyValidator().validate(msg, null);
    }

    @Test
    void bodyValidator_pollReqWithoutCertReqId_rejected() {
        PKIMessage msg = pkiMessage(new PKIBody(PKIBody.TYPE_POLL_REQ, new PollReqContent(new ASN1Integer[0])));

        assertThatThrownBy(() -> new BodyValidator().validate(msg, null))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("at least one certReqId is required");
    }

    @Test
    void validateDispatcher_routesPollReq_toValidateIn() throws Exception {
        // The convenience dispatcher (kept for completeness — BodyValidator goes via type)
        // must route TYPE_POLL_REQ messages to validateIn so direct callers can use the
        // same validator without knowing the direction up front.
        PKIMessage msg = pkiMessage(new PKIBody(PKIBody.TYPE_POLL_REQ,
                new PollReqContent(CERT_REQ_ID)));

        new BodyPollValidator().validate(msg, null);
    }

    @Test
    void validateDispatcher_routesPollRep_toValidateOut() throws Exception {
        PKIMessage msg = pkiMessage(new PKIBody(PKIBody.TYPE_POLL_REP,
                new PollRepContent(CERT_REQ_ID, CHECK_AFTER)));

        new BodyPollValidator().validate(msg, null);
    }

    @Test
    void validateDispatcher_rejectsMalformedPollReq() {
        PKIMessage msg = pkiMessage(new PKIBody(PKIBody.TYPE_POLL_REQ, new PollReqContent(new ASN1Integer[0])));

        assertThatThrownBy(() -> new BodyPollValidator().validate(msg, null))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("at least one certReqId is required");
    }

    @Test
    void validateDispatcher_rejectsMalformedPollRep_negativeCheckAfter() {
        PKIMessage msg = pkiMessage(new PKIBody(PKIBody.TYPE_POLL_REP,
                new PollRepContent(CERT_REQ_ID, new ASN1Integer(BigInteger.ONE.negate()))));

        assertThatThrownBy(() -> new BodyPollValidator().validate(msg, null))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining("checkAfter must be a non-negative integer");
    }

    private static PKIMessage pkiMessage(PKIBody body) {
        PKIHeader header = new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                new GeneralName(new X500Name("CN=test-sender")),
                new GeneralName(new X500Name("CN=test-recipient")))
                .setTransactionID(new DEROctetString(new byte[]{1, 2, 3, 4}))
                .build();
        return new PKIMessage(header, body);
    }
}
