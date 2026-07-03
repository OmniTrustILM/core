package com.otilm.core.service.cmp.impl;

import com.otilm.api.model.core.cmp.CmpProfileVariant;
import com.otilm.api.model.core.cmp.ProtectionMethod;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.cmp.CmpProfile;
import com.otilm.core.dao.entity.cmp.CmpTransaction;
import com.otilm.core.dao.repository.RaProfileRepository;
import com.otilm.core.dao.repository.cmp.CmpProfileRepository;
import com.otilm.core.service.cmp.CmpTestUtil;
import com.otilm.core.service.cmp.message.CmpTransactionService;
import com.otilm.core.service.cmp.message.validator.impl.HeaderValidator;
import org.bouncycastle.asn1.cmp.CertRepMessage;
import org.bouncycastle.asn1.cmp.ErrorMsgContent;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.cmp.PKIHeader;
import org.bouncycastle.asn1.cmp.PKIHeaderBuilder;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.bouncycastle.asn1.cmp.PKIStatusInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Drives {@link CmpServiceImpl#handlePost(String, byte[])} through its error paths to verify that the
 * wire-visible {@code PKIFreeText} carries a shaped message and never leaks a raw runtime exception.
 */
class CmpServiceImplHandlePostTest {

    private static final String PROFILE_NAME = "missing-profile";
    private static final String LEAKY_MESSAGE =
            "ERROR: duplicate key value violates unique constraint \"ra_profile_pkey\"";

    @AfterEach
    void clearRequestContext() {
        RequestContextHolder.resetRequestAttributes();
    }

    @Test
    void handlePost_returnsShapedProfileError_whenProfileNotResolved() throws Exception {
        // given: a raProfile-scoped request whose RA profile cannot be resolved, so profile validation fails
        RaProfileRepository raProfileRepository = mock(RaProfileRepository.class);
        when(raProfileRepository.findByName(anyString())).thenReturn(Optional.empty());
        CmpServiceImpl service = newService(raProfileRepository, mock(CmpProfileRepository.class), null, false);

        // when
        ResponseEntity<byte[]> response = service.handlePost(PROFILE_NAME, revocationRequest());

        // then: the shaped domain message reaches the wire; the response is a well-formed CMP error
        assertThat(response.getBody()).isNotNull();
        assertThat(wireStatusText(response.getBody())).contains("Requested CMP Profile not found");
    }

    @Test
    void handlePost_replacesRawMessageWithGenericDetail_whenProcessingThrowsNonDomainException() throws Exception {
        // given: a fully resolved profile so processing proceeds past validation
        CmpProfile cmpProfile = resolvedCmpProfile();
        RaProfile raProfile = resolvedRaProfile(cmpProfile);
        RaProfileRepository raProfileRepository = mock(RaProfileRepository.class);
        when(raProfileRepository.findByName(anyString())).thenReturn(Optional.of(raProfile));

        // and: the header validator throws a non-domain exception carrying a sensitive message
        HeaderValidator headerValidator = mock(HeaderValidator.class);
        when(headerValidator.validate(any(), any())).thenThrow(new RuntimeException(LEAKY_MESSAGE));

        CmpServiceImpl service = newService(raProfileRepository, mock(CmpProfileRepository.class), headerValidator, true);

        // when
        ResponseEntity<byte[]> response = service.handlePost(PROFILE_NAME, revocationRequest());

        // then: the sensitive message never reaches the wire-visible PKIFreeText
        assertThat(response.getBody()).isNotNull();
        assertThat(wireStatusText(response.getBody()))
                .isEqualTo("CMP request handling failed")
                .doesNotContain("ra_profile_pkey");
    }

    private CmpServiceImpl newService(RaProfileRepository raProfileRepository,
                                      CmpProfileRepository cmpProfileRepository,
                                      HeaderValidator headerValidator,
                                      boolean verbose) {
        CmpServiceImpl service = new CmpServiceImpl();
        service.setRaProfileRepository(raProfileRepository);
        service.setCmpProfileRepository(cmpProfileRepository);

        CmpTransactionService cmpTransactionService = mock(CmpTransactionService.class);
        when(cmpTransactionService.findByTransactionId(anyString())).thenReturn(Collections.<CmpTransaction>emptyList());

        ReflectionTestUtils.setField(service, "cmpTransactionService", cmpTransactionService);
        ReflectionTestUtils.setField(service, "headerValidator", headerValidator);
        ReflectionTestUtils.setField(service, "verbose", verbose);

        MockHttpServletRequest request =
                new MockHttpServletRequest("POST", "/v1/protocols/cmp/raProfile/" + PROFILE_NAME);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
        return service;
    }

    private static CmpProfile resolvedCmpProfile() {
        CmpProfile cmpProfile = mock(CmpProfile.class);
        when(cmpProfile.getEnabled()).thenReturn(true);
        when(cmpProfile.getResponseProtectionMethod()).thenReturn(ProtectionMethod.SHARED_SECRET);
        when(cmpProfile.getVariant()).thenReturn(CmpProfileVariant.V2);
        when(cmpProfile.getUuid()).thenReturn(UUID.randomUUID());
        when(cmpProfile.getName()).thenReturn("testCmpProfile");
        return cmpProfile;
    }

    private static RaProfile resolvedRaProfile(CmpProfile cmpProfile) {
        RaProfile raProfile = mock(RaProfile.class);
        when(raProfile.getCmpProfile()).thenReturn(cmpProfile);
        when(raProfile.getEnabled()).thenReturn(true);
        return raProfile;
    }

    private static byte[] revocationRequest() throws Exception {
        PKIHeaderBuilder headerBuilder = new PKIHeaderBuilder(
                PKIHeader.CMP_2000,
                new GeneralName(new X500Name("CN=user")),
                new GeneralName(new X500Name("CN=ManagementCA")));
        headerBuilder.setTransactionID(new byte[]{1, 2, 3, 4});
        headerBuilder.setSenderNonce("12345".getBytes(StandardCharsets.UTF_8));
        PKIBody body = CmpTestUtil.createRevocationBody(BigInteger.ONE);
        return new PKIMessage(headerBuilder.build(), body).getEncoded();
    }

    private static String wireStatusText(byte[] response) {
        PKIBody body = PKIMessage.getInstance(response).getBody();
        PKIStatusInfo statusInfo = body.getContent() instanceof ErrorMsgContent errorMsgContent
                ? errorMsgContent.getPKIStatusInfo()
                : ((CertRepMessage) body.getContent()).getResponse()[0].getStatus();
        return statusInfo.getStatusString().getStringAtUTF8(0).getString();
    }
}
