package com.otilm.core.service.scep;

import com.otilm.api.exception.ScepException;
import com.otilm.api.model.core.scep.FailInfo;
import com.otilm.core.certificate.request.RequestAttributePolicyViolationException;
import com.otilm.core.dao.entity.AuthorityInstanceReference;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.service.scep.impl.ScepServiceImpl;
import com.otilm.core.service.scep.message.ScepRequest;
import com.otilm.core.service.v2.ClientOperationInternalService;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;
import org.springframework.test.util.ReflectionTestUtils;

import java.lang.reflect.UndeclaredThrowableException;
import java.util.Base64;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;

/**
 * Verifies that the SCEP {@code PKCSReq} issue seam in {@link ScepServiceImpl} shapes a {@link RequestAttributePolicyViolationException} raised by
 * into a {@link ScepException} carrying {@link FailInfo#BAD_REQUEST} and the platform-authored (safe) message, rather than the generic
 * {@code CertificateOperationException} mapping.
 */
class ScepPkcsReqRequestAttributeValidationTest {

    private static final String PKCS10_BASE64 = "MIICUzCCATsCAQAwDjEMMAoGA1UEAwwDeDExMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAx3yEn1ivUp4etk3kdNrRXNP5PeIpTYobGj4lQrW57rsj9hhOhY/SwaeCu6sYPVvYIXPWnlc4tTafjcen/8Ikc7pY2NuzD0HaIAOujblcMKT2KAKA/OU+RrI2o/swU9UmEQ2wYveNYCGobimt/foURrB9opeDCx3pFXkddYsXAziaWu3AQIF5gIf/b+r7hYRIXh8V/u01t6FCnpBWCtdmYVrJ5e8KZw0yqptNpgDK1plu+8AR5tviP/vgrpBquwzNsVREsnRZJxOM6rXq9rG5scoqO+gxdsm6+EqfRiGiBvcaIr+Zpv81ryfiABLdixvyhoZ//3o8rAU0O7Pjm7HTxwIDAQABoAAwDQYJKoZIhvcNAQELBQADggEBAKM6lsrzME64G90fm98Zdgxe6IMBmIWTzA03V0OWGTYjYjYZbfsddAQAO1h3EMKjPl5nFaXkTVGoq8G4ZHvdu2fX72dyNJaGG+mG89uoW9iFd2US+nU5aN8xSpPx1k89DhPat/q5kdOwIIGAXvIbLWSXGx9A25DxdqvouuhDT7NJZqGTsPivHuFXgP3Mb1HTr/qnshx+shTnJ+FnYncARl3KmflCyCPC4NBKcorWl8kVFRDw2Y7aeg3a1hV3EJJfElFSwlmmT2Y/VDuZcMalFnnAKq2NqXByBlK9s7s67sMKzsqaAGwlg3TT37v6QN6L2q0zUU6egAuA4Av2LR6nJkw=";

    @Test
    void shapesBadRequest_whenPkcsReqViolatesRequestAttributePolicy() throws Exception {
        // given — a SCEP service whose downstream issuance is rejected by the request-attribute policy
        // (RA profile requires CN, the CSR's subject omits it)
        var policyMessage = "Certificate request does not satisfy the request-attribute policy "
                + "of RA profile 'X': missing required RDN: CN";
        ClientOperationInternalService clientOperationService = Mockito.mock(ClientOperationInternalService.class);
        given(clientOperationService.issueCertificate(any(), any(), any(), any()))
                .willThrow(new RequestAttributePolicyViolationException(policyMessage, List.of("missing required RDN: CN")));
        ScepServiceImpl service = seededScepService(clientOperationService);
        ScepRequest scepRequest = Mockito.mock(ScepRequest.class);
        given(scepRequest.getPkcs10Request()).willReturn(new JcaPKCS10CertificationRequest(Base64.getDecoder().decode(PKCS10_BASE64)));

        // when / then — the seam shapes the policy violation into a ScepException carrying the safe,
        // platform-authored message and FailInfo.BAD_REQUEST.
        // ReflectionTestUtils wraps the target's declared checked ScepException in an UndeclaredThrowableException.
        assertThatThrownBy(() -> ReflectionTestUtils.invokeMethod(service, "issueCertificate", scepRequest, null))
                .isInstanceOf(UndeclaredThrowableException.class)
                .cause()
                .isInstanceOf(ScepException.class)
                .hasMessage(policyMessage)
                .satisfies(ex -> {
                    ScepException scepException = (ScepException) ex;
                    assertThat(scepException.getFailInfo()).isEqualTo(FailInfo.BAD_REQUEST);
                    assertThat(scepException.getMessage())
                            .doesNotContainIgnoringCase("sql")
                            .doesNotContainIgnoringCase("exception")
                            .doesNotContain("com.otilm");
                });
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /**
     * Builds a {@link ScepServiceImpl} with the mock issuer wired and the fields normally populated by
     * {@code init(...)} seeded via reflection, so the private {@code issueCertificate} kernel can be driven
     * directly (matching {@code ScepServiceImplPollUnitTest}'s precedent — see class Javadoc for why).
     */
    private static ScepServiceImpl seededScepService(ClientOperationInternalService clientOperationService) {
        ScepServiceImpl service = new ScepServiceImpl();
        service.setClientOperationService(clientOperationService);

        AuthorityInstanceReference authorityInstanceReference = new AuthorityInstanceReference();
        authorityInstanceReference.setUuid(UUID.randomUUID());
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setAuthorityInstanceReference(authorityInstanceReference);
        ScepProfile scepProfile = new ScepProfile();
        scepProfile.setUuid(UUID.randomUUID());
        scepProfile.setIntuneEnabled(false);

        ReflectionTestUtils.setField(service, "raProfile", raProfile);
        ReflectionTestUtils.setField(service, "scepProfile", scepProfile);
        ReflectionTestUtils.setField(service, "issueAttributes", List.of());
        return service;
    }
}
