package com.otilm.core.service.scep.impl;

import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.dao.entity.scep.ScepProfile;
import com.otilm.core.service.scep.ScepMessageTestData;
import java.util.UUID;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.util.ReflectionTestUtils;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Covers the PKIOperation failure guard: an unexpected runtime failure must not escape as an {@code application/json}
 * error body, since a SCEP client cannot parse one.
 *
 * <p>
 * The profile here has no CA certificate, so processing fails immediately <em>and</em> the SCEP failure response cannot
 * be signed — the CA key is reached through the token connector. That is the degraded corner of the contract: a bare
 * status, never a JSON body, and nothing propagating out of the method.
 * </p>
 */
class ScepServiceImplPkiOperationFailureTest {

    private ScepServiceImpl service;

    @BeforeEach
    void setUp() {
        service = new ScepServiceImpl();

        ScepProfile profile = mock(ScepProfile.class);
        when(profile.getName()).thenReturn("scep-profile");
        RaProfile raProfile = new RaProfile();
        raProfile.setUuid(UUID.randomUUID());
        raProfile.setName("ra-profile");

        ReflectionTestUtils.setField(service, "scepProfile", profile);
        ReflectionTestUtils.setField(service, "raProfile", raProfile);
    }

    @Test
    void unexpectedFailure_answersWithABareStatusAndNeverAJsonBody() throws Exception {
        byte[] body = ScepMessageTestData.passwordEnvelopedPkcsReq();

        ResponseEntity<Object> response = invokePkiOperation(body);

        assertEquals(HttpStatus.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertNull(response.getBody(), "the response must carry no error body a SCEP client cannot parse");
    }

    @SuppressWarnings("unchecked")
    private ResponseEntity<Object> invokePkiOperation(byte[] body) {
        return (ResponseEntity<Object>) ReflectionTestUtils.invokeMethod(service, "pkiOperation", body);
    }
}
