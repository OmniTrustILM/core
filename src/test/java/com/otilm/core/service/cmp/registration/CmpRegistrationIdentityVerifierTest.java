package com.otilm.core.service.cmp.registration;

import com.otilm.api.interfaces.core.cmp.error.CmpProcessingException;
import com.otilm.api.model.core.certificate.CertificateEvent;
import com.otilm.api.model.core.certificate.CertificateEventStatus;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.dao.entity.Certificate;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import com.otilm.core.service.CertificateEventHistoryInternalService;
import com.otilm.core.service.cmp.CmpTestUtil;
import com.otilm.core.util.CertificateUtil;
import java.security.KeyPair;
import java.security.Security;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.PKIBody;
import org.bouncycastle.asn1.crmf.CertReqMessages;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Unit tests for {@link CmpRegistrationIdentityVerifier} — the shared subject-and-SAN identity check the ir/cr and kur
 * registration paths both apply to a CRMF before completing or rekeying.
 */
class CmpRegistrationIdentityVerifierTest {

    private static final ASN1OctetString TID = new DEROctetString(new byte[]{1, 2, 3, 4});
    private static final String SUBJECT_DN = "CN=device-1";
    private static final UUID MATCHED_UUID = UUID.randomUUID();

    private CertificateEventHistoryInternalService eventHistoryService;
    private CmpRegistrationIdentityVerifier verifier;

    private static Map<String, OidRecord> savedRdnCache;

    @BeforeAll
    static void setUpClass() {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        // PlatformX500NameStyle (used by RegistrationIdentityMatcher) reads the RDN OID registry at class
        // init, which is empty outside a Spring context; seed the codes these subjects use.
        Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
        savedRdnCache = existing == null ? null : new HashMap<>(existing);
        OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
        OidHandler
                .cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                        OidRecord.builder().displayName("Common Name").code("CN").build());
    }

    @AfterAll
    static void restoreRdnCache() {
        OidHandler
                .cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                        savedRdnCache != null ? savedRdnCache : new HashMap<>());
    }

    @BeforeEach
    void setUp() {
        eventHistoryService = mock(CertificateEventHistoryInternalService.class);
        verifier = new CmpRegistrationIdentityVerifier();
        verifier.setCertificateEventHistoryService(eventHistoryService);
    }

    private static CertReqMessages crmf(String subjectDn, List<String> dnsSans) throws Exception {
        KeyPair keyPair = CmpTestUtil.generateKeyPairEC();
        PKIBody body = CmpTestUtil
                .createRegistrationCrmfBody(keyPair, 0L, PKIBody.TYPE_INIT_REQ, subjectDn, dnsSans, null);
        return (CertReqMessages) body.getContent();
    }

    private static Certificate matched(String subjectDn, List<String> dnsSans) {
        Certificate certificate = new Certificate();
        certificate.setUuid(MATCHED_UUID);
        certificate.setSubjectDn(subjectDn);
        if (dnsSans != null) {
            certificate.setSubjectAlternativeNames(CertificateUtil.serializeSans(Map.of("dNSName", dnsSans)));
        }
        return certificate;
    }

    @Test
    void acceptsAMatchingSubjectAndSan() throws Exception {
        assertThatCode(() -> verifier
                .verify(crmf(SUBJECT_DN, List.of("device-1.example")), matched(SUBJECT_DN, List.of("device-1.example")),
                        CertificateEvent.ISSUE, TID))
                .doesNotThrowAnyException();
        verifyNoInteractions(eventHistoryService);
    }

    @Test
    void rejectsAndRecordsASanMismatch() throws Exception {
        assertThatThrownBy(() -> verifier
                .verify(crmf(SUBJECT_DN, List.of("attacker.example")), matched(SUBJECT_DN, List.of("device-1.example")),
                        CertificateEvent.REKEY, TID))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining(CmpRegistrationResolver.REGISTRATION_REJECTION);
        verify(eventHistoryService)
                .addEventHistory(eq(MATCHED_UUID), eq(CertificateEvent.REKEY), eq(CertificateEventStatus.FAILED),
                        org.mockito.ArgumentMatchers.contains("subject alternative names"), eq(""));
    }

    @Test
    void rejectsAndRecordsASubjectMismatch() throws Exception {
        assertThatThrownBy(() -> verifier
                .verify(crmf("CN=someone-else", List.of("device-1.example")),
                        matched(SUBJECT_DN, List.of("device-1.example")), CertificateEvent.ISSUE, TID))
                .isInstanceOf(CmpProcessingException.class)
                .hasMessageContaining(CmpRegistrationResolver.REGISTRATION_REJECTION);
        verify(eventHistoryService)
                .addEventHistory(eq(MATCHED_UUID), eq(CertificateEvent.ISSUE), eq(CertificateEventStatus.FAILED),
                        org.mockito.ArgumentMatchers.contains("subject does not match"), eq(""));
    }
}
