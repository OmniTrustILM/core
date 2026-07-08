package com.otilm.core.service.est;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.service.RaProfileCertificateRequestAttributeService;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.otilm.core.util.builders.MappedDataAttributeV3Builder.aMappedDataAttribute;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;

class EstCsrAttrsServiceImplTest {

    @Test
    void buildsCsrAttrs_fromResolvedSet() throws Exception {
        // given — a resolver returning a CN RDN and a DNS SAN, with CN resolvable to 2.5.4.3
        RaProfileCertificateRequestAttributeService resolver = mock(RaProfileCertificateRequestAttributeService.class);
        doReturn(List.<BaseAttribute>of(
                aMappedDataAttribute().withName("cn").mappingRdn("CN").build(),
                aMappedDataAttribute().withName("fqdn").mappingSan(GeneralNameType.DNS).build()))
                .when(resolver).resolveIssueAttributeSet(any(RaProfile.class));
        EstCsrAttrsServiceImpl service = new EstCsrAttrsServiceImpl(resolver) {
            @Override
            protected Map<String, String> codeToOid() {
                return Map.of("CN", "2.5.4.3");
            }
        };

        // when
        byte[] der = service.buildCsrAttrs(mock(RaProfile.class));
        ASN1Sequence csrAttrs = (ASN1Sequence) ASN1Primitive.fromByteArray(der);

        // then — the CN OID plus one extensionRequest (for the SAN)
        assertThat(csrAttrs.size()).isEqualTo(2);
        assertThat(csrAttrs.getObjectAt(0)).isEqualTo(new ASN1ObjectIdentifier("2.5.4.3"));
    }
}
