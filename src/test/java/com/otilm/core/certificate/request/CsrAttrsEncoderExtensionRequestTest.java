package com.otilm.core.certificate.request;

import com.otilm.api.model.core.certificate.GeneralNameType;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.otilm.core.util.builders.MappedDataAttributeV3Builder.aMappedDataAttribute;
import static org.assertj.core.api.Assertions.assertThat;

class CsrAttrsEncoderExtensionRequestTest {

    @Test
    void requestsSubjectAltNameUnderExtensionRequest_whenSanMapped() throws Exception {
        // given — a SAN-mapped (DNS) attribute
        var definitions = List.of(aMappedDataAttribute().withName("fqdn").mappingSan(GeneralNameType.DNS).build());

        // when
        Extensions extensionRequest = extensionRequestFrom(CsrAttrsEncoder.encode(definitions, Map.of()));

        // then — SAN is requested under id-ce-subjectAltName (2.5.29.17)
        assertThat(extensionRequest).as("extensionRequest attribute must be present").isNotNull();
        assertThat(extensionRequest.getExtension(Extension.subjectAlternativeName))
                .as("SAN must be requested under 2.5.29.17").isNotNull();
    }

    @Test
    void listsExtensionOidUnderExtensionRequest_whenExtensionMapped() throws Exception {
        // given — an EXTENSION-mapped attribute (extended key usage, 2.5.29.37)
        var ekuOid = "2.5.29.37";
        var definitions = List.of(aMappedDataAttribute().withName("eku").mappingExtension(ekuOid).build());

        // when
        Extensions extensionRequest = extensionRequestFrom(CsrAttrsEncoder.encode(definitions, Map.of()));

        // then
        assertThat(extensionRequest).isNotNull();
        assertThat(extensionRequest.getExtension(new ASN1ObjectIdentifier(ekuOid))).isNotNull();
    }

    @Test
    void emitsRdnAndExtensionRequest_whenBothMapped() throws Exception {
        // given — a CN RDN and a DNS SAN in the same set
        var definitions = List.of(
                aMappedDataAttribute().withName("cn").mappingRdn("CN").build(),
                aMappedDataAttribute().withName("san").mappingSan(GeneralNameType.DNS).build());

        // when
        byte[] der = CsrAttrsEncoder.encode(definitions, Map.of("CN", "2.5.4.3"));
        ASN1Sequence csrAttrs = (ASN1Sequence) ASN1Primitive.fromByteArray(der);

        // then — one bare RDN OID plus one extensionRequest attribute
        assertThat(csrAttrs.size()).isEqualTo(2);
        assertThat(csrAttrs.getObjectAt(0)).isEqualTo(new ASN1ObjectIdentifier("2.5.4.3"));
        assertThat(extensionRequestFrom(der)).isNotNull();
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /** Extracts the PKCS#9 extensionRequest attribute's {@link Extensions} from an encoded CsrAttrs, or null. */
    private static Extensions extensionRequestFrom(byte[] der) throws Exception {
        ASN1Sequence csrAttrs = (ASN1Sequence) ASN1Primitive.fromByteArray(der);
        for (int i = 0; i < csrAttrs.size(); i++) {
            if (csrAttrs.getObjectAt(i) instanceof ASN1Sequence) {
                Attribute attr = Attribute.getInstance(csrAttrs.getObjectAt(i));
                if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                    return Extensions.getInstance(attr.getAttrValues().getObjectAt(0));
                }
            }
        }
        return null;
    }
}
