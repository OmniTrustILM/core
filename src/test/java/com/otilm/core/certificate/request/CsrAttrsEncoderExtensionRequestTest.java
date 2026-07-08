package com.otilm.core.certificate.request;

import com.otilm.api.model.core.certificate.GeneralNameType;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import static com.otilm.core.util.builders.MappedDataAttributeV3Builder.aMappedDataAttribute;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies the RFC 7030 §4.5.2 form of the {@code extensionRequest} attribute: its {@code values} SET
 * lists the requested extension OIDs <em>directly</em> as bare OBJECT IDENTIFIERs.
 */
class CsrAttrsEncoderExtensionRequestTest {

    @Test
    void requestsSubjectAltNameUnderExtensionRequest_whenSanMapped() throws Exception {
        // given — a SAN-mapped (DNS) attribute
        var definitions = List.of(aMappedDataAttribute().withName("fqdn").mappingSan(GeneralNameType.DNS).build());

        // when
        List<ASN1ObjectIdentifier> requested = extensionRequestOids(CsrAttrsEncoder.encode(definitions, Map.of()));

        // then — SAN is requested under id-ce-subjectAltName (2.5.29.17), as a bare OID
        assertThat(requested).as("extensionRequest attribute must be present")
                .isNotNull()
                .contains(Extension.subjectAlternativeName);
    }

    @Test
    void listsExtensionOidUnderExtensionRequest_whenExtensionMapped() throws Exception {
        // given — an EXTENSION-mapped attribute (extended key usage, 2.5.29.37)
        var ekuOid = "2.5.29.37";
        var definitions = List.of(aMappedDataAttribute().withName("eku").mappingExtension(ekuOid).build());

        // when
        List<ASN1ObjectIdentifier> requested = extensionRequestOids(CsrAttrsEncoder.encode(definitions, Map.of()));

        // then
        assertThat(requested).isNotNull().contains(new ASN1ObjectIdentifier(ekuOid));
    }

    @Test
    void emitsBareOidsWithoutExtnValueWrapping_whenExtensionMapped() throws Exception {
        // given — an EXTENSION-mapped attribute
        var ekuOid = "2.5.29.37";
        var definitions = List.of(aMappedDataAttribute().withName("eku").mappingExtension(ekuOid).build());

        // when
        ASN1Set values = extensionRequestValues(CsrAttrsEncoder.encode(definitions, Map.of()));

        // then — every element is a bare OID, never an Extension SEQUENCE / octet-string wrapper
        assertThat(values).isNotNull();
        for (int i = 0; i < values.size(); i++) {
            assertThat(values.getObjectAt(i).toASN1Primitive())
                    .as("extensionRequest values must be bare OIDs (RFC 7030 §4.5.2 form)")
                    .isInstanceOf(ASN1ObjectIdentifier.class);
        }
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
        assertThat(extensionRequestOids(der)).contains(Extension.subjectAlternativeName);
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    /** Returns the extension OIDs listed in the PKCS#9 extensionRequest attribute's values SET, or null. */
    private static List<ASN1ObjectIdentifier> extensionRequestOids(byte[] der) throws Exception {
        ASN1Set values = extensionRequestValues(der);
        if (values == null) {
            return null;
        }
        List<ASN1ObjectIdentifier> oids = new ArrayList<>();
        for (ASN1Encodable value : values) {
            oids.add(ASN1ObjectIdentifier.getInstance(value));
        }
        return oids;
    }

    /** Returns the raw values SET of the PKCS#9 extensionRequest attribute in an encoded CsrAttrs, or null. */
    private static ASN1Set extensionRequestValues(byte[] der) throws Exception {
        ASN1Sequence csrAttrs = (ASN1Sequence) ASN1Primitive.fromByteArray(der);
        for (int i = 0; i < csrAttrs.size(); i++) {
            if (csrAttrs.getObjectAt(i) instanceof ASN1Sequence) {
                Attribute attr = Attribute.getInstance(csrAttrs.getObjectAt(i));
                if (attr.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest)) {
                    return attr.getAttrValues();
                }
            }
        }
        return null;
    }
}
