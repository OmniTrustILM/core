package com.otilm.core.certificate.request;

import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.common.attribute.common.content.AttributeContentType;
import com.otilm.api.model.common.attribute.v3.DataAttributeV3;
import com.otilm.api.model.common.attribute.v3.mapping.ObjectType;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static com.otilm.core.util.builders.MappedDataAttributeV3Builder.aMappedDataAttribute;
import static org.assertj.core.api.Assertions.assertThat;

class CsrAttrsEncoderTest {

    private static final Map<String, String> CODE_TO_OID = Map.of("CN", "2.5.4.3", "O", "2.5.4.10");

    @Test
    void encodesRdnTargetsAsBareOids() throws Exception {
        // given — two RDN-mapped attributes (CN, O)
        var definitions = List.of(
                aMappedDataAttribute().withName("cn").mappingRdn("CN").build(),
                aMappedDataAttribute().withName("o").mappingRdn("O").build());

        // when
        ASN1Sequence csrAttrs = encodeToSequence(definitions, CODE_TO_OID);

        // then — each RDN target is a bare attribute-type OID, in order
        assertThat(csrAttrs.size()).isEqualTo(2);
        assertThat(csrAttrs.getObjectAt(0)).isEqualTo(new ASN1ObjectIdentifier("2.5.4.3"));
        assertThat(csrAttrs.getObjectAt(1)).isEqualTo(new ASN1ObjectIdentifier("2.5.4.10"));
    }

    @Test
    void encodesEmptySequence_whenSetIsEmpty() throws Exception {
        // given — an empty request-attribute set

        // when
        ASN1Sequence csrAttrs = encodeToSequence(List.of(), CODE_TO_OID);

        // then
        assertThat(csrAttrs.size()).isEqualTo(0);
    }

    @Test
    void emitsDottedOidRdnDirectly() throws Exception {
        // given — an RDN mapped to a dotted OID rather than a well-known code
        var dottedOid = "1.3.6.1.4.1.99999.7";
        var definitions = List.of(aMappedDataAttribute().withName("custom").mappingRdn(dottedOid).build());

        // when
        ASN1Sequence csrAttrs = encodeToSequence(definitions, Map.of());

        // then
        assertThat(csrAttrs.getObjectAt(0)).isEqualTo(new ASN1ObjectIdentifier(dottedOid));
    }

    @Test
    void dedupesDuplicateRdnOids() throws Exception {
        // given — two attributes mapping to the same RDN (CN)
        var definitions = List.of(
                aMappedDataAttribute().withName("cn1").mappingRdn("CN").build(),
                aMappedDataAttribute().withName("cn2").mappingRdn("CN").build());

        // when
        ASN1Sequence csrAttrs = encodeToSequence(definitions, CODE_TO_OID);

        // then — the OID appears once
        assertThat(csrAttrs.size()).isEqualTo(1);
    }

    @Test
    void skipsUnmappedAttributes() throws Exception {
        // given — a plain attribute with no field mapping, alongside a mapped CN
        DataAttributeV3 unmapped = new DataAttributeV3();
        unmapped.setName("plain");
        unmapped.setContentType(AttributeContentType.STRING);
        var definitions = List.of(unmapped, aMappedDataAttribute().withName("cn").mappingRdn("CN").build());

        // when
        ASN1Sequence csrAttrs = encodeToSequence(definitions, CODE_TO_OID);

        // then — only the mapped attribute is projected
        assertThat(csrAttrs.size()).isEqualTo(1);
    }

    @Test
    void skipsNonX509FieldMapping() throws Exception {
        // given — an RDN mapping targeting a non-X.509 object type, alongside a mapped CN
        DataAttributeV3 sshRdn = aMappedDataAttribute().withName("sshCn").mappingRdn("CN").build();
        sshRdn.getFieldMapping().setObjectType(ObjectType.SSH_CERTIFICATE);
        var definitions = List.of(sshRdn, aMappedDataAttribute().withName("cn").mappingRdn("CN").build());

        // when
        ASN1Sequence csrAttrs = encodeToSequence(definitions, CODE_TO_OID);

        // then — only the X.509-mapped attribute is projected
        assertThat(csrAttrs.size()).isEqualTo(1);
        assertThat(csrAttrs.getObjectAt(0)).isEqualTo(new ASN1ObjectIdentifier("2.5.4.3"));
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static ASN1Sequence encodeToSequence(List<? extends BaseAttribute> definitions, Map<String, String> codeToOid)
            throws Exception {
        return (ASN1Sequence) ASN1Primitive.fromByteArray(CsrAttrsEncoder.encode(definitions, codeToOid));
    }
}
