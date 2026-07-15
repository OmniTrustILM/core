package com.otilm.core.util;

import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
import com.otilm.api.model.connector.v3.certificate.RequestedExtension;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Encoding;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.OtherName;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class X509RequestContentRendererTest {

    // ── ToX500Principal ─────────────────────────────────────────────────────

    @Nested
    class ToX500Principal {

        private static final String CUSTOM_CODE = "MYCODE";

        // The OidHandler cache is a process-wide static state shared across the whole test JVM.
        // Snapshot RDN_ATTRIBUTE_TYPE before this class replaces it. Restore it afterwards.
        private static Map<String, OidRecord> savedRdnCache;

        @BeforeAll
        static void snapshotRdnCache() {
            Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
            savedRdnCache = existing == null ? null : new HashMap<>(existing);
        }

        @AfterAll
        static void restoreRdnCache() {
            OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE,
                    savedRdnCache != null ? savedRdnCache : new HashMap<>());
        }

        @BeforeEach
        void seedRdnCacheWithCnAndCustomCode() {
            OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
            OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                    OidRecord.builder().displayName("Common Name").code("CN").build());
            OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "1.2.3.4.5.6",
                    OidRecord.builder().displayName("Custom").code(CUSTOM_CODE).build());
        }

        @Test
        void buildsDn_fromStandardCodeAndDottedOidRdns() throws IOException {
            // given — a CN code RDN and a dotted-decimal OID RDN
            var x509 = subjectOf(rdn("CN", "host.example.com"), rdn("1.3.6.1.4.1.99999.5", "X1"));

            // when
            X500Principal name = X509RequestContentRenderer.toX500Principal(x509);

            // then
            assertThat(name.toString()).contains("CN=host.example.com");
            assertThat(name.toString()).contains("1.3.6.1.4.1.99999.5=X1");
        }

        @Test
        void resolvesRdnType_viaCustomCodeInOidCache() throws IOException {
            // given — an RDN whose type is a custom code registered in the OID cache
            var x509 = subjectOf(rdn(CUSTOM_CODE, "val"));

            // when
            X500Principal name = X509RequestContentRenderer.toX500Principal(x509);

            // then
            assertThat(name.toString()).contains("1.2.3.4.5.6=val");
        }

        @Test
        void returnsEmptyDn_whenSubjectIsEmpty() throws IOException {
            // given
            var x509 = subjectOf();

            // when / then
            assertThat(X509RequestContentRenderer.toX500Principal(x509).toString()).isEmpty();
        }

        @Test
        void returnsEmptyDn_whenSubjectIsNull() throws IOException {
            // given — a request with no subject set at all
            var x509 = new X509RequestContent();

            // when / then
            assertThat(X509RequestContentRenderer.toX500Principal(x509).toString()).isEmpty();
        }

        @Test
        void throwsIllegalArgument_whenRdnCodeIsUnknown() {
            // given — an RDN type that is neither a dotted OID nor a known code
            var x509 = subjectOf(rdn("UNKNOWNCODE", "val"));

            // when / then
            assertThatThrownBy(() -> X509RequestContentRenderer.toX500Principal(x509))
                    .isInstanceOf(IllegalArgumentException.class);
        }

        private static RdnEntry rdn(String type, String value) {
            RdnEntry e = new RdnEntry();
            e.setType(type);
            e.setValue(value);
            return e;
        }

        private static X509RequestContent subjectOf(RdnEntry... rdns) {
            X509RequestContent x509 = new X509RequestContent();
            x509.setSubject(List.of(rdns));
            return x509;
        }
    }

    // ── ToExtensions ────────────────────────────────────────────────────────

    @Nested
    class ToExtensions {

        @Test
        void buildsSubjectAltName_fromDnsSan() throws Exception {
            // given
            var x509 = sansOf(san(GeneralNameType.DNS, "host.example.com"));

            // when
            Extensions ext = X509RequestContentRenderer.toExtensions(x509);

            // then
            GeneralName[] names = sanNamesOf(ext);
            assertThat(names[0].getTagNo()).isEqualTo(GeneralName.dNSName);
            assertThat(names[0].getName()).hasToString("host.example.com");
        }

        @Test
        void buildsSubjectAltName_fromEmailSan() throws Exception {
            // given
            var x509 = sansOf(san(GeneralNameType.EMAIL, "user@example.com"));

            // when
            Extensions ext = X509RequestContentRenderer.toExtensions(x509);

            // then
            GeneralName[] names = sanNamesOf(ext);
            assertThat(names[0].getTagNo()).isEqualTo(GeneralName.rfc822Name);
            assertThat(names[0].getName()).hasToString("user@example.com");
        }

        @Test
        void buildsSubjectAltName_fromUriSan() throws Exception {
            // given
            var x509 = sansOf(san(GeneralNameType.URI, "https://example.com"));

            // when
            Extensions ext = X509RequestContentRenderer.toExtensions(x509);

            // then
            assertThat(sanNamesOf(ext)[0].getTagNo()).isEqualTo(GeneralName.uniformResourceIdentifier);
        }

        @Test
        void includesAllEntries_whenMultipleSansPresent() throws Exception {
            // given
            var x509 = sansOf(san(GeneralNameType.DNS, "a.example.com"),
                    san(GeneralNameType.EMAIL, "a@example.com"));

            // when
            Extensions ext = X509RequestContentRenderer.toExtensions(x509);

            // then
            assertThat(sanNamesOf(ext)).hasSize(2);
        }

        @Test
        void returnsNull_whenNoSansAndNoExtensions() throws Exception {
            // given — an empty request
            var x509 = new X509RequestContent();

            // when / then
            assertThat(X509RequestContentRenderer.toExtensions(x509)).isNull();
        }

        @Test
        void buildsSubjectAltName_fromIpSan() throws Exception {
            // given
            var x509 = sansOf(san(GeneralNameType.IP, "192.0.2.10"));

            // when
            GeneralName[] names = sanNamesOf(X509RequestContentRenderer.toExtensions(x509));

            // then
            assertThat(names[0].getTagNo()).isEqualTo(GeneralName.iPAddress);
        }

        @Test
        void buildsSubjectAltName_fromDirectoryNameSan() throws Exception {
            // given
            var x509 = sansOf(san(GeneralNameType.DIRECTORY_NAME, "CN=dir.example.com,O=Example"));

            // when
            GeneralName[] names = sanNamesOf(X509RequestContentRenderer.toExtensions(x509));

            // then
            assertThat(names[0].getTagNo()).isEqualTo(GeneralName.directoryName);
        }

        @Test
        void buildsSubjectAltName_fromRegisteredIdSan() throws Exception {
            // given
            var x509 = sansOf(san(GeneralNameType.REGISTERED_ID, "1.3.6.1.4.1.99999.7"));

            // when
            GeneralName[] names = sanNamesOf(X509RequestContentRenderer.toExtensions(x509));

            // then
            assertThat(names[0].getTagNo()).isEqualTo(GeneralName.registeredID);
        }

        @Test
        void marksSanCritical_whenSubjectIsEmpty() throws Exception {
            // given — SAN present but no subject DN (RFC 5280 §4.2.1.6)
            var x509 = sansOf(san(GeneralNameType.DNS, "host.example.com"));

            // when
            Extensions ext = X509RequestContentRenderer.toExtensions(x509);

            // then
            assertThat(ext.getExtension(Extension.subjectAlternativeName).isCritical()).isTrue();
        }

        @Test
        void marksSanNonCritical_whenSubjectIsPresent() throws Exception {
            // given — both a subject RDN and a SAN
            var x509 = sansOf(san(GeneralNameType.DNS, "host.example.com"));
            RdnEntry cn = new RdnEntry();
            cn.setType("CN");
            cn.setValue("host.example.com");
            x509.setSubject(List.of(cn));

            // when
            Extensions ext = X509RequestContentRenderer.toExtensions(x509);

            // then
            assertThat(ext.getExtension(Extension.subjectAlternativeName).isCritical()).isFalse();
        }

        @Test
        void throwsIoException_whenExtensionOidIsMalformed() {
            // given — a requested extension carrying a non-OID string
            var ext = new RequestedExtension();
            ext.setOid("not-an-oid");
            ext.setCritical(false);
            ext.setEncoding(ExtensionValueEncoding.DER);
            ext.setValue("MAMCAQA=");
            var x509 = new X509RequestContent();
            x509.setExtensions(List.of(ext));

            // when / then
            assertThatThrownBy(() -> X509RequestContentRenderer.toExtensions(x509))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("Invalid or missing extension OID");
        }

        @Test
        void throwsIoException_whenTwoExtensionsShareTheSameOid() {
            // given — two requested extensions carrying the same OID (RFC 5280: each extension OID is unique)
            var oid = "2.5.29.37";
            var x509 = new X509RequestContent();
            x509.setExtensions(List.of(derExtension(oid), derExtension(oid)));

            // when / then — the renderer rejects the second occurrence before it reaches BouncyCastle, as a controlled IOException naming the OID
            assertThatThrownBy(() -> X509RequestContentRenderer.toExtensions(x509))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining(oid);
        }

        @Test
        void throwsIoException_whenExplicitExtensionDuplicatesSubjectAltName() {
            // given — a SAN entry plus an explicit extension mapped to the subjectAltName OID; both render into 2.5.29.17
            var sanOid = Extension.subjectAlternativeName.getId();
            var x509 = sansOf(san(GeneralNameType.DNS, "host.example.com"));
            x509.setExtensions(List.of(derExtension(sanOid)));

            // when / then — the subjectAltName extension may appear only once (RFC 5280)
            assertThatThrownBy(() -> X509RequestContentRenderer.toExtensions(x509))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining(sanOid);
        }

        @Test
        void rendersSanExtension_whenExplicitSubjectAltNameOidHasNoCompetingSanList() throws Exception {
            // given — no SAN list, but an explicit extension mapped to the subjectAltName OID (legal: the OID appears only once)
            var sanOid = Extension.subjectAlternativeName.getId();
            var x509 = new X509RequestContent();
            x509.setExtensions(List.of(derExtension(sanOid)));

            // when — the seenOids guard must not pre-register the SAN OID when the SAN list is empty
            Extensions extensions = X509RequestContentRenderer.toExtensions(x509);

            // then — the explicit extension renders as the subjectAltName extension
            assertThat(extensions.getExtension(Extension.subjectAlternativeName)).isNotNull();
        }

        private static RequestedExtension derExtension(String oid) {
            var e = new RequestedExtension();
            e.setOid(oid);
            e.setCritical(false);
            e.setEncoding(ExtensionValueEncoding.DER);
            e.setValue("MAMCAQA=");
            return e;
        }
    }

    // ── OtherNameEncoding ───────────────────────────────────────────────────

    @Nested
    class OtherNameEncoding {

        private static final String OTHER_NAME_OID = "1.3.6.1.4.1.311.20.2.3";

        @Test
        void encodesAsUtf8String_whenEncodingIsNull() throws Exception {
            // given — OTHER_NAME with no explicit encoding
            var x509 = sansOf(otherName("upn@example.com", null));

            // when
            ASN1Encodable value = otherNameValueOf(x509);

            // then
            assertThat(value).isInstanceOf(DERUTF8String.class);
            assertThat(((ASN1String) value).getString()).isEqualTo("upn@example.com");
        }

        @Test
        void encodesAsIa5String_whenEncodingIsIa5() throws Exception {
            // given
            var x509 = sansOf(otherName("upn@example.com", ExtensionValueEncoding.IA5_STRING));

            // when
            ASN1Encodable value = otherNameValueOf(x509);

            // then
            assertThat(value).isInstanceOf(DERIA5String.class);
            assertThat(((ASN1String) value).getString()).isEqualTo("upn@example.com");
        }

        @Test
        void encodesAsOctetString_whenEncodingIsOctetString() throws Exception {
            // given
            var rawValue = "raw-bytes";
            var x509 = sansOf(otherName(rawValue, ExtensionValueEncoding.OCTET_STRING));

            // when
            ASN1Encodable value = otherNameValueOf(x509);

            // then
            assertThat(value).isInstanceOf(ASN1OctetString.class);
            assertThat(((ASN1OctetString) value).getOctets())
                    .isEqualTo(rawValue.getBytes(StandardCharsets.UTF_8));
        }

        @Test
        void parsesDerValuePreservingType_whenEncodingIsDer() throws Exception {
            // given — DER encoding carries a base64-encoded DER object (a UTF8String here)
            var derBlob = new DERUTF8String("blob").getEncoded();
            var base64Der = java.util.Base64.getEncoder().encodeToString(derBlob);
            var x509 = sansOf(otherName(base64Der, ExtensionValueEncoding.DER));

            // when
            ASN1Encodable value = otherNameValueOf(x509);

            // then — the original ASN.1 type is preserved, not re-wrapped in an OCTET STRING
            assertThat(value).isInstanceOf(DERUTF8String.class);
            assertThat(((ASN1String) value).getString()).isEqualTo("blob");
        }

        @Test
        void preservesOctetStringType_whenEncodingIsDerAndValueIsDerOctetString() throws Exception {
            // given — DER encoding carrying a base64-encoded DER OCTET STRING
            var octets = "payload".getBytes(StandardCharsets.UTF_8);
            var derBlob = new DEROctetString(octets).getEncoded();
            var base64Der = java.util.Base64.getEncoder().encodeToString(derBlob);
            var x509 = sansOf(otherName(base64Der, ExtensionValueEncoding.DER));

            // when
            ASN1Encodable value = otherNameValueOf(x509);

            // then
            assertThat(value).isInstanceOf(ASN1OctetString.class);
            assertThat(((ASN1OctetString) value).getOctets()).isEqualTo(octets);
        }

        @Test
        void fallsBackToUtf8String_whenEncodingIsDerAndValueIsEmpty() throws Exception {
            // given — DER encoding but an empty value does not parse as a DER object
            var x509 = sansOf(otherName("", ExtensionValueEncoding.DER));

            // when
            ASN1Encodable value = otherNameValueOf(x509);

            // then
            assertThat(value).isInstanceOf(DERUTF8String.class);
            assertThat(((ASN1String) value).getString()).isEmpty();
        }

        @Test
        void fallsBackToUtf8String_whenEncodingIsDerAndValueIsInvalidBase64() throws Exception {
            // given — DER encoding but a value that is not valid base64
            var x509 = sansOf(otherName("not base64!!!", ExtensionValueEncoding.DER));

            // when
            ASN1Encodable value = otherNameValueOf(x509);

            // then
            assertThat(value).isInstanceOf(DERUTF8String.class);
            assertThat(((ASN1String) value).getString()).isEqualTo("not base64!!!");
        }

        @Test
        void encodesAsUtf8String_whenEncodingHasNoDedicatedBranch() throws Exception {
            // given — PRINTABLE_STRING falls through to the default UTF8String branch
            var x509 = sansOf(otherName("printable", ExtensionValueEncoding.PRINTABLE_STRING));

            // when
            ASN1Encodable value = otherNameValueOf(x509);

            // then
            assertThat(value).isInstanceOf(DERUTF8String.class);
            assertThat(((ASN1String) value).getString()).isEqualTo("printable");
        }

        private static GeneralNameEntry otherName(String value, ExtensionValueEncoding encoding) {
            GeneralNameEntry e = new GeneralNameEntry();
            e.setType(GeneralNameType.OTHER_NAME);
            e.setOtherNameOid(OTHER_NAME_OID);
            e.setValue(value);
            e.setValueEncoding(encoding);
            return e;
        }

        private static ASN1Encodable otherNameValueOf(X509RequestContent x509) throws IOException {
            GeneralName[] names = sanNamesOf(X509RequestContentRenderer.toExtensions(x509));
            assertThat(names[0].getTagNo()).isEqualTo(GeneralName.otherName);
            return OtherName.getInstance(names[0].getName()).getValue();
        }
    }

    // ── Criticality ─────────────────────────────────────────────────────────

    @Nested
    class Criticality {

        @Test
        void forcesCritical_forBasicConstraints_evenWhenRequestedNonCritical() throws Exception {
            // given — BasicConstraints requested as non-critical
            var x509 = extensionsOf(nonCriticalExtension("2.5.29.19"));

            // when
            Extensions extensions = X509RequestContentRenderer.toExtensions(x509);

            // then
            assertThat(extensions.getExtension(Extension.basicConstraints).isCritical()).isTrue();
        }

        @Test
        void forcesCritical_forKeyUsage_evenWhenRequestedNonCritical() throws Exception {
            // given — KeyUsage requested as non-critical
            var x509 = extensionsOf(nonCriticalExtension("2.5.29.15"));

            // when
            Extensions extensions = X509RequestContentRenderer.toExtensions(x509);

            // then
            assertThat(extensions.getExtension(Extension.keyUsage).isCritical()).isTrue();
        }

        @Test
        void respectsRequestedCriticality_forNonForcedExtension() throws Exception {
            // given — ExtendedKeyUsage (not in the forced set) requested as non-critical
            var nonForcedOid = "2.5.29.37";
            var x509 = extensionsOf(nonCriticalExtension(nonForcedOid));

            // when
            Extensions extensions = X509RequestContentRenderer.toExtensions(x509);

            // then
            assertThat(extensions.getExtension(new ASN1ObjectIdentifier(nonForcedOid)).isCritical()).isFalse();
        }

        @Test
        void forcedOidsConstant_containsBasicConstraintsAndKeyUsage() {
            // given / when / then
            assertThat(X509RequestContentRenderer.CRITICALITY_FORCED_OIDS)
                    .contains(Extension.basicConstraints.getId(), Extension.keyUsage.getId());
        }

        private static RequestedExtension nonCriticalExtension(String oid) {
            RequestedExtension e = new RequestedExtension();
            e.setOid(oid);
            e.setCritical(false);
            e.setEncoding(ExtensionValueEncoding.DER);
            e.setValue("MAMCAQA=");
            return e;
        }

        private static X509RequestContent extensionsOf(RequestedExtension... extensions) {
            X509RequestContent x509 = new X509RequestContent();
            x509.setExtensions(List.of(extensions));
            return x509;
        }
    }

    // ── ExtensionValueEncoding ──────────────────────────────────────────────

    @Nested
    class ExtensionValueEncodingTest {

        // ExtendedKeyUsage — not in the forced-critical set, so criticality does not interfere
        private static final String EXT_OID = "2.5.29.37";

        @Test
        void treatsValueAsBase64Der_whenEncodingIsDer() throws Exception {
            // given — value is a base64-encoded DER blob
            var derBlob = new DERUTF8String("hello").getEncoded(ASN1Encoding.DER);
            var base64Der = java.util.Base64.getEncoder().encodeToString(derBlob);

            // when
            byte[] extnValue = extnValueOf(extension(EXT_OID, ExtensionValueEncoding.DER, base64Der));

            // then — the decoded DER bytes are used verbatim as the extension value
            assertThat(extnValue).isEqualTo(derBlob);
        }

        @Test
        void encodesValueAsIa5String_whenEncodingIsIa5() throws Exception {
            // given
            var rawValue = "plain-ia5";

            // when
            byte[] extnValue = extnValueOf(extension(EXT_OID, ExtensionValueEncoding.IA5_STRING, rawValue));

            // then — the value is wrapped in a DER IA5String rather than base64-decoded
            assertThat(extnValue).isEqualTo(new DERIA5String(rawValue).getEncoded(ASN1Encoding.DER));
        }

        @Test
        void encodesValueAsOctetString_whenEncodingIsOctetString() throws Exception {
            // given
            var rawValue = "raw-octets";

            // when
            byte[] extnValue = extnValueOf(extension(EXT_OID, ExtensionValueEncoding.OCTET_STRING, rawValue));

            // then
            assertThat(extnValue).isEqualTo(
                    new DEROctetString(rawValue.getBytes(StandardCharsets.UTF_8)).getEncoded(ASN1Encoding.DER));
        }

        @Test
        void throwsIoException_whenEncodingIsDerAndValueIsInvalidBase64() {
            // given — a DER-encoded extension whose value is not valid base64
            var notBase64 = "not base64!!!";
            var x509 = new X509RequestContent();
            x509.setExtensions(List.of(extension(EXT_OID, ExtensionValueEncoding.DER, notBase64)));

            // when / then — the runtime decode failure is surfaced as a controlled IOException
            assertThatThrownBy(() -> X509RequestContentRenderer.toExtensions(x509))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("Invalid base64-encoded DER extension value");
        }

        @Test
        void throwsIoException_whenEncodingIsBitString() {
            // given — BIT_STRING is not supported on the extension path (would embed literal UTF-8 as bits)
            var x509 = new X509RequestContent();
            x509.setExtensions(List.of(extension(EXT_OID, ExtensionValueEncoding.BIT_STRING, "anything")));

            // when / then
            assertThatThrownBy(() -> X509RequestContentRenderer.toExtensions(x509))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("BIT_STRING extension value encoding is not supported");
        }

        @Test
        void throwsIoException_whenExtensionValueIsNull() {
            // given — an extension with no value
            var x509 = new X509RequestContent();
            x509.setExtensions(List.of(extension(EXT_OID, ExtensionValueEncoding.DER, null)));

            // when / then
            assertThatThrownBy(() -> X509RequestContentRenderer.toExtensions(x509))
                    .isInstanceOf(IOException.class)
                    .hasMessageContaining("Extension value is required");
        }

        private static byte[] extnValueOf(RequestedExtension ext) throws IOException {
            X509RequestContent x509 = new X509RequestContent();
            x509.setExtensions(List.of(ext));
            Extensions extensions = X509RequestContentRenderer.toExtensions(x509);
            return extensions.getExtension(new ASN1ObjectIdentifier(ext.getOid())).getExtnValue().getOctets();
        }

        private static RequestedExtension extension(String oid, ExtensionValueEncoding encoding, String value) {
            RequestedExtension e = new RequestedExtension();
            e.setOid(oid);
            e.setCritical(false);
            e.setEncoding(encoding);
            e.setValue(value);
            return e;
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    private static GeneralNameEntry san(GeneralNameType type, String value) {
        GeneralNameEntry e = new GeneralNameEntry();
        e.setType(type);
        e.setValue(value);
        return e;
    }

    private static X509RequestContent sansOf(GeneralNameEntry... sans) {
        X509RequestContent x509 = new X509RequestContent();
        x509.setSubjectAltNames(List.of(sans));
        return x509;
    }

    private static GeneralName[] sanNamesOf(Extensions ext) {
        assertThat(ext.getExtension(Extension.subjectAlternativeName)).isNotNull();
        return GeneralNames.getInstance(
                ext.getExtension(Extension.subjectAlternativeName).getParsedValue()).getNames();
    }
}
