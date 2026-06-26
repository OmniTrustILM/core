package com.otilm.core.util;

import com.otilm.api.model.connector.v3.certificate.GeneralNameEntry;
import com.otilm.api.model.connector.v3.certificate.RequestedExtension;
import com.otilm.api.model.connector.v3.certificate.RdnEntry;
import com.otilm.api.model.connector.v3.certificate.X509RequestContent;
import com.otilm.api.model.core.certificate.GeneralNameType;
import com.otilm.api.model.core.oid.ExtensionValueEncoding;
import com.otilm.api.model.core.oid.OidCategory;
import com.otilm.core.oid.OidHandler;
import com.otilm.core.oid.OidRecord;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import javax.security.auth.x500.X500Principal;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class X509RequestContentRendererTest {

    @Nested
    class ToX500Principal {

        public static final String MYCODE = "MYCODE";

        // The OidHandler cache is process-wide static state shared across the whole test JVM.
        // Snapshot RDN_ATTRIBUTE_TYPE before this class replaces it, and restore it afterwards,
        // so tests that run later in the same JVM (e.g. PlatformX500NameStyleTest) still see the
        // system OIDs seeded by the Spring context.
        private static Map<String, OidRecord> savedRdnCache;

        @BeforeAll
        static void saveOidCache() {
            Map<String, OidRecord> existing = OidHandler.getOidCache(OidCategory.RDN_ATTRIBUTE_TYPE);
            savedRdnCache = existing == null ? null : new HashMap<>(existing);
        }

        @AfterAll
        static void restoreOidCache() {
            if (savedRdnCache != null) {
                OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, savedRdnCache);
            }
        }

        @BeforeEach
        void seedCache() {
            OidHandler.cacheOidCategory(OidCategory.RDN_ATTRIBUTE_TYPE, new HashMap<>());
            OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "2.5.4.3",
                    OidRecord.builder().displayName("Common Name").code("CN").build());
            OidHandler.cacheOid(OidCategory.RDN_ATTRIBUTE_TYPE, "1.2.3.4.5.6",
                    OidRecord.builder().displayName("Custom").code(MYCODE).build());
        }

        @Test
        void buildsDnWithStandardAndCustomRdn() throws IOException {
            RdnEntry cn = new RdnEntry();
            cn.setType("CN");
            cn.setValue("host.example.com");
            RdnEntry custom = new RdnEntry();
            custom.setType("1.3.6.1.4.1.99999.5");
            custom.setValue("X1");
            X509RequestContent x509 = new X509RequestContent();
            x509.setSubject(List.of(cn, custom));

            X500Principal name = X509RequestContentRenderer.toX500Principal(x509);

            String s = name.toString();
            assertTrue(s.contains("CN=host.example.com"));
            assertTrue(s.contains("1.3.6.1.4.1.99999.5=X1"));
        }

        @Test
        void resolvesCustomCodeViaOidCache() throws IOException {
            RdnEntry entry = new RdnEntry();
            entry.setType(MYCODE);
            entry.setValue("val");
            X509RequestContent x509 = new X509RequestContent();
            x509.setSubject(List.of(entry));

            X500Principal name = X509RequestContentRenderer.toX500Principal(x509);

            assertTrue(name.toString().contains("1.2.3.4.5.6=val"));
        }

        @Test
        void emptySubject_returnsEmptyDn() throws IOException {
            X509RequestContent x509 = new X509RequestContent();
            x509.setSubject(List.of());

            assertEquals("", X509RequestContentRenderer.toX500Principal(x509).toString());
        }

        @Test
        void nullSubject_returnsEmptyDn() throws IOException {
            assertEquals("", X509RequestContentRenderer.toX500Principal(new X509RequestContent()).toString());
        }

        @Test
        void unknownCode_throws() {
            RdnEntry entry = new RdnEntry();
            entry.setType("UNKNOWNCODE");
            entry.setValue("val");
            X509RequestContent x509 = new X509RequestContent();
            x509.setSubject(List.of(entry));

            assertThrows(IllegalArgumentException.class, () -> X509RequestContentRenderer.toX500Principal(x509));
        }
    }

    @Nested
    class ToExtensions {

        @Test
        void buildsSubjectAltNameExtensionFromDnsSan() throws Exception {
            GeneralNameEntry dns = new GeneralNameEntry();
            dns.setType(GeneralNameType.DNS);
            dns.setValue("host.example.com");
            X509RequestContent x509 = new X509RequestContent();
            x509.setSubjectAltNames(List.of(dns));

            Extensions ext = X509RequestContentRenderer.toExtensions(x509);

            assertNotNull(ext.getExtension(Extension.subjectAlternativeName));
            GeneralNames gns = GeneralNames.getInstance(
                    ext.getExtension(Extension.subjectAlternativeName).getParsedValue());
            assertEquals(GeneralName.dNSName, gns.getNames()[0].getTagNo());
            assertEquals("host.example.com", gns.getNames()[0].getName().toString());
        }

        @Test
        void buildsSubjectAltNameFromEmailSan() throws Exception {
            GeneralNameEntry email = new GeneralNameEntry();
            email.setType(GeneralNameType.EMAIL);
            email.setValue("user@example.com");
            X509RequestContent x509 = new X509RequestContent();
            x509.setSubjectAltNames(List.of(email));

            Extensions ext = X509RequestContentRenderer.toExtensions(x509);

            GeneralNames gns = GeneralNames.getInstance(
                    ext.getExtension(Extension.subjectAlternativeName).getParsedValue());
            assertEquals(GeneralName.rfc822Name, gns.getNames()[0].getTagNo());
            assertEquals("user@example.com", gns.getNames()[0].getName().toString());
        }

        @Test
        void buildsSubjectAltNameFromUriSan() throws Exception {
            GeneralNameEntry uri = new GeneralNameEntry();
            uri.setType(GeneralNameType.URI);
            uri.setValue("https://example.com");
            X509RequestContent x509 = new X509RequestContent();
            x509.setSubjectAltNames(List.of(uri));

            Extensions ext = X509RequestContentRenderer.toExtensions(x509);

            GeneralNames gns = GeneralNames.getInstance(
                    ext.getExtension(Extension.subjectAlternativeName).getParsedValue());
            assertEquals(GeneralName.uniformResourceIdentifier, gns.getNames()[0].getTagNo());
        }

        @Test
        void multipleSanEntriesAllPresent() throws Exception {
            GeneralNameEntry dns = new GeneralNameEntry();
            dns.setType(GeneralNameType.DNS);
            dns.setValue("a.example.com");
            GeneralNameEntry email = new GeneralNameEntry();
            email.setType(GeneralNameType.EMAIL);
            email.setValue("a@example.com");
            X509RequestContent x509 = new X509RequestContent();
            x509.setSubjectAltNames(List.of(dns, email));

            Extensions ext = X509RequestContentRenderer.toExtensions(x509);

            GeneralNames gns = GeneralNames.getInstance(
                    ext.getExtension(Extension.subjectAlternativeName).getParsedValue());
            assertEquals(2, gns.getNames().length);
        }

        @Test
        void noSansAndNoExtensions_returnsEmptyExtensions() throws Exception {
            Extensions ext = X509RequestContentRenderer.toExtensions(new X509RequestContent());

            assertNull(ext);
        }
    }

    @Nested
    class Criticality {

        private static RequestedExtension ext(String oid) {
            RequestedExtension e = new RequestedExtension();
            e.setOid(oid);
            e.setCritical(false);
            e.setEncoding(ExtensionValueEncoding.DER);
            e.setValue("MAMCAQA=");
            return e;
        }

        @Test
        void basicConstraintsForcedCriticalEvenWhenRequestedNonCritical() throws Exception {
            X509RequestContent x509 = new X509RequestContent();
            x509.setExtensions(List.of(ext("2.5.29.19")));

            Extensions extensions = X509RequestContentRenderer.toExtensions(x509);

            assertTrue(extensions.getExtension(Extension.basicConstraints).isCritical());
        }

        @Test
        void keyUsageForcedCriticalEvenWhenRequestedNonCritical() throws Exception {
            X509RequestContent x509 = new X509RequestContent();
            x509.setExtensions(List.of(ext("2.5.29.15")));

            Extensions extensions = X509RequestContentRenderer.toExtensions(x509);

            assertTrue(extensions.getExtension(Extension.keyUsage).isCritical());
        }

        @Test
        void nonBlocklistedExtension_respectsRequestedCriticality() throws Exception {
            X509RequestContent x509 = new X509RequestContent();
            x509.setExtensions(List.of(ext("2.5.29.37")));

            Extensions extensions = X509RequestContentRenderer.toExtensions(x509);

            assertFalse(extensions.getExtension(new ASN1ObjectIdentifier("2.5.29.37")).isCritical());
        }

        @Test
        void blockedOidsConstantContainsBothMandatoryOids() {
            assertTrue(X509RequestContentRenderer.CRITICALITY_FORCED_OIDS.contains(Extension.basicConstraints.getId()));
            assertTrue(X509RequestContentRenderer.CRITICALITY_FORCED_OIDS.contains(Extension.keyUsage.getId()));
        }
    }
}
