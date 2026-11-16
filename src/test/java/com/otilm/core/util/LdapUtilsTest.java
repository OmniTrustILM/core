package com.otilm.core.util;

import com.otilm.core.util.LdapFixtures.SearchResults;
import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.List;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import javax.naming.directory.SearchControls;
import javax.naming.ldap.InitialLdapContext;
import org.assertj.core.api.ThrowableAssert.ThrowingCallable;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.Timeout;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.MockedConstruction;
import org.mockito.junit.jupiter.MockitoExtension;

import static com.otilm.core.util.LdapFixtures.searchResults;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class LdapUtilsTest {

    /** Bounds how long the silent server holds a connection its client never closes. */
    private static final int HOLD_LIMIT_MILLIS = 20_000;

    private static final String VALID_URI_CERTIFICATE_HOST_BINARY = "ldap://ldap.example.com/cn=CA,dc=example,dc=com?cACertificate;binary";
    private static final String VALID_URI_CERTIFICATE_NO_HOST_BINARY = "ldap:///cn=CA,dc=example,dc=com?cACertificate;binary";

    private static final String VALID_URI_CERTIFICATE_HOST_BASE = "ldap://ldap.example.com/cn=CA,dc=example,dc=com?cACertificate?base?objectClass=cACertificate";
    private static final String VALID_URI_CERTIFICATE_NO_HOST_BASE = "ldap:///cn=CA,dc=example,dc=com?cACertificate?base?objectClass=cACertificate";

    private static final String VALID_URI_CRL_HOST_ONE = "ldap://ldap.example.com/cn=CA,dc=example,dc=com?certificateRevocationList?one?objectClass=cRLDistributionPoint";
    private static final String VALID_URI_CRL_NO_HOST_ONE = "ldap:///cn=CA,dc=example,dc=com?certificateRevocationList?one?objectClass=cRLDistributionPoint";

    private static final String VALID_URI_CRL_HOST_SUB = "ldap://ldap.example.com/cn=CA,dc=example,dc=com?certificateRevocationList?sub?objectClass=cRLDistributionPoint";
    private static final String VALID_URI_CRL_NO_HOST_SUB = "ldap:///cn=CA,dc=example,dc=com?certificateRevocationList?sub?objectClass=cRLDistributionPoint";

    private static final String VALID_URI_CERTIFICATE_LDAPS = "ldaps://ldap.example.com/cn=CA,dc=example,dc=com?cACertificate;binary";

    private static final String INVALID_URI_LDAPSS = "ldapss://ldap.example.com/cn=CA,dc=example,dc=com?cACertificate;binary?objectClass=cACertificate";

    @Test
    public void testValidUriCertificateHostBinary() {
        Assertions.assertTrue(LdapUtils.isValidLdapUrl(VALID_URI_CERTIFICATE_HOST_BINARY));
    }

    @Test
    public void testValidUriCertificateNoHostBinary() {
        Assertions.assertTrue(LdapUtils.isValidLdapUrl(VALID_URI_CERTIFICATE_NO_HOST_BINARY));
    }

    @Test
    public void testValidUriCertificateHostBase() {
        Assertions.assertTrue(LdapUtils.isValidLdapUrl(VALID_URI_CERTIFICATE_HOST_BASE));
    }

    @Test
    public void testValidUriCertificateNoHostBase() {
        Assertions.assertTrue(LdapUtils.isValidLdapUrl(VALID_URI_CERTIFICATE_NO_HOST_BASE));
    }

    @Test
    public void testValidUriCrlHostOne() {
        Assertions.assertTrue(LdapUtils.isValidLdapUrl(VALID_URI_CRL_HOST_ONE));
    }

    @Test
    public void testValidUriCrlNoHostOne() {
        Assertions.assertTrue(LdapUtils.isValidLdapUrl(VALID_URI_CRL_NO_HOST_ONE));
    }

    @Test
    public void testValidUriCrlHostSub() {
        Assertions.assertTrue(LdapUtils.isValidLdapUrl(VALID_URI_CRL_HOST_SUB));
    }

    @Test
    public void testValidUriCrlNoHostSub() {
        Assertions.assertTrue(LdapUtils.isValidLdapUrl(VALID_URI_CRL_NO_HOST_SUB));
    }

    @Test
    public void testValidUriCertificateLdaps() {
        Assertions.assertTrue(LdapUtils.isValidLdapUrl(VALID_URI_CERTIFICATE_LDAPS));
    }

    @Test
    public void testInvalidUriLdapss() {
        Assertions.assertFalse(LdapUtils.isValidLdapUrl(INVALID_URI_LDAPSS));
    }

    @Test
    public void testConnectValidUriCertificateHostBinary() {
        Assertions.assertThrows(Exception.class, () -> {
            LdapUtils.downloadFromLdap(VALID_URI_CERTIFICATE_HOST_BINARY);
        });
    }

    @Test
    public void testConnectValidUriCertificateNoHostBinary() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            LdapUtils.downloadFromLdap(VALID_URI_CERTIFICATE_NO_HOST_BINARY);
        });
    }

    @Test
    public void testConnectValidUriCertificateHostBase() {
        Assertions.assertThrows(Exception.class, () -> {
            LdapUtils.downloadFromLdap(VALID_URI_CERTIFICATE_HOST_BASE);
        });
    }

    @Test
    public void testConnectValidUriCertificateNoHostBase() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            LdapUtils.downloadFromLdap(VALID_URI_CERTIFICATE_NO_HOST_BASE);
        });
    }

    @Test
    public void testConnectValidUriCrlHostOne() {
        Assertions.assertThrows(Exception.class, () -> {
            LdapUtils.downloadFromLdap(VALID_URI_CRL_HOST_ONE);
        });
    }

    @Test
    public void testConnectValidUriCrlNoHostOne() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            LdapUtils.downloadFromLdap(VALID_URI_CRL_NO_HOST_ONE);
        });
    }

    @Test
    public void testConnectValidUriCrlHostSub() {
        Assertions.assertThrows(Exception.class, () -> {
            LdapUtils.downloadFromLdap(VALID_URI_CRL_HOST_SUB);
        });
    }

    @Test
    public void testConnectValidUriCrlNoHostSub() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            LdapUtils.downloadFromLdap(VALID_URI_CRL_NO_HOST_SUB);
        });
    }

    @Test
    public void testConnectValidUriCertificateLdaps() {
        Assertions.assertThrows(Exception.class, () -> {
            LdapUtils.downloadFromLdap(VALID_URI_CERTIFICATE_LDAPS);
        });
    }

    @Test
    public void testConnectInvalidUriLdapss() {
        Assertions.assertThrows(IllegalArgumentException.class, () -> {
            LdapUtils.downloadFromLdap(INVALID_URI_LDAPSS);
        });
    }

    @Test
    @Timeout(20)
    void failsWithinReadTimeout_whenServerNeverAnswers() throws Exception {
        // given
        try (ServerSocket silentServer = new ServerSocket(0, 1, InetAddress.getByName(LoopbackWireMock.HOST))) {
            Thread.ofVirtual().start(() -> holdConnectionOpen(silentServer));
            String ldapUrl = "ldap://%s:%d/cn=CA?certificateRevocationList;binary?base"
                    .formatted(LoopbackWireMock.HOST, silentServer.getLocalPort());

            // when
            ThrowingCallable download = () -> LdapUtils.downloadFromLdap(ldapUrl, 500, 500);

            // then
            assertThatThrownBy(download).isInstanceOf(NamingException.class).hasMessageContaining("read timed out");
        }
    }

    @Test
    void returnsBinaryAttribute_whenUrlEncodesDnAndSearchFields() throws Exception {
        // given
        byte[] certificateBytes = {1, 2, 3};
        var attributes = new BasicAttributes("cACertificate;binary", certificateBytes, true);
        SearchResults results = searchResults(attributes);
        List<Hashtable<?, ?>> environments = new ArrayList<>();
        String ldapUrl = "ldaps://ldap.example.com:636/CN=CA+OU=PKI%20Team,DC=example"
                + "?cACertificate%3Bbinary?one?%28cn%3DA+B%3F%29";
        try (MockedConstruction<InitialLdapContext> contexts = mockConstruction(InitialLdapContext.class,
                (context, construction) -> {
                    environments.add((Hashtable<?, ?>) construction.arguments().getFirst());
                    when(context.search(anyString(), anyString(), any(SearchControls.class))).thenReturn(results);
                })) {
            // when
            byte[] downloaded = LdapUtils.downloadFromLdap(ldapUrl, 400, 700);

            // then
            assertThat(downloaded).isEqualTo(certificateBytes);
            assertThat(environments).hasSize(1);
            Hashtable<?, ?> environment = environments.getFirst();
            assertThat(environment.get(Context.PROVIDER_URL)).isEqualTo("ldaps://ldap.example.com:636");
            assertThat(environment.get(Context.SECURITY_PROTOCOL)).isEqualTo("ssl");
            assertThat(environment.get("com.sun.jndi.ldap.connect.timeout")).isEqualTo("400");
            assertThat(environment.get("com.sun.jndi.ldap.read.timeout")).isEqualTo("700");
            var controls = ArgumentCaptor.forClass(SearchControls.class);
            verify(contexts.constructed().getFirst())
                    .search(eq("CN=CA+OU=PKI Team,DC=example"), eq("(cn=A+B?)"), controls.capture());
            assertThat(controls.getValue().getReturningAttributes()).containsExactly("cACertificate;binary");
            assertThat(controls.getValue().getSearchScope()).isEqualTo(SearchControls.ONELEVEL_SCOPE);
            assertThat(results.isClosed()).isTrue();
            verify(contexts.constructed().getFirst()).close();
        }
    }

    @ParameterizedTest
    @CsvSource({"'',0", "base,0", "one,1", "sub,2"})
    void usesRequestedScope_whenUrlNamesAnAttributeWithoutBinaryOption(String scope, int expectedScope)
            throws Exception {
        // given
        byte[] certificateBytes = {1, 2, 3};
        SearchResults results = searchResults(new BasicAttributes("cACertificate", certificateBytes, true));
        String ldapUrl = "ldap://ldap.example.com/CN=CA?cACertificate" + (scope.isEmpty() ? "" : "?" + scope);
        try (MockedConstruction<InitialLdapContext> contexts = mockConstruction(InitialLdapContext.class,
                (context, construction) -> when(context.search(anyString(), anyString(), any(SearchControls.class)))
                        .thenReturn(results))) {
            // when
            byte[] downloaded = LdapUtils.downloadFromLdap(ldapUrl);

            // then
            assertThat(downloaded).isEqualTo(certificateBytes);
            var controls = ArgumentCaptor.forClass(SearchControls.class);
            verify(contexts.constructed().getFirst()).search(eq("CN=CA"), eq("(objectclass=*)"), controls.capture());
            assertThat(controls.getValue().getSearchScope()).isEqualTo(expectedScope);
            assertThat(controls.getValue().getReturningAttributes()).containsExactly("cACertificate");
        }
    }

    @ParameterizedTest
    @ValueSource(strings = {"missing", "empty", "text", "empty-bytes"})
    void throwsNamingException_whenRequestedAttributeHasNoBinaryValue(String invalidValue) throws Exception {
        // given
        var attributes = new BasicAttributes(true);
        if (invalidValue.equals("empty")) {
            attributes.put(new BasicAttribute("cACertificate"));
        } else if (invalidValue.equals("text")) {
            attributes.put("cACertificate", "not binary");
        } else if (invalidValue.equals("empty-bytes")) {
            attributes.put("cACertificate", new byte[0]);
        }
        SearchResults results = searchResults(attributes);
        try (MockedConstruction<InitialLdapContext> contexts = mockConstruction(InitialLdapContext.class,
                (context, construction) -> when(context.search(anyString(), anyString(), any(SearchControls.class)))
                        .thenReturn(results))) {
            // when
            ThrowingCallable download = () -> LdapUtils.downloadFromLdap("ldap://ldap.example.com/CN=CA?cACertificate");

            // then
            assertThatThrownBy(download).isInstanceOf(NamingException.class).hasMessageContaining("cACertificate");
            assertThat(results.isClosed()).isTrue();
            verify(contexts.constructed().getFirst()).close();
        }
    }

    @Test
    void throwsNamingException_whenSearchReturnsNoEntries() throws Exception {
        // given
        SearchResults results = searchResults();
        try (MockedConstruction<InitialLdapContext> contexts = mockConstruction(InitialLdapContext.class,
                (context, construction) -> when(context.search(anyString(), anyString(), any(SearchControls.class)))
                        .thenReturn(results))) {
            // when
            ThrowingCallable download = () -> LdapUtils.downloadFromLdap("ldap://ldap.example.com/CN=CA?cACertificate");

            // then
            assertThatThrownBy(download).isInstanceOf(NamingException.class).hasMessageContaining("No data found");
            assertThat(results.isClosed()).isTrue();
            verify(contexts.constructed().getFirst()).close();
        }
    }

    @Test
    void closesContext_whenSearchFails() throws Exception {
        // given
        var searchFailure = new NamingException("directory unavailable");
        try (MockedConstruction<InitialLdapContext> contexts = mockConstruction(InitialLdapContext.class,
                (context, construction) -> when(context.search(anyString(), anyString(), any(SearchControls.class)))
                        .thenThrow(searchFailure))) {
            // when
            ThrowingCallable download = () -> LdapUtils.downloadFromLdap("ldap://ldap.example.com/CN=CA?cACertificate");

            // then
            assertThatThrownBy(download).isSameAs(searchFailure);
            verify(contexts.constructed().getFirst()).close();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    /** Reads what the client sends and never answers, holding the connection until the client hangs up. */
    private static void holdConnectionOpen(ServerSocket server) {
        try (Socket client = server.accept()) {
            client.setSoTimeout(HOLD_LIMIT_MILLIS);
            client.getInputStream().transferTo(OutputStream.nullOutputStream());
        } catch (IOException connectionEnded) {
            // the client hung up, or the hold limit passed
        }
    }
}
