package com.otilm.core.util;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

public class LdapUtilsTest {

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

}
