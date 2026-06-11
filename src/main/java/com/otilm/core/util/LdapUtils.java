package com.otilm.core.util;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import java.util.Hashtable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class LdapUtils {

    private static final Logger logger = LoggerFactory.getLogger(LdapUtils.class);

    /**
     * Regular expression to match LDAP or LDAPS URI components with optional host
     * group 1: Protocol (ldap or ldaps)
     * group 2: Userinfo (optional)
     * group 3: Username (optional)
     * group 4: Password (optional)
     * group 5: Host (optional)
     * group 7: Port (optional)
     * group 9: Base DN (optional)
     * group 11: Attributes (optional)
     * group 13: Fragment (optional)
     */
    public static final String LDAP_URL_REGEX = "^(ldap|ldaps)://(([^/?#]+):([^/?#]+)@)?([^/?#:]*)?(:([0-9]+))?(/([^?#]*))?(\\?([^#]*))?(#(.*))?$";

    public static boolean isValidLdapUrl(String uri) {
        // Compile the regex pattern
        Pattern pattern = Pattern.compile(LDAP_URL_REGEX);

        // Create a matcher to find matches of the LDAP URI
        Matcher matcher = pattern.matcher(uri);

        // Check if the LDAP URI matches the pattern
        if (matcher.matches()) {
            // Extract and print each component of the LDAP URI
            logger.debug("Full match: " + matcher.group(0));
            logger.debug("Protocol: " + matcher.group(1));
            logger.debug("Userinfo (optional): " + matcher.group(2));
            logger.debug("Username (optional): " + matcher.group(3));
            logger.debug("Password (optional): " + matcher.group(4));
            logger.debug("Host (optional): " + matcher.group(5));
            logger.debug("Port (optional): " + matcher.group(7));
            logger.debug("Base DN (optional): " + matcher.group(9));
            logger.debug("Attributes (optional): " + matcher.group(11));
            logger.debug("Fragment (optional): " + matcher.group(13));
        } else {
            // Print an error message if the LDAP URI does not match the pattern
            logger.debug("The LDAP URI does not match the expected format.");
        }
        return matcher.matches();
    }

    public static byte[] downloadFromLdap(String ldapUrl) throws Exception {
        // Compile the regex pattern
        Pattern pattern = Pattern.compile(LDAP_URL_REGEX);

        // Create a matcher to find matches of the LDAP URI
        Matcher matcher = pattern.matcher(ldapUrl);

        if (!matcher.matches()) {
            throw new IllegalArgumentException("Invalid LDAP URL: " + ldapUrl);
        }

        // when no host is provided, we cannot connect to the LDAP server
        if (matcher.group(5) == null || matcher.group(5).isEmpty()) {
            throw new IllegalArgumentException("No host provided in LDAP URL: " + ldapUrl);
        }

        String baseDn = matcher.group(9) != null ? matcher.group(9) : "";
        String attributes = matcher.group(11) != null ? matcher.group(11) : "";
        String filter = matcher.group(13) != null ? matcher.group(13) : "(objectclass=*)";

        String attributeName = ""; // default to empty
        String[] attributesParts = attributes.split(";");
        if (attributesParts.length > 0) {
            attributeName = attributesParts[0];
        }

        String scope = "sub"; // default to sub
        // extract scope and filter from attributes
        String[] parts = attributes.split("\\?");
        if (parts.length > 1) {
            scope = parts[1];
        }

        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, ldapUrl);

        // Set security properties for LDAPS
        if (ldapUrl.startsWith("ldaps://")) {
            env.put(Context.SECURITY_PROTOCOL, "ssl");
        }

        LdapContext ctx = new InitialLdapContext(env, null);
        String[] attrIDs = {attributeName};
        SearchControls ctls = new SearchControls();
        ctls.setReturningAttributes(attrIDs);

        // Set the search scope based on the extracted scope
        if ("base".equalsIgnoreCase(scope)) {
            ctls.setSearchScope(SearchControls.OBJECT_SCOPE);
        } else if ("one".equalsIgnoreCase(scope)) {
            ctls.setSearchScope(SearchControls.ONELEVEL_SCOPE);
        } else if ("sub".equalsIgnoreCase(scope)) {
            ctls.setSearchScope(SearchControls.SUBTREE_SCOPE);
        } else {
            throw new IllegalArgumentException("Invalid LDAP URL search scope: " + ldapUrl);
        }

        NamingEnumeration<SearchResult> answer = ctx.search(baseDn, filter, ctls);
        if (answer.hasMore()) {
            Attributes attrs = answer.next().getAttributes();
            byte[] data = (byte[]) attrs.get(attributeName).get();
            ctx.close();
            return data;
        } else {
            ctx.close();
            throw new Exception("No data found for attribute in LDAP URL: " + ldapUrl);
        }
    }

}
