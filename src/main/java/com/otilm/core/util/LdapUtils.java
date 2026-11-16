package com.otilm.core.util;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Hashtable;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.naming.CompositeName;
import javax.naming.Context;
import javax.naming.NameNotFoundException;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import javax.naming.ldap.InitialLdapContext;
import javax.naming.ldap.LdapContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LdapUtils {

    private static final Logger logger = LoggerFactory.getLogger(LdapUtils.class);

    /**
     * Regular expression to match LDAP or LDAPS URI components with optional host group 1: Protocol (ldap or ldaps)
     * group 2: Userinfo (optional) group 3: Username (optional) group 4: Password (optional) group 5: Host (optional)
     * group 7: Port (optional) group 9: Base DN (optional) group 11: Attributes (optional) group 13: Fragment
     * (optional)
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
        return downloadFromLdap(ldapUrl, 0, 0);
    }

    /**
     * Reads the first attribute the LDAP URL names. A timeout of zero or less waits as long as the network allows; the
     * read timeout bounds the wait for each LDAP response.
     */
    public static byte[] downloadFromLdap(String ldapUrl, int connectTimeoutMillis, int readTimeoutMillis)
            throws NamingException {
        LdapRequest request = parseRequest(ldapUrl);
        Hashtable<String, String> env = new Hashtable<>();
        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, request.serverUrl());
        if (connectTimeoutMillis > 0) {
            env.put("com.sun.jndi.ldap.connect.timeout", Integer.toString(connectTimeoutMillis));
        }
        if (readTimeoutMillis > 0) {
            env.put("com.sun.jndi.ldap.read.timeout", Integer.toString(readTimeoutMillis));
        }

        if (request.serverUrl().regionMatches(true, 0, "ldaps://", 0, 8)) {
            env.put(Context.SECURITY_PROTOCOL, "ssl");
        }

        SearchControls ctls = new SearchControls();
        ctls.setReturningAttributes(new String[]{request.attributeName()});
        ctls.setSearchScope(request.scope());

        LdapContext ctx = new InitialLdapContext(env, null);
        try {
            NamingEnumeration<SearchResult> answer = ctx
                    .search(new CompositeName().add(request.baseDn()), request.filter(), ctls);
            try {
                if (!answer.hasMore()) {
                    throw new NameNotFoundException("No data found for attribute in LDAP URL: " + ldapUrl);
                }
                Attributes attrs = answer.next().getAttributes();
                return binaryValue(attrs, request.attributeName());
            } finally {
                // while an enumeration is open, closing the context only marks the connection for closing
                answer.close();
            }
        } finally {
            ctx.close();
        }
    }

    private static LdapRequest parseRequest(String ldapUrl) {
        URI uri = URI.create(ldapUrl);
        if (!("ldap".equalsIgnoreCase(uri.getScheme()) || "ldaps".equalsIgnoreCase(uri.getScheme()))
                || uri.getRawFragment() != null) {
            throw new IllegalArgumentException("Invalid LDAP URL: " + ldapUrl);
        }
        if (uri.getHost() == null || uri.getHost().isEmpty()) {
            throw new IllegalArgumentException("No host provided in LDAP URL: " + ldapUrl);
        }
        String[] query = uri.getRawQuery() == null ? new String[0] : uri.getRawQuery().split("\\?", -1);
        String attributeName = queryComponent(query, 0, "").split(",", -1)[0];
        if (attributeName.isBlank()) {
            throw new IllegalArgumentException("Missing attribute in LDAP URL: " + ldapUrl);
        }
        String scopeName = queryComponent(query, 1, "base");
        int scope;
        if ("base".equalsIgnoreCase(scopeName)) {
            scope = SearchControls.OBJECT_SCOPE;
        } else if ("one".equalsIgnoreCase(scopeName)) {
            scope = SearchControls.ONELEVEL_SCOPE;
        } else if ("sub".equalsIgnoreCase(scopeName)) {
            scope = SearchControls.SUBTREE_SCOPE;
        } else {
            throw new IllegalArgumentException("Invalid LDAP URL search scope: " + ldapUrl);
        }
        String path = uri.getPath();
        String baseDn = path == null || path.isEmpty() ? "" : path.substring(1);
        String serverUrl = uri.getScheme() + "://" + uri.getRawAuthority();
        return new LdapRequest(serverUrl, baseDn, attributeName, scope, queryComponent(query, 2, "(objectclass=*)"));
    }

    private static String queryComponent(String[] query, int index, String defaultValue) {
        if (index >= query.length || query[index].isEmpty()) {
            return defaultValue;
        }
        // LDAP URLs use URI encoding, where a literal plus is not a form-encoded space.
        return URLDecoder.decode(query[index].replace("+", "%2B"), StandardCharsets.UTF_8);
    }

    private static byte[] binaryValue(Attributes attributes, String attributeName) throws NamingException {
        Attribute attribute = attributes == null ? null : attributes.get(attributeName);
        if (attribute == null || attribute.size() == 0) {
            throw new NameNotFoundException("No data found for LDAP attribute " + attributeName);
        }
        Object value = attribute.get();
        if (!(value instanceof byte[] bytes) || bytes.length == 0) {
            throw new NamingException("No binary data found for LDAP attribute " + attributeName);
        }
        return bytes;
    }

    private record LdapRequest(String serverUrl, String baseDn, String attributeName, int scope, String filter) {
    }

}
