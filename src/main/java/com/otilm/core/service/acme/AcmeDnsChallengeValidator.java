package com.otilm.core.service.acme;

import com.otilm.api.model.core.acme.Problem;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.Properties;
import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Resolves the TXT records proving control of an identifier and matches them against the key authorization expected for
 * a DNS-01 challenge.
 */
public final class AcmeDnsChallengeValidator {

    private static final Logger logger = LoggerFactory.getLogger(AcmeDnsChallengeValidator.class);

    private static final String WILDCARD_PREFIX = "*.";

    private AcmeDnsChallengeValidator() {
    }

    /**
     * Queries the TXT records of {@code recordName} and reports whether one of them proves control.
     *
     * @param recordName name carrying the challenge response, from {@link #challengeRecordName(String)}
     * @param expectedKeyAuthorization digest of the key authorization the challenge expects
     * @param env resolver environment, from {@link #resolverEnv(String, String)}
     * @return the verdict, reporting a DNS problem when the records cannot be queried
     */
    public static ChallengeValidationResult validate(String recordName, String expectedKeyAuthorization,
            Properties env) {
        List<String> txtValues;
        try {
            txtValues = extractTxtValues(lookupTxtRecords(recordName, env));
        } catch (NamingException e) {
            logger.error("DNS query for {} failed: {}", recordName, e.getMessage());
            return ChallengeValidationResult.failure(Problem.DNS, "DNS query for " + recordName + " failed");
        }

        logger.debug("Resolved {} TXT record(s) for {}: {}", txtValues.size(), recordName, txtValues);
        return evaluate(recordName, txtValues, expectedKeyAuthorization);
    }

    /**
     * Name carrying the challenge response for an identifier. A wildcard identifier is proved at the challenge label of
     * its base domain (RFC 8555 section 8.4).
     */
    public static String challengeRecordName(String identifierValue) {
        String baseDomain = identifierValue.startsWith(WILDCARD_PREFIX)
                ? identifierValue.substring(WILDCARD_PREFIX.length())
                : identifierValue;
        return AcmeConstants.DNS_ACME_PREFIX + baseDomain;
    }

    /**
     * Resolver environment addressing the resolver declared by the ACME profile, or the system resolver when the
     * profile declares none.
     */
    public static Properties resolverEnv(String dnsResolverIp, String dnsResolverPort) {
        Properties env = new Properties();
        env.setProperty(Context.INITIAL_CONTEXT_FACTORY, AcmeConstants.DNS_CONTENT_FACTORY);
        if (dnsResolverIp == null || dnsResolverIp.isEmpty()) {
            env.setProperty(Context.PROVIDER_URL, AcmeConstants.DNS_ENV_PREFIX);
        } else {
            env
                    .setProperty(Context.PROVIDER_URL, AcmeConstants.DNS_ENV_PREFIX + dnsResolverIp + ":"
                            + Optional.ofNullable(dnsResolverPort).orElse(AcmeConstants.DEFAULT_DNS_PORT));
        }
        return env;
    }

    /**
     * Collects every TXT record returned for the queried name.
     *
     * <p>
     * The DNS provider returns all TXT records of a name as separate values of one {@code TXT} attribute, so the values
     * of each returned attribute have to be read. Reading the attributes alone yields a single record however many are
     * published, and which one it is depends on the order the resolver answered in.
     */
    static List<String> extractTxtValues(Attributes attributes) throws NamingException {
        List<String> txtValues = new ArrayList<>();
        NamingEnumeration<? extends Attribute> records = attributes.getAll();
        while (records.hasMore()) {
            NamingEnumeration<?> values = records.next().getAll();
            while (values.hasMore()) {
                txtValues.add(values.next().toString());
            }
        }
        return txtValues;
    }

    /**
     * Reports whether any published record matches the expected key authorization.
     *
     * <p>
     * Nothing published is a DNS problem, whereas records that are published but do not match are an incorrect
     * response. The published values stay out of the detail: they may hold verification tokens owned by third parties,
     * and the detail is returned to the client.
     */
    static ChallengeValidationResult evaluate(String recordName, List<String> txtValues,
            String expectedKeyAuthorization) {
        if (txtValues.isEmpty()) {
            return ChallengeValidationResult.failure(Problem.DNS, "No TXT record found at " + recordName);
        }
        if (txtValues.stream().noneMatch(txtValue -> matches(txtValue, expectedKeyAuthorization))) {
            return ChallengeValidationResult
                    .failure(Problem.INCORRECT_RESPONSE,
                            "No TXT record at " + recordName + " matches the expected key authorization");
        }
        return ChallengeValidationResult.success();
    }

    /**
     * A TXT record may be published as several character-strings, and its value is their concatenation. The DNS
     * provider renders such a record with the strings separated by a space, quoting only the strings that hold a
     * meta-character, so a key authorization split across strings arrives space-separated. A key authorization is
     * base64url and carries no space of its own, which is what makes removing them safe.
     */
    private static boolean matches(String txtValue, String expectedKeyAuthorization) {
        return txtValue.equals(expectedKeyAuthorization) || txtValue.replace(" ", "").equals(expectedKeyAuthorization);
    }

    private static Attributes lookupTxtRecords(String recordName, Properties env) throws NamingException {
        DirContext context = new InitialDirContext(env);
        try {
            return context.getAttributes(recordName, new String[]{AcmeConstants.DNS_RECORD_TYPE});
        } finally {
            context.close();
        }
    }

}
