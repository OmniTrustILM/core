package com.otilm.core.service.acme;

import com.otilm.api.model.core.acme.Problem;
import java.util.List;
import java.util.Properties;
import javax.naming.Context;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class AcmeDnsChallengeValidatorTest {

    private static final String IDENTIFIER = "nrf01.thp.nrf.5gc.mnc001.mcc230.example.org";
    private static final String RECORD_NAME = AcmeConstants.DNS_ACME_PREFIX + IDENTIFIER;
    private static final String EXPECTED_KEY_AUTHORIZATION = "pB0hVv6ackTHYaUi0Cap0dd9ORg47zEKsOtAEXcgmQQ";
    private static final String STALE_KEY_AUTHORIZATION = "f5R9M-KeH3NR4Yqq8J2EUN2ZjkjLWAUxC9gnZgR9B_4";

    /**
     * The DNS provider returns every TXT record of a name as separate values of one {@code TXT} attribute, so a name
     * carrying several records must still yield every value.
     */
    @Test
    void extractsEveryValueOfAMultiValuedTxtAttribute() throws NamingException {
        List<String> values = AcmeDnsChallengeValidator
                .extractTxtValues(txtAttributes(STALE_KEY_AUTHORIZATION, EXPECTED_KEY_AUTHORIZATION));

        Assertions.assertEquals(List.of(STALE_KEY_AUTHORIZATION, EXPECTED_KEY_AUTHORIZATION), values);
    }

    @Test
    void extractsNoValuesWhenTheNameHasNoTxtRecord() throws NamingException {
        Assertions.assertEquals(List.of(), AcmeDnsChallengeValidator.extractTxtValues(new BasicAttributes(true)));
    }

    @Test
    void acceptsTheExpectedRecordPublishedAlongsideStaleRecords() throws NamingException {
        List<String> values = AcmeDnsChallengeValidator
                .extractTxtValues(txtAttributes(STALE_KEY_AUTHORIZATION, EXPECTED_KEY_AUTHORIZATION));

        ChallengeValidationResult result = AcmeDnsChallengeValidator
                .evaluate(RECORD_NAME, values, EXPECTED_KEY_AUTHORIZATION);

        Assertions.assertTrue(result.valid());
        Assertions.assertNull(result.problem());
        Assertions.assertNull(result.detail());
    }

    /**
     * A record published as several character-strings arrives with the strings separated by a space, and its value is
     * their concatenation.
     */
    @Test
    void acceptsAKeyAuthorizationPublishedAsSeveralCharacterStrings() {
        String splitAcrossStrings = EXPECTED_KEY_AUTHORIZATION.substring(0, 20) + " "
                + EXPECTED_KEY_AUTHORIZATION.substring(20);

        ChallengeValidationResult result = AcmeDnsChallengeValidator
                .evaluate(RECORD_NAME, List.of(splitAcrossStrings), EXPECTED_KEY_AUTHORIZATION);

        Assertions.assertTrue(result.valid());
    }

    @Test
    void rejectsAnUnrelatedRecordThatContainsSpaces() {
        ChallengeValidationResult result = AcmeDnsChallengeValidator
                .evaluate(RECORD_NAME, List.of("v=spf1 include:_spf.example.com ~all"), EXPECTED_KEY_AUTHORIZATION);

        Assertions.assertFalse(result.valid());
        Assertions.assertEquals(Problem.INCORRECT_RESPONSE, result.problem());
    }

    @Test
    void reportsDnsProblemWhenNoRecordIsPublished() {
        ChallengeValidationResult result = AcmeDnsChallengeValidator
                .evaluate(RECORD_NAME, List.of(), EXPECTED_KEY_AUTHORIZATION);

        Assertions.assertFalse(result.valid());
        Assertions.assertEquals(Problem.DNS, result.problem());
        Assertions.assertTrue(result.detail().contains(RECORD_NAME));
    }

    @Test
    void reportsIncorrectResponseWhenPublishedRecordsDoNotMatch() {
        ChallengeValidationResult result = AcmeDnsChallengeValidator
                .evaluate(RECORD_NAME, List.of(STALE_KEY_AUTHORIZATION), EXPECTED_KEY_AUTHORIZATION);

        Assertions.assertFalse(result.valid());
        Assertions.assertEquals(Problem.INCORRECT_RESPONSE, result.problem());
        Assertions.assertTrue(result.detail().contains(RECORD_NAME));
    }

    /**
     * The published records may hold verification tokens owned by third parties, so they must never reach the client
     * through the challenge error.
     */
    @Test
    void keepsPublishedRecordValuesOutOfTheReportedDetail() {
        ChallengeValidationResult result = AcmeDnsChallengeValidator
                .evaluate(RECORD_NAME, List.of(STALE_KEY_AUTHORIZATION), EXPECTED_KEY_AUTHORIZATION);

        Assertions.assertFalse(result.detail().contains(STALE_KEY_AUTHORIZATION));
        Assertions.assertFalse(result.detail().contains(EXPECTED_KEY_AUTHORIZATION));
    }

    @Test
    void prefixesTheIdentifierWithTheChallengeLabel() {
        Assertions.assertEquals(RECORD_NAME, AcmeDnsChallengeValidator.challengeRecordName(IDENTIFIER));
    }

    /**
     * A wildcard identifier is validated at the challenge label of its base domain (RFC 8555 section 8.4).
     */
    @Test
    void resolvesAWildcardIdentifierAgainstItsBaseDomain() {
        Assertions
                .assertEquals(AcmeConstants.DNS_ACME_PREFIX + "example.org",
                        AcmeDnsChallengeValidator.challengeRecordName("*.example.org"));
    }

    @Test
    void usesTheSystemResolverWhenTheProfileDeclaresNone() {
        Assertions
                .assertEquals(AcmeConstants.DNS_ENV_PREFIX,
                        AcmeDnsChallengeValidator.resolverEnv(null, null).getProperty(Context.PROVIDER_URL));
        Assertions
                .assertEquals(AcmeConstants.DNS_ENV_PREFIX,
                        AcmeDnsChallengeValidator.resolverEnv("", "5353").getProperty(Context.PROVIDER_URL));
    }

    @Test
    void usesTheResolverDeclaredByTheProfile() {
        Assertions
                .assertEquals("dns://10.0.0.53:5353",
                        AcmeDnsChallengeValidator.resolverEnv("10.0.0.53", "5353").getProperty(Context.PROVIDER_URL));
    }

    @Test
    void fallsBackToTheDefaultPortWhenTheProfileDeclaresNone() {
        Assertions
                .assertEquals("dns://10.0.0.53:" + AcmeConstants.DEFAULT_DNS_PORT,
                        AcmeDnsChallengeValidator.resolverEnv("10.0.0.53", null).getProperty(Context.PROVIDER_URL));
    }

    @Test
    void reportsDnsProblemWhenTheResolverCannotBeReached() {
        ChallengeValidationResult result = AcmeDnsChallengeValidator
                .validate(RECORD_NAME, EXPECTED_KEY_AUTHORIZATION, unreachableResolverEnv());

        Assertions.assertFalse(result.valid());
        Assertions.assertEquals(Problem.DNS, result.problem());
        Assertions.assertTrue(result.detail().contains(RECORD_NAME));
    }

    private static Attributes txtAttributes(String... values) {
        BasicAttribute txtRecords = new BasicAttribute(AcmeConstants.DNS_RECORD_TYPE);
        for (String value : values) {
            txtRecords.add(value);
        }
        Attributes attributes = new BasicAttributes(true);
        attributes.put(txtRecords);
        return attributes;
    }

    private static Properties unreachableResolverEnv() {
        Properties env = AcmeDnsChallengeValidator.resolverEnv("127.0.0.1", "1");
        env.setProperty("com.sun.jndi.dns.timeout.initial", "1");
        env.setProperty("com.sun.jndi.dns.timeout.retries", "0");
        return env;
    }

}
