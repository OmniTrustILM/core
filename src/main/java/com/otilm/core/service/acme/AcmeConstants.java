package com.otilm.core.service.acme;

import java.util.List;

public class AcmeConstants {

    public static final String LINK_HEADER_NAME = "Link";
    public static final String NONCE_HEADER_NAME = "Replay-Nonce";
    public static final String RETRY_HEADER_NAME = "Retry-After";
    public static final String RSA_KEY_TYPE_NOTATION = "RSA";
    public static final String EC_KEY_TYPE_NOTATION = "EC";
    public static final List<String> ACME_SUPPORTED_ALGORITHMS = List.of(RSA_KEY_TYPE_NOTATION, EC_KEY_TYPE_NOTATION);
    public static final Integer ACME_RSA_MINIMUM_KEY_LENGTH = 1024;
    public static final Integer ACME_EC_MINIMUM_KEY_LENGTH = 112;
    public static final String ACME_URI_HEADER = "/v1/protocols/acme";
    public static final Integer NONCE_VALIDITY = 60 * 60; //1 Hour
    public static final Integer MAX_REDIRECT_COUNT = 15;
    public static final String CERTIFICATE_TYPE = "X.509";
    public static final String MESSAGE_DIGEST_ALGORITHM = "SHA-256";
    public static final String DNS_RECORD_TYPE = "TXT";
    public static final String DNS_ACME_PREFIX = "_acme-challenge.";
    public static final String DEFAULT_DNS_PORT = "53";
    public static final String DNS_CONTENT_FACTORY = "com.sun.jndi.dns.DnsContextFactory";
    public static final String DNS_ENV_PREFIX = "dns://";
    public static final String HTTP_CHALLENGE_REQUEST_METHOD = "GET";
    public static final String LOCATION_HEADER_NAME = "Location";
    public static final String HTTP_CHALLENGE_BASE_URL = "http://%s/.well-known/acme-challenge/%s";

}
