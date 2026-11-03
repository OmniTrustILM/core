package com.otilm.core.security.authn.client;

import org.springframework.stereotype.Component;

/**
 * Secondary index of the certificate fingerprints cached for each user. A user holds more than one while a lookup with
 * a replaced certificate is still finishing.
 */
@Component
public class UserCertificateIndex extends UserKeyIndex {
}
