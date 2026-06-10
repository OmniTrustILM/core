package com.czertainly.core.service.scep;

import com.otilm.api.exception.*;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.czertainly.core.dao.entity.*;
import com.czertainly.core.dao.entity.scep.ScepProfile;
import com.czertainly.core.dao.repository.*;
import com.czertainly.core.dao.repository.scep.ScepProfileRepository;
import com.czertainly.core.service.scep.impl.ScepServiceImpl;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

class ScepServiceTest extends BaseSpringBootTest {

    @Autowired
    private ScepService scepService;

    @Autowired
    private ScepProfileRepository scepProfileRepository;

    @Autowired
    private CertificateContentRepository certificateContentRepository;

    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private AuthorityInstanceReferenceRepository authorityInstanceReferenceRepository;
    @Autowired
    private RaProfileRepository raProfileRepository;
    @Autowired
    private CertificateRepository certificateRepository;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    private RaProfile raProfile;
    private ScepProfile scepProfile;
    private Certificate certificate;

    @BeforeEach
    void setUp() {
        Connector connector = new Connector();
        connector.setUrl("http://localhost:3665");
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        AuthorityInstanceReference authorityInstance = new AuthorityInstanceReference();
        authorityInstance.setName("TestAuthority");
        authorityInstance.setConnector(connector);
        authorityInstance.setConnectorUuid(connector.getUuid());
        authorityInstance.setKind("sample");
        authorityInstance.setAuthorityInstanceUuid("1l");
        authorityInstance = authorityInstanceReferenceRepository.save(authorityInstance);

        raProfile = new RaProfile();
        raProfile.setName("TestRAProfile");
        raProfile.setAuthorityInstanceReference(authorityInstance);
        raProfileRepository.save(raProfile);

        CryptographicKey key = new CryptographicKey();
        key.setName("testKey1");
        key.setDescription("initial description");
        cryptographicKeyRepository.save(key);

        CryptographicKeyItem content = new CryptographicKeyItem();
        content.setLength(1024);
        content.setKey(key);
        content.setKeyUuid(key.getUuid());
        content.setType(KeyType.PRIVATE_KEY);
        content.setKeyData("some/encrypted/data");
        content.setFormat(KeyFormat.PRKI);
        content.setState(KeyState.ACTIVE);
        content.setEnabled(true);
        content.setKeyAlgorithm(KeyAlgorithm.RSA);
        content.setUsage(List.of(KeyUsage.DECRYPT, KeyUsage.SIGN));
        cryptographicKeyItemRepository.save(content);

        CryptographicKeyItem content1 = new CryptographicKeyItem();
        content1.setLength(1024);
        content1.setKey(key);
        content1.setKeyUuid(key.getUuid());
        content1.setType(KeyType.PUBLIC_KEY);
        content1.setKeyData("some/encrypted/data");
        content1.setFormat(KeyFormat.SPKI);
        content1.setState(KeyState.ACTIVE);
        content1.setEnabled(true);
        content1.setKeyAlgorithm(KeyAlgorithm.RSA);
        content1.setUsage(List.of(KeyUsage.ENCRYPT, KeyUsage.VERIFY));
        cryptographicKeyItemRepository.save(content1);

        content.setKeyReferenceUuid(content.getUuid());
        content1.setKeyReferenceUuid(content1.getUuid());
        cryptographicKeyItemRepository.save(content);
        cryptographicKeyItemRepository.save(content1);

        Set<CryptographicKeyItem> items = new HashSet<>();
        items.add(content1);
        items.add(content);
        key.setItems(items);
        cryptographicKeyRepository.save(key);

        CertificateContent certificateContent = new CertificateContent();
        certificateContent.setContent("MIIOaTCCBN2gAwIBAgIUYMDCBGsuMhyBlmH99mpLcOVcHEcwDQYLKwYBBAECggsHBAQwGjEYMBYGA1UEAwwPQ29uY3plcnQgU1VCIENBMB4XDTIzMTEyMTEyMDAwMVoXDTI0MDIxOTEyMDAwMFowHTEbMBkGA1UEAwwSQ29uY3plcnQgREVNTyB1c2VyMIIDujANBgsrBgEEAYGwGgUFAgOCA6cABIIDojEpAWK5BJq6dJLtxDhapKKnYC2tyMzgFWObi0OBXt48NkzW+uA31ST1BGt0NrvqICFxehqsCVaVHkSVxQkar/Cd+feD8HZJodPAF50BQQDH5srd5rZg4ZreZ7PfJ9ruAk0ZkRgrc1l9qKu2haau0gnutOL6tyTRmr9pgWA/QbyqCLua3for0yvKhZbHv0X2mO+NrX/C55M5VM+PIhzRmizDEdgHmFBZMnQYSqIO2snbV28ryY2+jNpxgdFTdzW6z3ce+gYCC1RYeLI7JeEHAMLuBd6z0khx0rGr1vmpOYFS701MXKWY1wAmVXi9Oe3nE6ztcInKOFTwJ8LyaOy/8ipb8HXi1UM+0woC0cnuY0JjFVEOumnZMyErfOLTCk4rj0QnwKLqf2tuq9xRtDGj5+jit3nAHAKMHO6b7uuqLb5McnUe7w2oufj2YBdVF62RPM58pGiS6hQ+Tko8Q7nIvBiA33mipKn+ex4WSFl9oEtHNhUACvvCMv+Pu85Y9Oxrz3ecUvCKIZ52iIcT7KPylRaYHngpz09MGP93kd8FD+1U2HpXDL/jm6f0tgplvXgIhRwXKFPNvLsxvX9nkiluBOvghVXAJdiqKjYFOcs12y8I3niSBzgkLrkv373plw/Z/SUFdatCWoVKqP/OzjaDePl0n7n5LaGI3gzp9rLnRKTMMHf0tQM01ctQiLQiyAsdpA0oRt+pOkhb2iR9K8Y5kH1sknOyRP3QYD4Pzc78dCu9UkEnHh+NmsqIVUz91UIIy69DzR12tWEZlIqr6AgooZmOD+ey8kMDR24HSo0Bhyvsac+UrZcGp9+y1BFCYSjq8CJyKwxDf314nkSptSw15aEBbNasp4knTvMDC9Wfwmu+YKWQysm+Rhd8IJtu8nqDBR0WdTu1V6OC2qQAf3IsFbEOTROOz+iz56ImlFAWbGIVbh5ItiRqJUB+b9MpgIgXZ0MlKPB/ZaDUsw7pn72jxWgZvvfW+MMSAle2yx9hdLtJV6yTqFkayax6R+qhxBcKZilSDn1dutzXDr1/lfGt5n630KZBqttWKx4hLJa5aKXZ+DJWil0cYYovD6fqILrFY9YiVrMLS6mmsEYwaJyIp3+DNY4d4jHozkjVj0jXfv4Dstrj474C37TSaei4VeRDhgSZUtlxZ1BcAVFL//3Ad23G+x3qKLMncL7fAL2fUyBrN8p3y+c7Kg+wgzSjhN46HgQr9Te5aqjLHAvco5dQQ8WFA6OBlzCBlDAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFCcXGxGh0Oyyh3yt5pcLpmFXJ9/GMDQGA1UdJQQtMCsGCCsGAQUFBwMDBggrBgEFBQcDBAYKKwYBBAGCNwoDDAYJKoZIhvcvAQEFMB0GA1UdDgQWBBT1S87JPOfM38mcchmwoolfY6tBfjAOBgNVHQ8BAf8EBAMCBeAwDQYLKwYBBAECggsHBAQDggl1AM1Cdk2upQZTPWJF6YvsybaJUhNMWcS3pu3YfeAZY/xXDhdNsKTXUC35g9I6OI0ZipnREXGwmrhGwN2K66TyV7iCyHCaaPtZtK2tj7yePAMzhnXD2Z6tNyiftJlWuaz3uGjDxwHuCCEDsT4vLfcGWH46HBin8tGAAtyiBdOQ+IixPecEptnLJ2PPrVKU+58Gdrr1rU1dYJwpSM42MLAintvVgtmIahrLFeHwFGFUPYOL61q7ZsDaU7q31/wMGlJkpI7PhCrPlIwJHAqYUH5M0Q9hK13tvSaRlGvSISbL9PR/8uMbVwkQk2ZIKdFfELjNY/mWGY42PVI5dkZv0mYwUyZYrUo13B10decgHlsm3E6nfT16i6+J301TVaocU3Q05Np3wgyecNBsT/uet7w/9gz8kDuHgoNuBaz1qeJSLUAkFE+zzXLUxq9/omOUQ7zBMgGMXwfCQhAl/STwLtcFnxmiMWdV0cF2vMQU91mMIkKRQ60SbplSrJ1sObBvXL0LVSsKPkSqQO4xyBWiDO2jHc5t8Tw8vIiU8eoLU4Lxc5054e8X+Qlzz8DP2JOPGApoizi1nlmD8DsxmM8kpLMkqOCHJ54hybKGFXq84akMuJ99ug2XTqJ6OtPX3L01l9fcYO/bKDQXjjAxiQ+rg4Fqxt3sh+qTwl2DKbA17Bd3UDyeZx6OuP1ZIf5KVRQXuFAsYaN0vmSuDln0EHoG8pPtihgLO91x8Z+QsOxlRHistTRFmsCVkHuquwvEDAU3HUQZ3CeCRHdsTEuQrfbCLbi/4Xc2am6jq4/iU/hH95DWOoPkYEn3tYj3JdF2ltY1lxEHHRw4U4U6HwcnFG5XXIPHij6YFw0VIzejDfEidebWE/M0oIM/nFS5sGV90wsJl7vudWoLf4kDNQBR1oFthIBm95qfjolWpcSg7oCh6EkeRQwMQLaAqQQJoNfrtD56U0hEMc7UZ6w5/Ly/AdJ8rQxU+2Ycd6HHRMBxNS8xsBJzzuR93IYRc8h4R+oOn+QQmW/5H/LUE8Du7eLAJ+CCazbX/pinMkpbvKRCn7v0of/0whALueExnx84o4sK+rCMcExSAQaW4sVwPo0eUwZC96xkHiGUuVlHngPndzpISMMbyJyGj9o8sXbcNRbq9Gq5Rznw7ymJnh4yJe4Ah+eTAg53CP2UjHr+hLJI+Nho04YbtgFVPBCf5I4J3VsaOlU4GQbN38Y7yfE6x6T8tOiMM4fnQkIIfaQVI8UQ8X2JaVHg0gyACM/FE/puaHqUgVk3BEg2mq+f5uRtAO5a2mvW3Ul7uAyUitLAv2mtQMZUvLUPu7ogxgde/jh7zvCrfI6jkj8x/9r5bD6XB7hvXwzsohtjxiIK8+k/a7hdt+G3Rxo0qlxOBGaIEo/Dv9Duotlgr9c9H5rbcTVNMEsqYXPCnaFPqSojAWTu+w594Jixed7vAdg2Yiy4jL9YXGOStbQGk8vhZCSrkbx0xUqxzBmuzQEA/EcJEwwXVl1gKS8ZD1fUi7Qp+q0SIHOIFF70yOBeK1HQVpfP5IxydHRzfeGPMAvXRgoUJBhFJRZy72bWE+URceqHVfH6yLvlmqmpc663XUoEj+PbOEUDkayBk7Rbgmh/AWk5a4cJC2IJbkvgt4XMWspFkPImNMFaHuUVkLquM5tCShYTaEGmGsFD6ABo6+3M4Bj1bRmM6R58lvEDjCEtxUhR3X0wItzlhTwBJr+w6Ecj8UROXEpvTKWyzTOCJC8SlNW1UNCDUUoPKKdZIK8keedh8w3x4RXKu495+iTHq7lOmLjrME1+BzFlrRzeNxj9VxLHgWj9DZkHiGhDIDI3xj+rpDfvyWykLeD2WoXtUE9H0tYwvRQQdKFMiGaDPrXwX9xl///YUP+Bm2/rvj5clHTh400B/1Ihcuhafe9RWeMBewQ+nU5si21DBZfYbliqzPkQJ1tGGzpwjH5Bg9JhR8z/RFwFsFVWzwNY7bJHmrXqxNCPs22DZq1KWoR5346wC//0hhsvycOCc94sOUlGKIo9w7AYvbJggNBiKZDlf/FA4FK1KenVxq1dHSMxRnStWLmg3njJGwrLtdyBp4vvUsRW+JHVoV0wyNzf9mx8KWe2s9dC2g1n8TmS/nE2yDGO3RnQDccJ6EWS+SwFrTyvVeusw1AgRviRjDo5JqMAKv/Pz57mhf11HEA+MGtRBFD9lYnpVdGgH1of1TEKMdMEbY9gHFC8UoOvm3h64ticheQJlTpcZumxBTSdn6d72KxV7dV0LhQRfaZEgTTvEOcb4bqjUjxM3355Xtgb4IxJFdpQ8wJZfRJWKtXrZ2fcfhPrQ+bLeFX5X93OQpuFRNyt9IV3ng1EE0ZMKkSifB7FCYnLiymoLRXUd75KBglrFoJs/AiTOZw+qyRr46pXz40Qplg8oek5yN4V7/7V8aXGkAQvSLc0v5tL00tWHAhJn5zR8lgaUTYI8vsGWtXPTdfN2Su9lQxrczAfe6UmQQ15Ad1iBtsFxrlFQ1htXFQDNX5AtChgMevOTmPTWRVYn29eBg6nYS5B8p7lp/I5PJqXr4UlPp9ioxomjJNXJhw1thWf9yxWAj/9jTn4HtJyNRasMcWZkkEJfbH+ud13ekrdEMNdLfzVOt748VoDGo8KSE5zT7IkDJfJn+B9CHLkiqLbfYUiYM2RkPKGFLrSSBCxq+04rZF3fHZcsFFg5GZhI6dcc8kSmMFFFQyXyXGSoPmWmLF00vg1xUArv2RsTQm/EBx2VO62u2KQk857jupMe2ISsZgKpf5RU4A4ph7YxN5WALD4DNpdBe3tGQkWUgTstvRlmAWKhAoeKqzxyFncKy4uJuBip6VKF4TsfWi4E8UpwhFa09C9g8XGW7+U2N91nEXqqbclTnQUJbE7Cf2NwA9ybnXZ8dIE69N7VfnomsuW4YbzjWOcSY8lqJ78duqmUoCYWKnPzj97ncRshbM/nOfQyV6wpySBPJNsvgh7RwTh9ngV0J1Suo7rt+V3UDqZhre1+tJDNkj10DqYTdNIYdDpxXy22fqK7uBSJFMsBjoBzTmR91ahWDv4nu1f3Z+kOxvcLEhJbyGx+FFWuvtG7+Htcc5sNNaVFqnuWYFhyizZx3E6AiE1QEhdZ22FlcvOECE7PlJcbW50d5WxtczO0NMAPWaMsLW4wc3R5foGITqIi6Wzvb7J1dvv9PcAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMHSk4");
        certificateContent = certificateContentRepository.save(certificateContent);

        certificate = new Certificate();
        certificate.setSubjectDn("testCertificate");
        certificate.setIssuerDn("testCertificate");
        certificate.setSerialNumber("123456789");
        certificate.setCertificateContent(certificateContent);
        certificate.setCertificateContentId(certificateContent.getId());
        certificate.setState(CertificateState.ISSUED);
        certificate.setValidationStatus(CertificateValidationStatus.VALID);
        certificate.setKey(key);
        certificate = certificateRepository.save(certificate);

        scepProfile = new ScepProfile();
        scepProfile.setDescription("sample description");
        scepProfile.setName("sameName");
        scepProfile.setRequireManualApproval(false);
        scepProfile.setChallengePassword("test123");
        scepProfile.setIncludeCaCertificate(true);
        scepProfile.setEnabled(true);
        scepProfile.setCaCertificate(certificate);
        scepProfile.setRaProfile(raProfile);
        scepProfileRepository.save(scepProfile);
    }

    @Test
    void testScepProfileValidity() {
        Assertions.assertThrows(ScepException.class, () -> scepService.handleGet("NotExistingScepProfile", ScepServiceImpl.SCEP_OPERATION_GET_CA_CERT, null), "SCEP profile should be existing");

        ScepProfile tempProfile = new ScepProfile();
        tempProfile.setName("TestScep");
        tempProfile.setRequireManualApproval(false);
        tempProfile.setChallengePassword("test123");
        scepProfileRepository.save(tempProfile);

        Assertions.assertThrows(ScepException.class, () -> scepService.handleGet(scepProfile.getName(), ScepServiceImpl.SCEP_OPERATION_GET_CA_CERT, null), "SCEP profile should be enabled");

        tempProfile.setEnabled(true);
        scepProfileRepository.save(tempProfile);
        var message = "testScepMessage".getBytes();
        Assertions.assertThrows(ScepException.class, () -> scepService.handlePost(scepProfile.getName(), ScepServiceImpl.SCEP_OPERATION_GET_CA_CERT, message), "SCEP profile should have CA certificate");

        CertificateContent certificateContent2 = new CertificateContent();
        certificateContent2.setContent("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");
        certificateContent2.setFingerprint("23r2r23r");
        certificateContent2 = certificateContentRepository.save(certificateContent2);

        Certificate certificateBad = new Certificate();
        certificateBad.setSubjectDn("testCertificateBad");
        certificateBad.setIssuerDn("testCertificateBad");
        certificateBad.setSerialNumber("1234567890");
        certificateBad.setCertificateContent(certificateContent2);
        certificateBad.setCertificateContentId(certificateContent2.getId());
        certificateBad.setState(CertificateState.ISSUED);
        certificateBad.setValidationStatus(CertificateValidationStatus.VALID);
        certificateBad.setFingerprint("23r2r23r");
        certificateBad = certificateRepository.save(certificateBad);

        tempProfile.setCaCertificate(certificateBad);
        scepProfileRepository.save(tempProfile);
        Assertions.assertThrows(ScepException.class, () -> scepService.handlePost(scepProfile.getName(), ScepServiceImpl.SCEP_OPERATION_GET_CA_CERT, message), "SCEP profile should have eligible CA certificate");

        tempProfile.setCaCertificate(certificate);
        scepProfileRepository.save(tempProfile);
        Assertions.assertThrows(ScepException.class, () -> scepService.handlePost(scepProfile.getName(), ScepServiceImpl.SCEP_OPERATION_GET_CA_CERT, message), "SCEP profile should have RA profile");

        tempProfile.setRaProfile(raProfile);
        scepProfileRepository.save(tempProfile);
        Assertions.assertThrows(ScepException.class, () -> scepService.handlePost(scepProfile.getName(), ScepServiceImpl.SCEP_OPERATION_GET_CA_CERT, message), "SCEP profile should have enabled RA profile");

        raProfile.setEnabled(true);
        raProfileRepository.save(raProfile);
    }

    @Test
    void testScepService() {
        raProfile.setEnabled(true);
        raProfileRepository.save(raProfile);

        var message = "testScepMessage".getBytes();
        Assertions.assertDoesNotThrow(() -> scepService.handlePost(scepProfile.getName(), ScepServiceImpl.SCEP_OPERATION_GET_CA_CERT, message));
        Assertions.assertDoesNotThrow(() -> scepService.handlePost(scepProfile.getName(), ScepServiceImpl.SCEP_OPERATION_GET_CA_CAPS, message));

        Assertions.assertThrows(ScepException.class, () -> scepService.handleGet(scepProfile.getName(), ScepServiceImpl.SCEP_OPERATION_PKI_OPERATION, "Wrong message"));
    }


}
