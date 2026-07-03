package com.otilm.core.service.scep;

import com.otilm.api.clients.cryptography.CryptographicOperationsApiClient;
import com.otilm.api.model.client.attribute.RequestAttribute;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.core.dao.entity.*;
import com.otilm.core.dao.repository.*;
import com.otilm.core.provider.PlatformCipherService;
import com.otilm.core.provider.PlatformProvider;
import com.otilm.core.provider.key.PlatformPrivateKey;
import com.otilm.core.service.CryptographicKeyExternalService;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.annotation.Rollback;
import org.springframework.transaction.annotation.Transactional;
import org.testcontainers.shaded.org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.util.*;

@SpringBootTest
@Transactional
@Rollback
class CryptographicProviderTest {
    @Autowired
    CryptographicOperationsApiClient cryptographicOperationsApiClient;

    @Autowired
    private CryptographicKeyExternalService cryptographicKeyService;
    @Autowired
    private CryptographicKeyRepository cryptographicKeyRepository;
    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;
    @Autowired
    private ConnectorRepository connectorRepository;
    @Autowired
    private TokenProfileRepository tokenProfileRepository;
    @Autowired
    private CryptographicKeyItemRepository cryptographicKeyItemRepository;

    private TokenInstanceReference tokenInstanceReference;
    private CryptographicKeyItem content;
    private CryptographicKeyItem content1;
    private TokenProfile tokenProfile;
    private Connector connector;
    private CryptographicKey key;
    private WireMockServer mockServer;

    @BeforeEach
    public void setUp() {
        mockServer = new WireMockServer(0);
        mockServer.start();

        WireMock.configureFor("localhost", mockServer.port());

        connector = new Connector();
        connector.setUrl("http://localhost:"+mockServer.port());
        connector.setVersion(ConnectorVersion.V1);
        connector.setStatus(ConnectorStatus.CONNECTED);
        connector = connectorRepository.save(connector);

        tokenInstanceReference = new TokenInstanceReference();
        tokenInstanceReference.setTokenInstanceUuid("1l");
        tokenInstanceReference.setConnector(connector);
        tokenInstanceReferenceRepository.save(tokenInstanceReference);

        tokenProfile = new TokenProfile();
        tokenProfile.setName("profile1");
        tokenProfile.setTokenInstanceReference(tokenInstanceReference);
        tokenProfile.setDescription("sample description");
        tokenProfile.setEnabled(true);
        tokenProfile.setTokenInstanceName("testInstance");
        tokenProfileRepository.save(tokenProfile);

        key = new CryptographicKey();
        key.setName("testKey");
        key.setTokenProfile(tokenProfile);
        key.setTokenInstanceReference(tokenInstanceReference);
        key.setDescription("initial description");
        cryptographicKeyRepository.save(key);

        content = new CryptographicKeyItem();
        content.setLength(1024);
        content.setKey(key);
        content.setKeyUuid(key.getUuid());
        content.setType(KeyType.PRIVATE_KEY);
        content.setKeyData("some/encrypted/data");
        content.setFormat(KeyFormat.PRKI);
        content.setState(KeyState.ACTIVE);
        content.setEnabled(true);
        content.setKeyAlgorithm(KeyAlgorithm.RSA);
        cryptographicKeyItemRepository.save(content);

        content1 = new CryptographicKeyItem();
        content1.setLength(1024);
        content1.setKey(key);
        content1.setKeyUuid(key.getUuid());
        content1.setType(KeyType.PUBLIC_KEY);
        content1.setKeyData("some/encrypted/data");
        content1.setFormat(KeyFormat.SPKI);
        content1.setState(KeyState.ACTIVE);
        content1.setEnabled(true);
        content1.setKeyAlgorithm(KeyAlgorithm.RSA);
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
    }

    @AfterEach
    public void tearDown() {
        mockServer.stop();
    }

    @Test
    void testCmsDecrypt() throws org.bouncycastle.cms.CMSException {
        String encapsulatedString = "MIIDwwYJKoZIhvcNAQcDoIIDtDCCA7ACAQAxgcgwgcUCAQAwLjAWMRQwEgYDVQQDDAtuZXdweXRoc3ViMQIUORJlivM+pu04Au0ztZaINDDKIPUwDQYJKoZIhvcNAQEBBQAEgYA/tWdX8NQMMkXosoIcvhToSGiyrSYKc+9inIQY0ByjpfJK2DH1V0Z6aJ5uwMMVePlAKU/DN++lilS9m79k75HQx8XOOjX8f+513fFAxJJN5c4PTeK/riT9r2pNBAlLnTicF7uEGIQmcQSW9SS7abf8Zfhi0/MQUNSZ+nWskGhCwDCCAt4GCSqGSIb3DQEHATAdBglghkgBZQMEAQIEENbWHLEpTF3gz1TSCMrD7PKAggKwgJTHwfQ9izDLz5j7Ao8ddQD7Hc1N28wGXj4Yf6MJSN533Pf9Yo4BMLCT3UiYkf5ocXeYkMyBsiAc5CSU5I09UkuCrBu8lC9HyLvcOtbiNwtnvMAnvIJgwtPOmQklmU9bmxWCmyiHn3V7ooA0I1ki5zF4NKNAZMOX8PgXvHpxEURsP1QTknA6cUk03NN94Ah9x7OZZZGJ1kFPmZDK3odhSrZqTA45gUd/p8R6MYa2VGVG6zzb7CUUbSuLhvPRK7aLD/PiHTJGDTmgHgWjcwg4RAYEwD7MMmXVrdAC2/b+XCVjJJBSWuD7yRJGksVdKboap9Px5WaywPjFJtdJ6SKlpSay8/qW8BXbogR+r8WFqKQLp9sktZ85bRzOuPpotNgB+4YHKU2u776qVLGF1pnwzT9WL0VfMFmlpWMTDPPMarxcobHc0y1shhBlankvu7CXoapvSCpJqvGnEmhRaz8vU+ciulKpnqGDG+b/GSkDeoPE64DZj+AnRzb193XElNJ38Q9hEzOt0896MrIT6lGrz/iIK28+GyId1TvkMDSHq1UCatuZDx7Cc0THz9FBCzkUajq1ZXHpCUwn/HL7wBg19MYvE0YfPlLbKA+dQBipCm8/pDQMYVYKB8Z9y+5pNyQhZCtUVyaIKvZ2//R1LvYJ+Fnn/T2r51m1eOhO8IObuPcTMVG6ykOCFQNBHOOTQAOMYx3EcIlfeS7JrhrWWKCRMXrI01btbhY+BmCr7wXtClFEM178Xzn0ZzokPqTexmPIe2fqqbNwVxYV9reGLM1+3R6ZaE+z3xjvNZTkQOAXVKFUtAenctD90N78ONm6lQrVXmTPZ+OmNVbM6nT6GCH2dSBgeuM8lX7PsnHW6ASbaS93yGnqvEKxj/UcRZR7vLNeLP4XceJxnlTTGHxpfTkJJQ==";

        byte[] cmsDataStream = Base64.getDecoder().decode(encapsulatedString);

        PlatformPrivateKey privateKey = new PlatformPrivateKey(tokenInstanceReference.getTokenInstanceUuid(), key.getUuid().toString(), connector.mapToDto(), "RSA");
        PlatformProvider provider = PlatformProvider.getInstance("Test", true, cryptographicOperationsApiClient);

        CMSEnvelopedData envelopedData = new CMSEnvelopedData(cmsDataStream);
        RecipientInformationStore recipientInfos = envelopedData.getRecipientInfos();
        Collection<RecipientInformation> recipients = recipientInfos.getRecipients();
        Iterator<RecipientInformation> recipientInformationIterator = recipients.iterator();

        if (recipientInformationIterator.hasNext()) {
            recipientInformationIterator.next();
            Assertions.assertDoesNotThrow(() -> new JceKeyTransEnvelopedRecipient(privateKey)
                    .setProvider(provider)
                    .setContentProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .setMustProduceEncodableUnwrappedKey(true)
                    .setAlgorithmMapping(new ASN1ObjectIdentifier("1.2.840.113549.1.1.1"), "RSA"));
        }
    }

    @Test
    void testMapCipherAttributesFromCipherAlgorithm() {
        PlatformCipherService cipherService = new PlatformCipherService(cryptographicOperationsApiClient, "RSA/NONE/OAEPWithSHA1AndMGF1Padding");
        List<RequestAttribute> attributes = cipherService.mapCipherAttributesFromCipherAlgorithm(cipherService.getAlgorithm());
        Assertions.assertFalse(attributes.isEmpty());
    }
}
