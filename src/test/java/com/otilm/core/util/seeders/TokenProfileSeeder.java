package com.otilm.core.util.seeders;

import com.otilm.api.model.client.connector.v2.ConnectorInterface;
import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.client.connector.v2.FeatureFlag;
import com.otilm.api.model.client.cryptography.key.KeyRequestType;
import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.api.model.core.connector.ConnectorStatus;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.ConnectorInterfaceRepository;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import com.otilm.core.model.crypto.TransferableKeyType;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static com.otilm.core.util.builders.ConnectorBuilder.aConnector;

/**
 * Seeds the V2 connector, token instance and token profile chain that every persisted key hangs from; the token is
 * connected and the profile enabled.
 */
@Component
public class TokenProfileSeeder {

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private ConnectorInterfaceRepository connectorInterfaceRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    public TokenProfile seedTokenProfile() {
        String uniqueUrl = "http://provider-" + UUID.randomUUID() + ".test";
        Connector connector = connectorRepository
                .saveAndFlush(
                        aConnector().withGeneratedUuid().withVersion(ConnectorVersion.V2).withUrl(uniqueUrl).build());

        TokenInstanceReference tokenInstance = new TokenInstanceReference();
        tokenInstance.setName("test-token");
        tokenInstance.setTokenInstanceUuid(UUID.randomUUID().toString());
        tokenInstance.setConnector(connector);
        tokenInstance.setStatus(TokenInstanceStatus.CONNECTED);
        tokenInstanceReferenceRepository.saveAndFlush(tokenInstance);

        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("test-profile");
        tokenProfile.setTokenInstanceReference(tokenInstance);
        tokenProfile.setTokenInstanceName(tokenInstance.getName());
        tokenProfile.setEnabled(true);
        return tokenProfileRepository.saveAndFlush(tokenProfile);
    }

    /**
     * Seeds a token profile on a v2 cryptography provider at the URL that declares key export, whose keys sign, and
     * whose connector has already answered that it exports key pairs of the algorithm.
     */
    public TokenProfile seedKeyExportingTokenProfile(String connectorUrl, KeyAlgorithm exportedAlgorithm) {
        Connector connector = aConnector()
                .withGeneratedUuid()
                .withVersion(ConnectorVersion.V2)
                .withUrl(connectorUrl)
                .build();
        connector.setStatus(ConnectorStatus.CONNECTED);
        connectorRepository.saveAndFlush(connector);
        ConnectorInterfaceEntity cryptography = new ConnectorInterfaceEntity();
        cryptography.setConnector(connector);
        cryptography.setConnectorUuid(connector.getUuid());
        cryptography.setInterfaceCode(ConnectorInterface.CRYPTOGRAPHY);
        cryptography.setVersion("v2");
        cryptography.setFeatures(List.of(FeatureFlag.STATELESS, FeatureFlag.KEY_EXPORT));
        connectorInterfaceRepository.saveAndFlush(cryptography);

        TokenInstanceReference tokenInstance = new TokenInstanceReference();
        tokenInstance.setName("exporting-token");
        tokenInstance.setConnector(connector);
        tokenInstance.setConnectorUuid(connector.getUuid());
        tokenInstance.setConnectorInterface(cryptography);
        tokenInstance.setKind("SOFT");
        tokenInstance.setStatus(TokenInstanceStatus.ACTIVATED);
        tokenInstanceReferenceRepository.saveAndFlush(tokenInstance);

        TokenProfile tokenProfile = new TokenProfile();
        tokenProfile.setName("exporting-profile");
        tokenProfile.setTokenInstanceReference(tokenInstance);
        tokenProfile.setTokenInstanceName(tokenInstance.getName());
        tokenProfile.setEnabled(true);
        tokenProfile.setUsage(List.of(KeyUsage.SIGN, KeyUsage.VERIFY));
        tokenProfile
                .setExportableKeyTypes(
                        List.of(new TransferableKeyType(KeyRequestType.KEY_PAIR, Set.of(exportedAlgorithm))));
        return tokenProfileRepository.saveAndFlush(tokenProfile);
    }
}
