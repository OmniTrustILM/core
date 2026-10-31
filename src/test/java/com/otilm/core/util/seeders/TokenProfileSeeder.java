package com.otilm.core.util.seeders;

import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.TokenInstanceReference;
import com.otilm.core.dao.entity.TokenProfile;
import com.otilm.core.dao.repository.ConnectorRepository;
import com.otilm.core.dao.repository.TokenInstanceReferenceRepository;
import com.otilm.core.dao.repository.TokenProfileRepository;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import static com.otilm.core.util.builders.ConnectorBuilder.aConnector;

/**
 * Seeds the connector, token instance and token profile chain that every persisted key hangs from; the token is
 * connected and the profile enabled.
 */
@Component
public class TokenProfileSeeder {

    @Autowired
    private ConnectorRepository connectorRepository;

    @Autowired
    private TokenInstanceReferenceRepository tokenInstanceReferenceRepository;

    @Autowired
    private TokenProfileRepository tokenProfileRepository;

    public TokenProfile seedTokenProfile() {
        Connector connector = connectorRepository.saveAndFlush(aConnector().withGeneratedUuid().build());

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
}
