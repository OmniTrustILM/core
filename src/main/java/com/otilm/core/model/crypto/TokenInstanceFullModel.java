package com.otilm.core.model.crypto;

import com.otilm.core.model.connector.ImmutableConnectorInterface;
import java.util.Set;

public interface TokenInstanceFullModel extends TokenInstanceBasicModel {

    ImmutableConnectorInterface connectorInterface();

    Set<TokenProfileBasicModel> tokenProfiles();
}
