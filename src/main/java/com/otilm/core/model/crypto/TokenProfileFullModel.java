package com.otilm.core.model.crypto;

import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;
import java.util.UUID;

/** Token-profile state whose associated token instance and status are present. */
public interface TokenProfileFullModel extends TokenProfileBasicModel {

    TokenInstanceStatus tokenInstanceStatus();

    UUID connectorUuid();
}
