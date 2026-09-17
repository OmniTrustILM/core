package com.otilm.core.model.crypto;

import java.util.UUID;

/** Token-profile state whose associated token instance and status are present. */
public interface TokenProfileFullModel extends TokenProfileBasicModel {

    TokenInstanceFullModel tokenInstance();

    UUID connectorUuid();
}
