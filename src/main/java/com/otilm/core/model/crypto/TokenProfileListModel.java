package com.otilm.core.model.crypto;

import com.otilm.api.model.connector.cryptography.enums.TokenInstanceStatus;

/** Token-profile summary with token status, without the token's provider and profile graph. */
public interface TokenProfileListModel extends TokenProfileBasicModel {

    TokenInstanceStatus tokenInstanceStatus();
}
