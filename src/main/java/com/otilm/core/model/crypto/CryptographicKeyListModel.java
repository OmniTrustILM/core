package com.otilm.core.model.crypto;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/** Key summary without certificate details or the token's provider and profile graph. */
public interface CryptographicKeyListModel extends CryptographicKeyBasicModel {

    String tokenProfileName();

    String tokenInstanceName();

    OffsetDateTime created();

    UUID ownerUuid();

    String ownerName();

    List<CryptographicKeyItemBasicModel> items();

    int associationCount();
}
