package com.otilm.core.model.crypto;

import java.time.OffsetDateTime;
import java.util.List;
import java.util.UUID;

/** Key-wrapper snapshot with the fields needed for API responses. */
public interface CryptographicKeyFullModel extends CryptographicKeyBasicModel {

    TokenProfileBasicModel tokenProfile();

    TokenInstanceFullModel tokenInstance();

    OffsetDateTime created();

    UUID ownerUuid();

    String ownerName();

    List<CryptographicKeyItemBasicModel> items();

    /** All certificate links; empty when there are none. */
    List<KeyCertificateAssociationModel> certificateAssociations();
}
