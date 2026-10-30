package com.otilm.core.model.crypto;

import com.otilm.core.model.NamedModel;
import com.otilm.core.model.group.GroupModel;
import java.util.Set;
import java.util.UUID;

/** Key-wrapper state with group snapshots, without loading the profile or token instance. */
public interface CryptographicKeyBasicModel extends NamedModel {

    String description();

    UUID tokenProfileUuid();

    UUID tokenInstanceReferenceUuid();

    Set<GroupModel> groups();
}
