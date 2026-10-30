package com.otilm.core.model.crypto;

import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.model.NamedModel;
import java.util.List;
import java.util.UUID;

/** Token-profile state that does not require its token-instance association to be loaded. */
public interface TokenProfileBasicModel extends NamedModel {

    String description();

    String tokenInstanceName();

    UUID tokenInstanceReferenceUuid();

    Boolean enabled();

    List<KeyUsage> usages();
}
