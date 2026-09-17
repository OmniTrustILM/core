package com.otilm.core.util.builders;

import com.otilm.api.model.common.enums.cryptography.KeyAlgorithm;
import com.otilm.api.model.common.enums.cryptography.KeyFormat;
import com.otilm.api.model.common.enums.cryptography.KeyType;
import com.otilm.api.model.core.compliance.ComplianceStatus;
import com.otilm.api.model.core.cryptography.key.KeyState;
import com.otilm.api.model.core.cryptography.key.KeyUsage;
import com.otilm.core.model.crypto.CryptographicKeyItemBasicModel;
import com.otilm.core.model.crypto.RemoteKeyReference;
import java.util.List;
import java.util.UUID;

public class CryptographicKeyItemBasicModelBuilder {

    private RemoteKeyReference reference = new RemoteKeyReference.UuidReference(UUID.randomUUID());
    private List<KeyUsage> usages = List.of(KeyUsage.SIGN);
    private ComplianceStatus complianceStatus = ComplianceStatus.OK;
    private String keyData;
    private KeyFormat format = KeyFormat.PRKI;

    public static CryptographicKeyItemBasicModelBuilder aKeyItemSnapshot() {
        return new CryptographicKeyItemBasicModelBuilder();
    }

    public CryptographicKeyItemBasicModelBuilder withReference(RemoteKeyReference reference) {
        this.reference = reference;
        return this;
    }

    public CryptographicKeyItemBasicModelBuilder withUsages(List<KeyUsage> usages) {
        this.usages = usages;
        return this;
    }

    public CryptographicKeyItemBasicModelBuilder withComplianceStatus(ComplianceStatus complianceStatus) {
        this.complianceStatus = complianceStatus;
        return this;
    }

    public CryptographicKeyItemBasicModel build() {
        return new CryptographicKeyItemBasicModel(UUID.randomUUID(), UUID.randomUUID(), "signing-key", reference,
                KeyType.PRIVATE_KEY, KeyAlgorithm.RSA, format, keyData, 2048, KeyState.ACTIVE, true, usages, null,
                complianceStatus);
    }

    public CryptographicKeyItemBasicModelBuilder withKeyData(String keyData) {
        this.keyData = keyData;
        return this;
    }

    public CryptographicKeyItemBasicModelBuilder withFormat(KeyFormat format) {
        this.format = format;
        return this;
    }
}
