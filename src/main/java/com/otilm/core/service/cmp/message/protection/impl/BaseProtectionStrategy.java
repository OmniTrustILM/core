package com.otilm.core.service.cmp.message.protection.impl;

import com.otilm.core.service.cmp.configurations.ConfigurationContext;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;

public abstract class BaseProtectionStrategy {

    protected final ConfigurationContext configuration;
    protected final AlgorithmIdentifier headerProtectionAlgorithm;

    protected BaseProtectionStrategy(ConfigurationContext configuration, AlgorithmIdentifier headerProtectionAlgorithm) {
        this.configuration = configuration;
        this.headerProtectionAlgorithm = headerProtectionAlgorithm;
    }
}
