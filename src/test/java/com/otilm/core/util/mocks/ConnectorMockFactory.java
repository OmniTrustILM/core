package com.otilm.core.util.mocks;

import com.otilm.core.util.seeders.FunctionGroupSeeder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Spring-managed entry point for starting connector mocks. The mocks themselves are plain WireMock
 * wrappers with a per-test lifecycle (fresh server and random port per start; callers stop them in
 * {@code @AfterEach}), so they cannot be Spring beans — this factory bridges the two worlds by
 * injecting the beans a mock needs at start. It is the only way to start a mock (constructors are
 * package-private), which guarantees the cryptography-provider mock always seeds its function-group
 * reference data consistently with what it advertises.
 */
@Component
public class ConnectorMockFactory {

    @Autowired
    private FunctionGroupSeeder functionGroupSeeder;

    public CryptographyProviderConnectorMock startCryptographyProvider() {
        return new CryptographyProviderConnectorMock(functionGroupSeeder);
    }

    public ContentSigningFormatterMock startContentSigningFormatter() {
        return new ContentSigningFormatterMock();
    }

    public TimestampingFormatterConnectorMock startTimestampingFormatter() {
        return new TimestampingFormatterConnectorMock();
    }

    public SignerConnectorMock startSigner() {
        return new SignerConnectorMock();
    }
}
