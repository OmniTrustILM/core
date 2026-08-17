package com.otilm.core.util.mocks;

import com.otilm.core.util.WireMockPorts;
import com.otilm.core.util.seeders.FunctionGroupSeeder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

/**
 * Spring-managed entry point for starting connector mocks. The mocks themselves are plain WireMock wrappers with a
 * per-test lifecycle (fresh server on the mock's fixed {@link WireMockPorts} port per start; callers stop them in
 * {@code @AfterEach}), so they cannot be Spring beans — this factory bridges the two worlds by injecting the beans a
 * mock needs at start. It is the only way to start a mock (constructors are package-private), which guarantees the
 * cryptography-provider mock always seeds its function-group reference data consistently with what it advertises.
 * <p>
 * The fixed port allows one mock of each kind at a time; a leaked one holds its port against every later test class.
 * Stop each in {@code @AfterEach} behind a null check, so an aborted setup still releases what it started.
 */
@Component
public class ConnectorMockFactory {

    @Autowired
    private FunctionGroupSeeder functionGroupSeeder;

    public CryptographyProviderConnectorMock startCryptographyProvider() {
        return new CryptographyProviderConnectorMock(functionGroupSeeder);
    }

    public ContentSigningFormattingMock startContentSigningFormatting() {
        return new ContentSigningFormattingMock(WireMockPorts.CONTENT_SIGNING_FORMATTING);
    }

    /** A second content-signing formatting mock, on {@link WireMockPorts#CONTENT_SIGNING_FORMATTING_SECONDARY}. */
    public ContentSigningFormattingMock startSecondContentSigningFormatting() {
        return new ContentSigningFormattingMock(WireMockPorts.CONTENT_SIGNING_FORMATTING_SECONDARY);
    }

    public TimestampingFormattingConnectorMock startTimestampingFormatting() {
        return new TimestampingFormattingConnectorMock();
    }

    public SignerConnectorMock startSigner() {
        return new SignerConnectorMock();
    }
}
