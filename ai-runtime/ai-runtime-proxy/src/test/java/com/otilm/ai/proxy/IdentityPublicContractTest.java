package com.otilm.ai.proxy;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class IdentityPublicContractTest {
    @TempDir
    Path directory;

    @Test
    void missingCurrentKeyReturnsOnlyTheFixedIdentityFailure() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var c = fixture.configuration();
            Files.delete(c.privateKeyFile());
            var failure = assertThrows(GeneralSecurityException.class,
                    () -> IdentityFiles.load(c.certificateFile(), c.privateKeyFile(), c.serverCaFile()));
            assertEquals("IDENTITY_UNAVAILABLE", failure.getMessage());
            assertNull(failure.getCause());
        }
    }

    @Test
    void invalidPublicPathsReturnTheFixedFailureEvenWhenTheIdentityFilesExist() throws Exception {
        try (var fixture = new LocalTlsFixture(directory)) {
            var c = fixture.configuration();
            Path certificate = c.certificateFile(), key = c.privateKeyFile(), ca = c.serverCaFile();
            Path working = Path.of("").toAbsolutePath();
            for (Path[] paths : new Path[][]{
                    {null, key, ca},
                    {certificate, null, ca},
                    {certificate, key, null},
                    {Path.of("tls.crt"), key, ca},
                    {certificate, Path.of("tls.key"), ca},
                    {certificate, key, Path.of("ca.pem")},
                    {Path.of("/"), key, ca},
                    {certificate, Path.of("/"), ca},
                    {certificate, key, Path.of("/")},
                    {working.relativize(certificate), working.relativize(key), working.relativize(ca)},
                    {certificate, Path.of("/other/tls.key"), ca}}) {
                var failure = assertThrows(GeneralSecurityException.class,
                        () -> IdentityFiles.load(paths[0], paths[1], paths[2]));
                assertEquals("IDENTITY_UNAVAILABLE", failure.getMessage());
                assertNull(failure.getCause());
            }
        }
    }
}
