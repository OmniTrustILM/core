package com.otilm.core.util;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import java.util.UUID;

/**
 * The auth-service WireMock stubs that impersonation needs: user detail lookup and a superadmin authentication
 * response. One place to update when the auth-service contract changes.
 */
public final class AuthServiceWireMockStubs {

    private AuthServiceWireMockStubs() {
    }

    public static void stubImpersonation(WireMockServer mockServer, UUID userUuid, String username) {
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users/[^/]+")).willReturn(WireMock.okJson("""
                {
                    "uuid": "%s",
                    "username": "%s",
                    "email": "testuser1@example.com",
                    "groups": [],
                    "roles": []
                }
                """.formatted(userUuid, username))));

        mockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/auth")).willReturn(WireMock.okJson("""
                {
                    "authenticated": true,
                    "data": {
                        "user": {
                            "uuid": "%s",
                            "username": "%s"
                        },
                        "roles": [
                            {
                                "name": "superadmin"
                            }
                        ],
                        "permissions": {
                            "allowAllResources": true,
                            "resources": []
                        }
                    }
                }
                """.formatted(userUuid, username))));
    }
}
