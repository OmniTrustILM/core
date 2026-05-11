package com.czertainly.core.service;

import com.czertainly.api.exception.NotFoundException;
import com.czertainly.api.model.client.auth.UpdateUserRequestDto;
import com.czertainly.api.model.common.NameAndUuidDto;
import com.czertainly.api.model.core.auth.AuthResourceDto;
import com.czertainly.api.model.core.auth.UserDetailDto;
import com.czertainly.api.model.core.auth.UserProfileDetailDto;
import com.czertainly.api.model.core.logging.enums.AuthMethod;
import com.czertainly.core.auth.ContextRefreshListener;
import com.czertainly.core.model.auth.ResourceSyncRequestDto;
import com.czertainly.core.security.authn.CzertainlyAuthenticationToken;
import com.czertainly.core.security.authn.CzertainlyUserDetails;
import com.czertainly.core.security.authn.client.AuthenticationInfo;
import com.czertainly.core.util.AuthHelper;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.security.cert.CertificateException;
import java.util.List;

@SpringBootTest
class AuthServiceTest extends BaseSpringBootTest {

    private static final int AUTH_SERVICE_MOCK_PORT = 10001;

    @DynamicPropertySource
    static void authServiceProperties(DynamicPropertyRegistry registry) {
        registry.add("auth-service.base-url", () -> "http://localhost:" + AUTH_SERVICE_MOCK_PORT);
    }

    private WireMockServer mockServer;

    @Autowired
    private AuthService authService;

    @Autowired
    private ContextRefreshListener contextRefreshListener;

    @BeforeEach
    void setUp() {
        mockServer = new WireMockServer(AUTH_SERVICE_MOCK_PORT);
        mockServer.start();
        WireMock.configureFor("localhost", mockServer.port());

        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/resources")).willReturn(WireMock.okJson(getAuthResourcesMockResponse())));
        mockServer.stubFor(WireMock.get(WireMock.urlPathMatching("/auth/users/[^/]+")).willReturn(
                WireMock.okJson(getUserDetailMockResponse())));
        mockServer.stubFor(WireMock.put(WireMock.urlPathMatching("/auth/users/[^/]+")).willReturn(
                WireMock.okJson(getUserDetailMockResponse())));
    }

    @AfterEach
    void cleanup() {
        mockServer.stop();
    }

    @Test
    void testAuthResources() {
        List<AuthResourceDto> authResources = authService.getAuthResources();
        List<ResourceSyncRequestDto> resources = contextRefreshListener.getResources();

        Assertions.assertEquals(resources.size(), authResources.size());
    }

    @Test
    void testAuthProfile() {
        injectLocalhostUserProfileToContext();

        UserProfileDetailDto userProfileDto = authService.getAuthProfile();
        Assertions.assertEquals(4, userProfileDto.getPermissions().getAllowedListings().size());

        // allow also users through group object member permissions
        injectLocalhostUserProfileChangedToContext();
        userProfileDto = authService.getAuthProfile();
        Assertions.assertEquals(6, userProfileDto.getPermissions().getAllowedListings().size());

    }

    @Test
    void testUpdateAuthProfile() throws NotFoundException, CertificateException {
        UpdateUserRequestDto updateUserRequest = new UpdateUserRequestDto();
        updateUserRequest.setEmail("localhost@example.com");

        UserDetailDto userDetailDto = authService.updateUserProfile(updateUserRequest);

        injectLocalhostUserProfileToContext();
        NameAndUuidDto userId = AuthHelper.getUserIdentification();

        Assertions.assertEquals(userDetailDto.getUsername(), userId.getName());
    }

    private void injectLocalhostUserProfileToContext() {
        String userProfileData = """
                {
                    "user": {
                        "uuid": "616be97b-0bd0-434c-a582-2d4dee5d0b41",
                        "username": "localhost",
                        "description": "System user for localhost operations",
                        "groups": [],
                        "enabled": true,
                        "systemUser": true,
                        "createdAt": "2024-12-02T10:52:54.36424+00:00",
                        "updatedAt": "2024-12-02T10:52:54.364241+00:00"
                    },
                    "roles": [{
                            "uuid": "9db01d1f-fb62-4be8-b344-a852e82edf80",
                            "name": "localhost"
                        }
                    ],
                    "permissions": {
                        "allowAllResources": false,
                        "resources": [{
                                "name": "certificates",
                                "allowAllActions": false,
                                "actions": ["create", "detail"],
                                "objects": []
                            }, {
                                "name": "raProfiles",
                                "allowAllActions": false,
                                "actions": ["members"],
                                "objects": []
                            }, {
                                "name": "settings",
                                "allowAllActions": false,
                                "actions": ["detail", "list", "update"],
                                "objects": []
                            }, {
                                "name": "users",
                                "allowAllActions": false,
                                "actions": ["create", "update"],
                                "objects": []
                            }
                        ]
                    }
                }
                """;

        // inject other user profile
        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, "616be97b-0bd0-434c-a582-2d4dee5d0b41", "localhost", List.of(), userProfileData);
        SecurityContextHolder.getContext().setAuthentication(new CzertainlyAuthenticationToken(new CzertainlyUserDetails(info)));
    }

    private void injectLocalhostUserProfileChangedToContext() {
        String userProfileData = """
                {
                     "user": {
                         "uuid": "616be97b-0bd0-434c-a582-2d4dee5d0b41",
                         "username": "localhost",
                         "description": "System user for localhost operations",
                         "groups": [],
                         "enabled": true,
                         "systemUser": true,
                         "createdAt": "2024-12-02T10:52:54.36424+00:00",
                         "updatedAt": "2024-12-02T10:52:54.364241+00:00"
                     },
                     "roles": [{
                             "uuid": "9db01d1f-fb62-4be8-b344-a852e82edf80",
                             "name": "localhost"
                         }
                     ],
                     "permissions": {
                         "allowAllResources": false,
                         "resources": [{
                                 "name": "certificates",
                                 "allowAllActions": false,
                                 "actions": ["create", "detail"],
                                 "objects": []
                             }, {
                                 "name": "groups",
                                 "allowAllActions": false,
                                 "actions": ["create", "detail", "list"],
                                 "objects": [{
                                         "uuid": "1fa64e9a-1a34-4e87-a7dc-4ed55e3021a5",
                                         "name": "ABCDEF",
                                         "allow": [
                                             "members"
                                         ],
                                         "deny": []
                                     }
                                 ]
                             }, {
                                 "name": "raProfiles",
                                 "allowAllActions": false,
                                 "actions": ["members"],
                                 "objects": []
                             }, {
                                 "name": "settings",
                                 "allowAllActions": false,
                                 "actions": ["detail", "list", "update"],
                                 "objects": []
                             }, {
                                 "name": "users",
                                 "allowAllActions": false,
                                 "actions": ["create", "update"],
                                 "objects": []
                             }
                         ]
                     }
                }
                """;

        // inject other user profile
        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, "616be97b-0bd0-434c-a582-2d4dee5d0b41", "localhost", List.of(), userProfileData);
        SecurityContextHolder.getContext().setAuthentication(new CzertainlyAuthenticationToken(new CzertainlyUserDetails(info)));
    }

    private String getUserDetailMockResponse() {
        return """
                {
                  "uuid": "616be97b-0bd0-434c-a582-2d4dee5d0b41",
                  "username": "localhost",
                  "groups": [],
                  "enabled": true,
                  "systemUser": true,
                  "roles": [
                    {
                      "uuid": "9db01d1f-fb62-4be8-b344-a852e82edf80",
                      "name": "localhost",
                      "description": "System role with all permissions needed for localhost operations",
                      "email": null,
                      "systemRole": true,
                      "createdAt": "2024-12-02T10:52:54.186481+00:00",
                      "updatedAt": "2024-12-02T10:52:54.186505+00:00"
                    }
                  ],
                  "createdAt": "2024-12-02T10:52:54.36424+00:00",
                  "updatedAt": "2024-12-02T10:52:54.364241+00:00"
                }
                """;
    }

    private String getAuthResourcesMockResponse() {
        return """
                [
                    {
                        "uuid": "d6ab6d7d-3335-4304-8cb2-f73300c2d56c",
                        "name": "acmeAccounts",
                        "displayName": "Acme Accounts",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "370f1bba-7922-4353-b574-f4252221610c",
                        "name": "acmeProfiles",
                        "displayName": "Acme Profiles",
                        "listObjectsEndpoint": "/v1/acmeProfiles",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "bd172dc0-ac11-41b6-b519-391af4b7e6c7",
                        "name": "actions",
                        "displayName": "Actions",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "9327090a-4469-4584-abc9-8aecbac16059",
                        "name": "approvalProfiles",
                        "displayName": "Approval Profiles",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "7819f46c-bd01-4e81-ad7f-ec2a61d9ab67",
                        "name": "approvals",
                        "displayName": "Approvals",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "d83d6cda-d1cb-453a-983a-575589382c49",
                        "name": "attributes",
                        "displayName": "Attributes",
                        "listObjectsEndpoint": "/v1/attributes/custom",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "757dee6e-3d19-4446-9a9f-84912bad3d58",
                        "name": "auditLogs",
                        "displayName": "Audit Logs",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "2eed4057-d423-438a-bbb3-86695a80689c",
                        "name": "authorities",
                        "displayName": "Authorities",
                        "listObjectsEndpoint": "/v1/authorities",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "fdca1036-d1ff-43b2-9df5-291276421e4b",
                        "name": "certificates",
                        "displayName": "Certificates",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "3b95180f-ba9a-4544-8c46-621828f287b5",
                        "name": "cmpProfiles",
                        "displayName": "Cmp Profiles",
                        "listObjectsEndpoint": "/v1/cmpProfiles",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "8e34cec1-bfd4-424b-9e9d-b48dae426001",
                        "name": "complianceProfiles",
                        "displayName": "Compliance Profiles",
                        "listObjectsEndpoint": "/v1/complianceProfiles",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "0c7b1165-82a1-4ade-a348-b9e765612cd2",
                        "name": "connectors",
                        "displayName": "Connectors",
                        "listObjectsEndpoint": "/v1/connectors",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "a5138bd1-df1a-4d6e-b91d-81a3d8cbf629",
                        "name": "credentials",
                        "displayName": "Credentials",
                        "listObjectsEndpoint": "/v1/credentials",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "2a44538f-b607-48cf-ba2a-e8d2b5f71402",
                        "name": "discoveries",
                        "displayName": "Discoveries",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "90bcb780-1b6a-4225-bb1d-c1bc27ee4239",
                        "name": "entities",
                        "displayName": "Entities",
                        "listObjectsEndpoint": "/v1/entities/list",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "31010bed-3f9f-423e-abee-b4fadad2550d",
                        "name": "groups",
                        "displayName": "Groups",
                        "listObjectsEndpoint": "/v1/groups",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "74c4cfb9-6dec-4384-89e9-0a40806102e1",
                        "name": "jobs",
                        "displayName": "Jobs",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "4f376c97-64ac-4b64-87f4-8474e8f4e409",
                        "name": "keys",
                        "displayName": "Keys",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "4478e340-e1f2-4c70-b1d0-56fc4a624e34",
                        "name": "locations",
                        "displayName": "Locations",
                        "listObjectsEndpoint": "/v1/locations",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "185944d8-e84d-4d0d-84f4-e79b8c3e21aa",
                        "name": "notificationInstances",
                        "displayName": "Notification Instances",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "21fb8c77-328a-4d58-82bb-df092affb93f",
                        "name": "notificationProfiles",
                        "displayName": "Notification Profiles",
                        "objectAccess": false,
                        "actions": [
                          {
                            "uuid": "df199f09-142b-4256-be1a-3140727a6c39",
                            "name": "list",
                            "displayName": "List"
                          }
                        ]
                    },
                    {
                        "uuid": "23c08ec0-ec49-4253-a69c-f7fd3296363a",
                        "name": "raProfiles",
                        "displayName": "Ra Profiles",
                        "listObjectsEndpoint": "/v1/raProfiles",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "38274315-71f5-43dc-8a92-84b06e9bc3d1",
                        "name": "roles",
                        "displayName": "Roles",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "8774a52e-add4-4b5c-947c-5f64d175635b",
                        "name": "rules",
                        "displayName": "Rules",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "2418093b-213c-42a2-9374-849a6c047038",
                        "name": "scepProfiles",
                        "displayName": "Scep Profiles",
                        "listObjectsEndpoint": "/v1/scepProfiles",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "acea2b03-682d-430c-8c6b-16a9358208ba",
                        "name": "settings",
                        "displayName": "Settings",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "a4b5a4f9-7fcf-4cbe-a184-5cf5f22f73ba",
                        "name": "tokenProfiles",
                        "displayName": "Token Profiles",
                        "listObjectsEndpoint": "/v1/tokenProfiles",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "e215e3d9-1c61-44ce-b7f8-25ca7bcd215b",
                        "name": "tokens",
                        "displayName": "Tokens",
                        "listObjectsEndpoint": "/v1/tokens",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "4154f38e-775b-4154-a41b-7cdae5fb76df",
                        "name": "triggers",
                        "displayName": "Triggers",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "232e32a1-6581-4a3f-a1e7-35720a49bc2f",
                        "name": "users",
                        "displayName": "Users",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                     {
                        "uuid": "bfea6df2-279e-4e18-94ec-26a167487ca5",
                        "name": "oids",
                        "displayName": "OIDs",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "df7604bb-1cfb-45cb-a948-e2faa78722c6",
                        "name": "proxies",
                        "displayName": "Proxies",
                        "listObjectsEndpoint": "/v1/proxies",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "f3f2f6e1-6c8b-4f7c-9a9b-4d6e9b5c3e2a",
                        "name": "trustedCertificates",
                        "displayName": "Trusted Certificates",
                        "listObjectsEndpoint": "/v1/trustedCertificates",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                     {
                        "uuid": "84388678-2bc8-422d-b374-fdbc3cc91115",
                        "name": "cboms",
                        "displayName": "CBOMs",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "b31b0ea1-d97f-4ade-895c-a982f4544e1b",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "d1c8e5b4-9c3a-4c8e-9b0c-1f2a5e6f7890",
                        "name": "vaults",
                        "displayName": "Vaults",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "b31b0ea1-d97f-4ade-895c-a982f4544e1b",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "d1c8e5b4-9c3a-4c8e-9b0c-1f2a5e6f7891",
                        "name": "vaultProfiles",
                        "displayName": "Vault Profiles",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "b31b0ea1-d97f-4ade-895c-a982f4544e1b",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "d1c8e5b4-9c3a-4c8e-9b0c-1f2a5e6f7892",
                        "name": "secrets",
                        "displayName": "Secrets",
                        "objectAccess": true,
                        "actions": [
                            {
                                "uuid": "b31b0ea1-d97f-4ade-895c-a982f4544e1b",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    },
                    {
                        "uuid": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
                        "name": "timeQualityConfigurations",
                        "displayName": "Time Quality Configurations",
                        "objectAccess": false,
                        "actions": [
                            {
                                "uuid": "53421445-5d6e-4257-b59d-235aaf26e61e",
                                "name": "list",
                                "displayName": "List"
                            }
                        ]
                    }
                ]
                """;
    }

}
