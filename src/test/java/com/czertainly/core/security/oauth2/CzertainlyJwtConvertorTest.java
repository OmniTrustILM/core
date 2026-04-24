package com.czertainly.core.security.oauth2;

import com.czertainly.api.model.core.settings.authentication.OAuth2ProviderSettingsUpdateDto;
import com.czertainly.core.auth.oauth2.CzertainlyJwtAuthenticationConverter;
import com.czertainly.core.security.authn.CzertainlyAuthenticationException;
import com.czertainly.core.security.authn.CzertainlyAuthenticationToken;
import com.czertainly.core.service.SettingService;
import com.czertainly.core.util.BaseSpringBootTest;
import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.nimbusds.jose.JOSEException;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

class CzertainlyJwtConvertorTest extends BaseSpringBootTest {

    @DynamicPropertySource
    static void authServiceProperties(DynamicPropertyRegistry registry) {
        registry.add("auth-service.base-url", () -> "http://localhost:10009");
    }

    @Autowired
    SettingService settingService;

    @Autowired
    CzertainlyJwtAuthenticationConverter jwtAuthenticationConverter;

    WireMockServer authMockServer;

    OAuth2ProviderSettingsUpdateDto providerSettings;

    Jwt jwt;

    KeyPair keyPair;

    @BeforeEach
    void setUp() throws NoSuchAlgorithmException, JOSEException {

        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keyPair = generator.generateKeyPair();

        jwt = Jwt.withTokenValue(OAuth2TestUtil.createJwtTokenValue(keyPair.getPrivate(), 0, "http://issuer", "", "user")).header("alg", "HS256").claim("claim", "claim").issuer("http://issuer")
                .build();
        providerSettings = new OAuth2ProviderSettingsUpdateDto();
        providerSettings.setIssuerUrl("http://issuer");
        providerSettings.setJwkSet("eyJrZXlzIjpbeyJraWQiOiJKbGRVNGJnb1AxT3B3V3k1N19GYV9mSlNoQUkwUFpDRjJpSkpzdmNsdkd3Iiwia3R5IjoiUlNBIiwiYWxnIjoiUlMyNTYiLCJ1c2UiOiJzaWciLCJuIjoiOGhEMU94NlBpRmczN1p2TlA1TUhkdHBUVmdyV3doLXMzTklfdmhncDhxc0dRdGhlc05TbWJ0bV9qWi1reTFwSkR4c2JfM1pldXo2MFZvQmRNRC1sNHVSQ3poSDJWb1VVVGx6THZUNllYWElTZHdGdXJVVWtHSS1UaC1Xdm5tajY0Y1BETGdDLXdqcmRuUGZnbGZZNXJZUTVzNzVRQmhrWE1Gci1TRmplX3pVRWxzcDlNT0VtbWFyQTZKUG5DVDJhWVc4X3NlaGV1ZEFxbTVOc0wtQnhhWXdnTHAxa2c4Z2ZwTm9RdHFBck51WDVzMk82djRybXMxX2poVC0xT19uWUVxVGxfenhmbVV2czBmT1F1N3MtWUM3Y2pESUl1cFlTYzIwbXBTWVZMN2JIQUpReElCTlVsZjI2aUdwa0Y0Q0Y0bFk3dFhsTmpaQ3lNZVl5MzluZ1J3IiwiZSI6IkFRQUIiLCJ4NWMiOlsiTUlJQ3J6Q0NBWmNDQmdHVVJ1RlFKakFOQmdrcWhraUc5dzBCQVFzRkFEQWJNUmt3RndZRFZRUUREQkJEV2tWU1ZFRkpUa3haTFhKbFlXeHRNQjRYRFRJMU1ERXdPREUzTURReE9Gb1hEVE0xTURFd09ERTNNRFUxT0Zvd0d6RVpNQmNHQTFVRUF3d1FRMXBGVWxSQlNVNU1XUzF5WldGc2JUQ0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQVBJUTlUc2VqNGhZTisyYnpUK1RCM2JhVTFZSzFzSWZyTnpTUDc0WUtmS3JCa0xZWHJEVXBtN1p2NDJmcE10YVNROGJHLzkyWHJzK3RGYUFYVEEvcGVMa1FzNFI5bGFGRkU1Y3k3MCttRjF5RW5jQmJxMUZKQmlQazRmbHI1NW8rdUhEd3k0QXZzSTYzWnozNEpYMk9hMkVPYk8rVUFZWkZ6QmEva2hZM3Y4MUJKYktmVERoSnBtcXdPaVQ1d2s5bW1GdlA3SG9Ycm5RS3B1VGJDL2djV21NSUM2ZFpJUElINlRhRUxhZ0t6YmwrYk5qdXIrSzVyTmY0NFUvdFR2NTJCS2s1Zjg4WDVsTDdOSHprTHU3UG1BdTNJd3lDTHFXRW5OdEpxVW1GUysyeHdDVU1TQVRWSlg5dW9ocVpCZUFoZUpXTzdWNVRZMlFzakhtTXQvWjRFY0NBd0VBQVRBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQVFFQWg3RHQxd3VFYWtVTDJNMkNma24yTEl6YllVUmxXTUVMZ1VhQld6NFNqUEFUMTZPWjkzL2dLTDJBOUxTTS9BSlUxUEZ0WlVHbS9XQk1ERU94cElSaFovdFFYT01zSW5YSlpnamtiUDRuSi9sNWFWNTNQSFpNN0VNbktWbmVZVkp5K1JmSE12Qi9zUXRtOWVwQ3QwdGNLNFVRT0htZ3A5SWFYMTlUaFJsQkF6TkFGakRxV3pTcVNJK20zZFlwbXBuSzI5KzZySStRcGJLTE1SVWZ6VFkvbkRCb05Bam84NmE0MW1PWlYvQUVFWXhmWDZScDBhTExuU1h6QTAwcHRiQ2g0QmRucjJZWU9Kd1NiVkNpaVZnSjBNb0ppaHR4QzJSaHZiblMrZE9WM0wzazN3b0FBVnBwU1lqc0I0bXNoL1RVVUI2UFNXaFREa1o4aWZ5cXZkNWFaUT09Il0sIng1dCI6InhTb2dRV2FrMjlmQlh0Q1dPYjlLb1djc0UxRSIsIng1dCNTMjU2IjoidnVabkh1Q0NsYWZMUlZkVUZaY2NMTzB0YmRxcFhmWlZydzk5c2VCYmMxcyJ9LHsia2lkIjoibE5Bb0o4VGxRWE9NelRGN3oyTXpHZEZHOTI1YzktdUtaTlh3dXZQTG1HSSIsImt0eSI6IlJTQSIsImFsZyI6IlJTQS1PQUVQIiwidXNlIjoiZW5jIiwibiI6InVseVVMSVpqWXZqekg5RDV5dm1KYWdoU3pNaHJ4aFh3OThMNFpOOWx6TUE5UGxBR3NGVnZCeDdxcFhSZFBxWVRzdG8zRmtjRWR6bmhhSkNvNmZxSnlLVlUzWVJCTjhGN0NKemZiY1lFQ0gtMWhBVmYtUlV1OF9LdFZVeVBZd3N2Q3VUZk9jTU9Ga0huNmplWEc4cUpDZ3ZCS0hVT0ZuRFR3RTNXQVhkZWNwUGpJSkllTmpDVDdBeFp1d2o4dnZrVkNybkxmU2hQV3FYcW5QTFRMOTJhd3pqLXVVd0U4alhDczNFOVZ5TnJGYzBLOFhyVDF3WWVrdjM5cmJyZTR6YU1WcG5sV19jTmZPX2xGM2dsX2d3V2hvMXJvUS1MTHAtV2RzMEFsbllaVmxOR3pxRGFYZTFfNzJBOWQ0cllXNFBFZDhrUk5jejRXWHpfaUZJTV9KeklMdyIsImUiOiJBUUFCIiwieDVjIjpbIk1JSUNyekNDQVpjQ0JnR1VSdUZQMVRBTkJna3Foa2lHOXcwQkFRc0ZBREFiTVJrd0Z3WURWUVFEREJCRFdrVlNWRUZKVGt4WkxYSmxZV3h0TUI0WERUSTFNREV3T0RFM01EUXhPRm9YRFRNMU1ERXdPREUzTURVMU9Gb3dHekVaTUJjR0ExVUVBd3dRUTFwRlVsUkJTVTVNV1MxeVpXRnNiVENDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFMcGNsQ3lHWTJMNDh4L1ErY3I1aVdvSVVzeklhOFlWOFBmQytHVGZaY3pBUFQ1UUJyQlZid2NlNnFWMFhUNm1FN0xhTnhaSEJIYzU0V2lRcU9uNmljaWxWTjJFUVRmQmV3aWMzMjNHQkFoL3RZUUZYL2tWTHZQeXJWVk1qMk1MTHdyazN6bkREaFpCNStvM2x4dktpUW9Md1NoMURoWncwOEJOMWdGM1huS1Q0eUNTSGpZd2srd01XYnNJL0w3NUZRcTV5MzBvVDFxbDZwenkweS9kbXNNNC9ybE1CUEkxd3JOeFBWY2pheFhOQ3ZGNjA5Y0dIcEw5L2EyNjN1TTJqRmFaNVZ2M0RYenY1UmQ0SmY0TUZvYU5hNkVQaXk2ZmxuYk5BSloyR1ZaVFJzNmcybDN0Zis5Z1BYZUsyRnVEeEhmSkVUWE0rRmw4LzRoU0RQeWN5QzhDQXdFQUFUQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FRRUFvNDRocnU1VDdhMmlrUTZoRFRoQWRwd0diUVNGTWJMYjROUUlQZ3Z1U1JaMGM2d3ArQk1EaHU5NUhpck1wUVpwR0FmVi93bzJuL1FXNFBmaVB5QXN1VlRYSkM0cVZxdjJvcXY0bjlPWUJ3SWhkNU1KWUR4MkgxQ1JPTFQxV0plWWNGV2dBMFFzWTNOVjUvZGdETktXbjJ5TWFrM2EwR0lxaFBndXZmZDRhVGFmM1FUUTNyaXIxUU5BUXg5bW90M0xyQjhobjB0R000VE9BVlAwaGVVd3BlWDFWWDl0Zm55cis0NUtNU0FPdDRHbGUzSTJ0SGVCQWtBQ3pKa0Z1bE9uTFhMeHg4aTZoVFBFOEdYWmo4aVN1OFFTNWg4QWorZy8xTGFRVFBPSnE0bmthQU9lbnU4SlpKeHFSSjFOWlhSZGtUY1JkM2ViTTdXUFdwNU44bTNUekE9PSJdLCJ4NXQiOiJ2RU1MU2VtNDEtN1E1cW1nbXFmV0EtT1k0V0EiLCJ4NXQjUzI1NiI6ImQxQzdtVU1FUDdERHJuTmlFN0I3Mzc2VlBkeDQ5U1NzTUZGQTRhdHpldTgifV19");
        settingService.updateOAuth2ProviderSettings("provider", providerSettings);
        authMockServer = new WireMockServer(10009);
        authMockServer.start();
        WireMock.configureFor("localhost", authMockServer.port());

        authMockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/auth")).willReturn(
                WireMock.okJson("""        
                        {
                          "authenticated": true,
                          "data": {
                            "user": {
                              "username": "user2"
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
                        """)
        ));
    }


    @AfterEach
    void stopServer() {
        authMockServer.stop();
    }


    @Test
    void testJwtConverter() {
        Assertions.assertDoesNotThrow(() -> jwtAuthenticationConverter.convert(jwt));
    }

    @Test
    void testJwtConverterOnTokenWithoutUsername() throws JOSEException {
        Jwt jwtNoUsername = Jwt.withTokenValue(OAuth2TestUtil.createJwtTokenValue(keyPair.getPrivate(), 0, "http://issuer", "", null)).header("alg", "HS256").issuer("http://issuer")
                .claim("claim", "claim")
                .build();
        Exception exception = Assertions.assertThrows(CzertainlyAuthenticationException.class, () ->  jwtAuthenticationConverter.convert(jwtNoUsername));
        Assertions.assertTrue(exception.getMessage().contains("could not be retrieved"));
    }

    @Test
    void testAddingClaimsFromUserInfo() {
        providerSettings.setUserInfoUrl("http://localhost:" + authMockServer.port() + "/userinfo");
        settingService.updateOAuth2ProviderSettings("provider", providerSettings);

        authMockServer.stubFor(WireMock.get("/userinfo").willReturn(
                WireMock.aResponse().withStatus(200)
                        .withHeader("Content-Type", "application/json")
                        .withBody("""
                                {
                                "username": "userInfoUser",
                                "email": "mail@mail.com"
                                }
                                """)
        ));

        authMockServer.stubFor(WireMock.post(WireMock.urlPathMatching("/auth"))
                .withRequestBody(WireMock.containing("userInfoUser"))
                .willReturn(
                WireMock.okJson("""
                        {
                          "authenticated": true,
                          "data": {
                            "user": {
                              "username": "userInfoUser"
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
                        """)
        ));

        CzertainlyAuthenticationToken authenticationToken = (CzertainlyAuthenticationToken) jwtAuthenticationConverter.convert(jwt);
        Assertions.assertEquals("userInfoUser", authenticationToken.getPrincipal().getUsername());

        providerSettings.setUserInfoUrl(null);
        settingService.updateOAuth2ProviderSettings("provider", providerSettings);

        authenticationToken = (CzertainlyAuthenticationToken) jwtAuthenticationConverter.convert(jwt);
        Assertions.assertEquals("user2", authenticationToken.getPrincipal().getUsername());
    }

}

