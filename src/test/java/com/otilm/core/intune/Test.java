// Copyright (c) Microsoft Corporation.
// All rights reserved.
//
// This code is licensed under the MIT License.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files(the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and / or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions :
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

/*
This class was updated for the integration of the platform with the Intune server.
It is placed under the package `com.czertainly.core.intune` and further maintained by
the development team.

The important modification are marked with the comment "MODIFICATION"
*/

package com.otilm.core.intune;

import static org.junit.jupiter.api.Assertions.*;

import com.czertainly.core.intune.scepvalidation.*;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

import java.io.ByteArrayInputStream;
import java.net.URISyntaxException;
import java.net.UnknownHostException;
import java.util.UUID;

import javax.naming.ServiceUnavailableException;

import com.otilm.core.intune.scepvalidation.IntuneClientHttpErrorException;
import com.otilm.core.intune.scepvalidation.IntuneScepServiceClient;
import com.otilm.core.intune.scepvalidation.IntuneScepServiceException;
import com.otilm.core.intune.scepvalidation.IntuneServiceNotFoundException;
import org.apache.hc.client5.http.classic.methods.HttpUriRequest;
import org.mockito.ArgumentMatcher;
import org.mockito.ArgumentMatchers;

public class Test 
{
    @org.junit.jupiter.api.Test
    public void TestValidationSuccess() throws Exception
    {
        Helper helper = new Helper();
        
        IntuneScepServiceClient client = new IntuneScepServiceClient(helper.properties, helper.msal, helper.adal, helper.httpBuilder);
        
        UUID transactionId = UUID.randomUUID();
        String csr = "test";

        client.ValidateRequest(transactionId.toString(), csr);
        
        verify(helper.adal, times(0)).getAccessTokenFromCredential(anyString());
        verify(helper.msal, times(2)).getAccessToken(ArgumentMatchers.<String>anySet());
        
        verify(helper.httpClient, times(1)).execute(
                argThat(new ArgumentMatcher<HttpUriRequest>() {
                    @Override
                    public boolean matches(HttpUriRequest resp) {
                        try {
                            return resp.getUri().getHost().equals(Helper.MSAL_URL);
                        } catch (URISyntaxException e) {
                            return false;
                        }
                    }}));

        verify(helper.httpClient, times(1)).execute(
                argThat(new ArgumentMatcher<HttpUriRequest>() {
                    @Override
                    public boolean matches(HttpUriRequest resp) {
                        try {
                            return resp.getUri().getHost().equals(Helper.SERVICE_URL);
                        } catch (URISyntaxException e) {
                            return false;
                        }
                    }}));
    }

    @org.junit.jupiter.api.Test
    public void TestErrorThrows() throws IntuneScepServiceException, Exception
    {
        Helper helper = new Helper();
        
        when(helper.intuneResponseEntity.getContent())
            .thenReturn(new ByteArrayInputStream(Helper.ERROR_SCEP_RESPONSE.getBytes()));
        when(helper.intuneResponseEntity.getContentLength())
            .thenReturn((long)Helper.ERROR_SCEP_RESPONSE.length());
        
        IntuneScepServiceClient client = new IntuneScepServiceClient(helper.properties, helper.msal, helper.adal, helper.httpBuilder);
        
        UUID transactionId = UUID.randomUUID();
        String csr = "test";
        try 
        {
            client.ValidateRequest(transactionId.toString(), csr);
        }
        catch(IntuneScepServiceException e)
        {
            verify(helper.adal, times(0)).getAccessTokenFromCredential(anyString());
            verify(helper.msal, times(2)).getAccessToken(ArgumentMatchers.<String>anySet());
            
            verify(helper.httpClient, times(1)).execute(
                    argThat(new ArgumentMatcher<HttpUriRequest>() {
                        @Override
                        public boolean matches(HttpUriRequest resp) {
                            try {
                                return resp.getUri().getHost().equals(Helper.MSAL_URL);
                            } catch (URISyntaxException ex) {
                                return false;
                            }
                        }}));

            verify(helper.httpClient, times(1)).execute(
                    argThat(new ArgumentMatcher<HttpUriRequest>() {
                        @Override
                        public boolean matches(HttpUriRequest resp) {
                            try {
                                return resp.getUri().getHost().equals(Helper.SERVICE_URL);
                            } catch (URISyntaxException ex) {
                                return false;
                            }
                        }}));
            
            assertTrue(e.getParsedErrorCode() == IntuneScepServiceException.ErrorCode.ChallengeDecodingError);
            return;
        }
        
        assertNotNull(null);
    }
    
    @org.junit.jupiter.api.Test
    public void TestServiceRoleMismatchThrows() throws IntuneScepServiceException, Exception 
    {
        Helper helper = new Helper();
        
        when(helper.intuneResponse.getCode())
            .thenReturn(401);
        
        IntuneScepServiceClient client = new IntuneScepServiceClient(helper.properties, helper.msal, helper.adal, helper.httpBuilder);
        
        UUID transactionId = UUID.randomUUID();
        String csr = "test";
        try 
        {
            client.ValidateRequest(transactionId.toString(), csr);
        }
        catch(IntuneClientHttpErrorException e)
        {
            verify(helper.adal, times(0)).getAccessTokenFromCredential(anyString());
            verify(helper.msal, times(2)).getAccessToken(ArgumentMatchers.<String>anySet());
            
            verify(helper.httpClient, times(1)).execute(
                    argThat(new ArgumentMatcher<HttpUriRequest>() {
                        @Override
                        public boolean matches(HttpUriRequest resp) {
                            try {
                                return resp.getUri().getHost().equals(Helper.MSAL_URL);
                            } catch (URISyntaxException ex) {
                                return false;
                            }
                        }}));

            verify(helper.httpClient, times(1)).execute(
                    argThat(new ArgumentMatcher<HttpUriRequest>() {
                        @Override
                        public boolean matches(HttpUriRequest resp) {
                            try {
                                return resp.getUri().getHost().equals(Helper.SERVICE_URL);
                            } catch (URISyntaxException ex) {
                                return false;
                            }
                        }}));
            return;
        }
        
        assertNotNull(null);
    }
    
    @org.junit.jupiter.api.Test
    public void TestFailedToGetTokenThrows() throws IntuneScepServiceException, Exception 
    {
        Helper helper = new Helper();
        
        when(helper.adal.getAccessTokenFromCredential(anyString()))
            .thenThrow(new ServiceUnavailableException());
        when(helper.msal.getAccessToken(ArgumentMatchers.<String>anySet()))
            .thenThrow(new ServiceUnavailableException());
        
        IntuneScepServiceClient client = new IntuneScepServiceClient(helper.properties, helper.msal, helper.adal, helper.httpBuilder);
        
        UUID transactionId = UUID.randomUUID();
        String csr = "test";
        try 
        {
            client.ValidateRequest(transactionId.toString(), csr);
        }
        catch(ServiceUnavailableException e)
        {
            verify(helper.msal, times(1)).getAccessToken(ArgumentMatchers.<String>anySet());
            verify(helper.adal, times(1)).getAccessTokenFromCredential(anyString());
            
            verify(helper.httpClient, times(0)).execute(
                    argThat(new ArgumentMatcher<HttpUriRequest>() {
                        @Override
                        public boolean matches(HttpUriRequest resp) {
                            try {
                                return resp.getUri().getHost().equals(Helper.MSAL_URL);
                            } catch (URISyntaxException ex) {
                                return false;
                            }
                        }}));

            verify(helper.httpClient, times(0)).execute(
                    argThat(new ArgumentMatcher<HttpUriRequest>() {
                        @Override
                        public boolean matches(HttpUriRequest resp) {
                            try {
                                return resp.getUri().getHost().equals(Helper.SERVICE_URL);
                            } catch (URISyntaxException ex) {
                                return false;
                            }
                        }}));
            return;
        }
        
        assertNotNull(null);
    }
    
    @org.junit.jupiter.api.Test
    public void TestServiceEndpointNotFound() throws IntuneScepServiceException, Exception 
    {
        Helper helper = new Helper();
        
        when(helper.msal.getAccessToken(ArgumentMatchers.<String>anySet()))
            .thenThrow(new ServiceUnavailableException());
            
        when(helper.graphResponseEntity.getContent())
            .thenReturn(new ByteArrayInputStream(Helper.NO_SERVICE_DISCOVERY_RESPONSE.getBytes()));
        when(helper.graphResponseEntity.getContentLength())
            .thenReturn((long)Helper.NO_SERVICE_DISCOVERY_RESPONSE.length());
        
        IntuneScepServiceClient client = new IntuneScepServiceClient(helper.properties, helper.msal, helper.adal, helper.httpBuilder);
        
        UUID transactionId = UUID.randomUUID();
        String csr = "test";
        try 
        {
            client.ValidateRequest(transactionId.toString(), csr);
        }
        catch(IntuneServiceNotFoundException e)
        {
            verify(helper.msal, times(1)).getAccessToken(ArgumentMatchers.<String>anySet());
            verify(helper.adal, times(1)).getAccessTokenFromCredential(anyString());
            
            verify(helper.httpClient, times(1)).execute(
                    argThat(new ArgumentMatcher<HttpUriRequest>() {
                        @Override
                        public boolean matches(HttpUriRequest resp) {
                            try {
                                return resp.getUri().getHost().equals(Helper.GRAPH_URL);
                            } catch (URISyntaxException ex) {
                                return false;
                            }
                        }}));

            verify(helper.httpClient, times(0)).execute(
                    argThat(new ArgumentMatcher<HttpUriRequest>() {
                        @Override
                        public boolean matches(HttpUriRequest resp) {
                            try {
                                return resp.getUri().getHost().equals(Helper.SERVICE_URL);
                            } catch (URISyntaxException ex) {
                                return false;
                            }
                        }}));
            return;
        }
        
        assertNotNull(null);
    }
    
    @org.junit.jupiter.api.Test
    public void TestServiceMapClearMockito() throws IntuneScepServiceException, Exception
    {
        Helper helper = new Helper();

        when(helper.httpClient.execute(
                argThat(new ArgumentMatcher<HttpUriRequest>() {
                    @Override
                    public boolean matches(HttpUriRequest resp) {
                        if(resp == null)
                            return false;
                        try {
                            return resp.getUri().getHost().equals(Helper.SERVICE_URL);
                        } catch (URISyntaxException e) {
                            return false;
                        }
                    }})))
        .thenThrow(new UnknownHostException());
        
        IntuneScepServiceClient client = new IntuneScepServiceClient(helper.properties, helper.msal, helper.adal, helper.httpBuilder);
        
        UUID transactionId = UUID.randomUUID();
        String csr = "test";
        boolean caught = false;
        try 
        {
            // Run test where SERVICE URL throws UnknownHostException to cause refresh service map
            client.ValidateRequest(transactionId.toString(), csr);
        }
        catch(UnknownHostException e)
        {
            caught = true;
        }
        
        assertTrue(caught);
        
        verify(helper.msal, times(2)).getAccessToken(ArgumentMatchers.<String>anySet());
        verify(helper.adal, times(0)).getAccessTokenFromCredential(anyString());
        
        verify(helper.httpClient, times(1)).execute(
                argThat(new ArgumentMatcher<HttpUriRequest>() {
                    @Override
                    public boolean matches(HttpUriRequest resp) {
                        try {
                            return resp.getUri().getHost().equals(Helper.MSAL_URL);
                        } catch (URISyntaxException e) {
                            return false;
                        }
                    }}));

        verify(helper.httpClient, times(1)).execute(
                argThat(new ArgumentMatcher<HttpUriRequest>() {
                    @Override
                    public boolean matches(HttpUriRequest resp) {
                        try {
                            return resp.getUri().getHost().equals(Helper.SERVICE_URL);
                        } catch (URISyntaxException e) {
                            return false;
                        }
                    }}));
        
        // do this so the result doesn't get cached
        helper.resetMsalRequest();
        
        when(helper.httpClient.execute(
                argThat(new ArgumentMatcher<HttpUriRequest>() {
                    @Override
                    public boolean matches(HttpUriRequest resp) {
                        if (resp == null)
                            return false;
                        try {
                            return resp.getUri().getHost().equals(Helper.SERVICE_URL);
                        } catch (URISyntaxException e) {
                            return false;
                        }
                    }})))
            .thenReturn(helper.intuneResponse);
        
        // Run test that should trigger a 2nd call to GRAPH for service discovery meaning we refreshed the cache
        client.ValidateRequest(transactionId.toString(), csr);

        verify(helper.msal, times(4)).getAccessToken(ArgumentMatchers.<String>anySet());
        verify(helper.adal, times(0)).getAccessTokenFromCredential(anyString());
        
        // Verify we indeed called graph a 2nd time
        verify(helper.httpClient, times(2)).execute(
                argThat(new ArgumentMatcher<HttpUriRequest>() {
                    @Override
                    public boolean matches(HttpUriRequest resp) {
                        try {
                            return resp.getUri().getHost().equals(Helper.MSAL_URL);
                        } catch (URISyntaxException e) {
                            return false;
                        }
                    }}));

        verify(helper.httpClient, times(2)).execute(
                argThat(new ArgumentMatcher<HttpUriRequest>() {
                    @Override
                    public boolean matches(HttpUriRequest resp) {
                        try {
                            return resp.getUri().getHost().equals(Helper.SERVICE_URL);
                        } catch (URISyntaxException e) {
                            return false;
                        }
                    }}));
    }
}
