package com.otilm.core.auth;

import com.otilm.core.model.auth.ResourceSyncRequestDto;
import com.otilm.core.model.auth.SyncResponseDto;
import com.otilm.core.security.authn.client.ResourceApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.client.WebClientRequestException;

import java.util.List;


@Component
public class AuthResourceSynchronizer {

    private static final Logger logger = LoggerFactory.getLogger(AuthResourceSynchronizer.class);
    private ContextRefreshListener contextRefreshListener;
    private ResourceApiClient resourceApiClient;

    @Autowired
    public void setEndpointsListener(ContextRefreshListener contextRefreshListener) {
        this.contextRefreshListener = contextRefreshListener;
    }

    @Autowired
    public void setEndPointApiClient(ResourceApiClient resourceApiClient) {
        this.resourceApiClient = resourceApiClient;
    }

    @EventListener({ApplicationReadyEvent.class})
    public void register() {
        logger.info("Initiating Endpoints sync");
        List<ResourceSyncRequestDto> resources = contextRefreshListener.getResources();
        logger.debug("Resources: {}", resources);
        //Sync API Operation here
        try {
            SyncResponseDto response = resourceApiClient.syncResources(resources);
            logger.info("Sync operation completed, Response is {}", response);
        } catch (WebClientRequestException e) {
            logger.error("Unable to communicate with Auth Service: {}", e.getMessage());
        }
    }
}
