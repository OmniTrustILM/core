package com.czertainly.core.auth;

import com.otilm.api.exception.AttributeException;
import com.otilm.api.model.common.attribute.common.BaseAttribute;
import com.otilm.api.model.core.auth.Resource;
import com.czertainly.core.attribute.CoreAttributeDefinitions;
import com.czertainly.core.attribute.engine.AttributeEngine;
import com.czertainly.core.model.auth.ResourceSyncRequestDto;
import com.czertainly.core.security.authz.ExternalAuthorization;
import lombok.Getter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.ApplicationContext;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

@Component
public class ContextRefreshListener {

    private static final Logger LOGGER = LoggerFactory.getLogger(ContextRefreshListener.class);

    @Getter
    private List<ResourceSyncRequestDto> resources = new ArrayList<>();

    private AttributeEngine attributeEngine;

    @Autowired
    public void setAttributeEngine(AttributeEngine attributeEngine) {
        this.attributeEngine = attributeEngine;
    }


    @EventListener
    public void handleContextRefresh(ContextRefreshedEvent event) {
        ApplicationContext applicationContext = event.getApplicationContext();
        Map<Resource, String> listingEndpoints = new EnumMap<>(Resource.class);
        Map<Resource, Set<String>> resourceToAction = new EnumMap<>(Resource.class);
        //Get all the routes annotated with the listing end point
        applicationContext.getBean("requestMappingHandlerMapping", RequestMappingHandlerMapping.class)
                .getHandlerMethods()
                .entrySet().stream()
                .filter(e -> !e.getKey().getMethodsCondition().getMethods().isEmpty())
                .filter(e -> e.getValue().getMethod().getAnnotation(AuthEndpoint.class) != null)
                .forEach(e -> {
                    AuthEndpoint annotatedValues = e.getValue().getMethod().getAnnotation(AuthEndpoint.class);
                    if (listingEndpoints.get(annotatedValues.resourceName()) != null) {
                        throw new RuntimeException("Duplicate listing end point on " + annotatedValues.resourceName().getCode());
                    }
                    listingEndpoints.put(annotatedValues.resourceName(), e.getKey().getPatternValues().iterator().next());
                });
        //Iterate and get all the methods that are annotated with ExternalAuthentication
        for (String beanName : applicationContext.getBeanDefinitionNames()) {
            Method[] methods = AopUtils.getTargetClass(applicationContext.getBean(beanName)).getDeclaredMethods();

            for (Method m : methods) {
                if (m.isAnnotationPresent(ExternalAuthorization.class)) {
                    ExternalAuthorization annotatedValue = m.getAnnotation(ExternalAuthorization.class);
                    resourceToAction.computeIfAbsent(annotatedValue.resource(),
                            k -> new HashSet<>()).add(annotatedValue.action().getCode());
                    if (annotatedValue.parentResource() != null && annotatedValue.parentResource() != Resource.NONE) {
                        resourceToAction.computeIfAbsent(annotatedValue.parentResource(),
                                k -> new HashSet<>()).add(annotatedValue.parentAction().getCode());
                    }
                }

                saveCoreAttributes(beanName, m, applicationContext);
            }
        }
        //Merge listing end point and external annotation end point to get the resource request sync operation
        for (Map.Entry<Resource, Set<String>> entry : resourceToAction.entrySet()) {
            ResourceSyncRequestDto requestDto = new ResourceSyncRequestDto();
            requestDto.setActions(new ArrayList<>(entry.getValue()));
            requestDto.setName(com.czertainly.core.model.auth.Resource.findByCode(entry.getKey().getCode()));
            requestDto.setListObjectsEndpoint(listingEndpoints.get(entry.getKey()));
            resources.add(requestDto);
        }
    }

    private void saveCoreAttributes(String beanName, Method m, ApplicationContext applicationContext) {
        if (m.isAnnotationPresent(CoreAttributeDefinitions.class)) {
            CoreAttributeDefinitions attributeDefinitions = m.getAnnotation(CoreAttributeDefinitions.class);
            try {
                List<BaseAttribute> attributes = (List<BaseAttribute>) m.invoke(applicationContext.getBean(beanName));
                attributeEngine.updateDataAttributeDefinitions(null, attributeDefinitions.operation(), attributes);
            } catch (IllegalAccessException | ClassCastException | InvocationTargetException e) {
                LOGGER.error("Cannot retrieve list of attributes from bean {} and method {}: {}", beanName, m.getName(), e.getMessage());
            } catch (AttributeException e) {
                LOGGER.error("Did not manage to save attribute definitions returned by method {} in bean {}: {}", beanName, m.getName(), e.getMessage());
            }
        }
    }

}
