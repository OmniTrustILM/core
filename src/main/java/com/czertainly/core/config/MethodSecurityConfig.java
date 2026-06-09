package com.czertainly.core.config;

import com.czertainly.core.security.authz.ExternalAuthorization;
import com.czertainly.core.security.authz.ExternalAuthorizationDynamic;
import com.czertainly.core.security.authz.ExternalMethodAuthorizationManager;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.aop.support.annotation.AnnotationMatchingPointcut;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerBeforeMethodInterceptor;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

import static org.springframework.beans.factory.config.BeanDefinition.ROLE_INFRASTRUCTURE;

@Configuration
@EnableMethodSecurity
public class MethodSecurityConfig {

    ExternalMethodAuthorizationManager externalMethodAuthorizationManager;

    @Bean
    public AuthorizationManager<MethodInvocation> authorizationManager() {
        return externalMethodAuthorizationManager;
    }

    @Bean
    @Role(ROLE_INFRASTRUCTURE)
    public Advisor authorizationManagerBeforeMethodInterception(AuthorizationManager<MethodInvocation> authorizationManager) {
        AnnotationMatchingPointcut pointcut = new AnnotationMatchingPointcut(null, ExternalAuthorization.class);
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, authorizationManager);
    }

    @Bean
    @Role(ROLE_INFRASTRUCTURE)
    public Advisor dynamicAuthorizationManagerBeforeMethodInterception(AuthorizationManager<MethodInvocation> authorizationManager) {
        AnnotationMatchingPointcut pointcut = new AnnotationMatchingPointcut(null, ExternalAuthorizationDynamic.class);
        return new AuthorizationManagerBeforeMethodInterceptor(pointcut, authorizationManager);
    }

    @Autowired
    public void setExternalMethodAuthorizationManager(ExternalMethodAuthorizationManager externalMethodAuthorizationManager) {
        this.externalMethodAuthorizationManager = externalMethodAuthorizationManager;
    }
}
