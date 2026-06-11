package com.otilm.core.dao.repository;

import org.springframework.context.annotation.Configuration;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;

@Configuration
@EnableJpaRepositories(repositoryBaseClass = SecurityFilterRepositoryImpl.class)
public class RepositoryConfiguration {
}
