package com.czertainly.core.dao.repository;

import com.czertainly.api.model.core.proxy.ProxyStatus;
import com.czertainly.core.dao.entity.Proxy;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ProxyRepository extends SecurityFilterRepository<Proxy, UUID> {

    Optional<Proxy> findByName(String name);

    Optional<Proxy> findByCode(String code);

    List<Proxy> findByStatus(ProxyStatus status);
}
