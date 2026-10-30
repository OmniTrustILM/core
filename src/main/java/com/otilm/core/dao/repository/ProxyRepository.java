package com.otilm.core.dao.repository;

import com.otilm.api.model.core.proxy.ProxyStatus;
import com.otilm.core.dao.entity.Proxy;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import org.springframework.stereotype.Repository;

@Repository
public interface ProxyRepository extends SecurityFilterRepository<Proxy, UUID> {

    Optional<Proxy> findByName(String name);

    Optional<Proxy> findByCode(String code);

    List<Proxy> findByStatus(ProxyStatus status);
}
