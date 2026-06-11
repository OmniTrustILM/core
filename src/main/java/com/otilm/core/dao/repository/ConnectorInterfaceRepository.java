package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.ConnectorInterfaceEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface ConnectorInterfaceRepository extends JpaRepository<ConnectorInterfaceEntity, UUID> {

}
