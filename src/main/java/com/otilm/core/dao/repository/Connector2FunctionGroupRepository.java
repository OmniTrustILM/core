package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.Connector;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.dao.entity.FunctionGroup;
import java.util.List;
import java.util.Optional;
import org.springframework.stereotype.Repository;

@Repository
public interface Connector2FunctionGroupRepository extends SecurityFilterRepository<Connector2FunctionGroup, Long> {

    List<Connector2FunctionGroup> findAllByConnector(Connector connector);

    Optional<Connector2FunctionGroup> findByConnectorAndFunctionGroup(Connector connector, FunctionGroup functionGroup);
}
