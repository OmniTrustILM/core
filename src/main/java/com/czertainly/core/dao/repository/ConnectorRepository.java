package com.czertainly.core.dao.repository;

import com.otilm.api.model.client.connector.v2.ConnectorVersion;
import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.czertainly.core.dao.entity.Connector;
import com.czertainly.core.dao.entity.FunctionGroup;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface ConnectorRepository extends SecurityFilterRepository<Connector, Long> {

    Optional<Connector> findByUuid(UUID uuid);

    Optional<Connector> findByName(String name);

    Optional<Connector> findByUrlAndVersion(String url, ConnectorVersion version);

    @Query(value =
            " select c from Connector c " +
                    " join c.functionGroups c2fg " +
                    " where c.status = 'CONNECTED' " +
                    "   and c2fg.functionGroup = :functionGroup " +
                    "   and c2fg.kinds like '%' || :kind || '%' "
    )
    List<Connector> findConnectedByFunctionGroupAndKind(
            @Param("functionGroup") FunctionGroup functionGroup,
            @Param("kind") String kind);

    @Query(value = """
            SELECT c from Connector c
            JOIN c.functionGroups c2fg
            JOIN c2fg.functionGroup fg
            WHERE c.status = 'CONNECTED' AND fg.code = :functionGroup
            """)
    List<Connector> findConnectedByFunctionGroupCode(@Param("functionGroup") FunctionGroupCode functionGroupCode);

    @Query(value = """
            SELECT c from Connector c
            JOIN c.functionGroups c2fg
            JOIN c2fg.functionGroup fg
            WHERE c.status = 'CONNECTED' AND fg.code = :functionGroup AND c2fg.kinds LIKE '%' || :kind || '%'
            """)
    List<Connector> findConnectedByFunctionGroupCodeAndKind(@Param("functionGroup") FunctionGroupCode functionGroupCode, @Param("kind") String kind);
}
