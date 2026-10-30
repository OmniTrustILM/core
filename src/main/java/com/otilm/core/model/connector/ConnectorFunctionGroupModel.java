package com.otilm.core.model.connector;

import com.otilm.api.model.core.connector.FunctionGroupCode;
import com.otilm.core.dao.entity.Connector2FunctionGroup;
import com.otilm.core.util.MetaDefinitions;
import java.util.List;
import java.util.UUID;

/** Connector function group data exposed by the full connector model. */
public record ConnectorFunctionGroupModel(UUID uuid, String name, FunctionGroupCode code, List<String> kinds) {

    public static ConnectorFunctionGroupModel from(Connector2FunctionGroup relation) {
        return new ConnectorFunctionGroupModel(relation.getFunctionGroup().getUuid(),
                relation.getFunctionGroup().getName(), relation.getFunctionGroup().getCode(),
                MetaDefinitions.deserializeArrayString(relation.getKinds()));
    }
}
