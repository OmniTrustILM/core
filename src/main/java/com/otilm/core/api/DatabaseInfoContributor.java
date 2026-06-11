package com.otilm.core.api;

import org.springframework.boot.actuate.info.Info;
import org.springframework.boot.actuate.info.InfoContributor;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.util.HashMap;
import java.util.Map;

@Component
@Profile("!test")
public class DatabaseInfoContributor implements InfoContributor {

    private final Map<String, Object> cachedDatabaseInfo;

    public DatabaseInfoContributor(DataSource dataSource) {
        this.cachedDatabaseInfo = precomputeDatabaseInfo(dataSource);
    }

    @Override
    public void contribute(Info.Builder builder) {
        builder.withDetail("db", cachedDatabaseInfo);
    }

    private Map<String, Object> precomputeDatabaseInfo(DataSource dataSource) {
        Map<String, Object> dbInfo = new HashMap<>();

        try (Connection connection = dataSource.getConnection()) {
            DatabaseMetaData metaData = connection.getMetaData();
            dbInfo.put("system", metaData.getDatabaseProductName());
            dbInfo.put("version", metaData.getDatabaseProductVersion());
        } catch (Exception e) {
            throw new RuntimeException("Unable to retrieve database information.", e);
        }

        return dbInfo;
    }
}
