package com.otilm.core.dao.repository;

import com.otilm.core.dao.entity.Endpoint;
import java.util.UUID;
import org.springframework.stereotype.Repository;

/**
 * Test-scope repository for {@link Endpoint}. Production has no repository for this table — endpoint reference data is
 * inserted only by Flyway migrations. Tests run with Flyway disabled, so {@code FunctionGroupSeeder} needs a way to
 * persist the rows; same exception to the "persist via services" rule as the seeder itself.
 */
@Repository
public interface EndpointRepository extends SecurityFilterRepository<Endpoint, UUID> {
}
