package com.otilm.core.service.ai;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import com.zaxxer.hikari.pool.HikariPool;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import javax.sql.DataSource;
import org.hibernate.dialect.Dialect;
import org.hibernate.engine.jdbc.connections.internal.DataSourceConnectionProvider;
import org.hibernate.engine.jdbc.connections.spi.ConnectionProvider;
import org.hibernate.engine.jdbc.connections.spi.DatabaseConnectionInfo;
import org.hibernate.engine.jdbc.env.spi.ExtractedDatabaseMetaData;
import org.hibernate.service.spi.Configurable;
import org.hibernate.service.spi.Stoppable;
import org.postgresql.Driver;
import org.postgresql.PGProperty;
import org.postgresql.util.URLCoder;
import org.springframework.jdbc.datasource.AbstractDataSource;

/** Isolates bounded AI acquisitions while ordinary Hibernate connections retain their datasource. */
public final class AiRuntimeJdbcConnectionProvider implements ConnectionProvider, Configurable, Stoppable {
    private static final long serialVersionUID = 1L;
    private final DataSourceConnectionProvider ordinary = new DataSourceConnectionProvider();
    private final AiRuntimeJdbcDeadline deadlines = new AiRuntimeJdbcDeadline();
    private final Set<Thread> workers = ConcurrentHashMap.newKeySet();
    private final HikariDataSource ai;
    private volatile boolean stopped;

    AiRuntimeJdbcConnectionProvider(DataSource source) {
        ordinary.setDataSource(source);
        ordinary.configure(Map.of());
        HikariDataSource supported = null;
        if (source instanceof HikariDataSource hikari) {
            try {
                supported = pool(hikari);
            } catch (IllegalArgumentException unsupported) {
                // Unsupported setups retain ordinary database access; AI acquisition fails closed.
            }
        }
        ai = supported;
    }

    private void writeObject(ObjectOutputStream output) throws NotSerializableException {
        throw new NotSerializableException("AI JDBC provider serialization unavailable");
    }

    private void readObject(ObjectInputStream input) throws NotSerializableException {
        throw new NotSerializableException("AI JDBC provider serialization unavailable");
    }

    private HikariDataSource pool(HikariDataSource source) {
        var properties = connectionProperties(source);
        String host = PGProperty.PG_HOST.getOrDefault(properties);
        String port = PGProperty.PG_PORT.getOrDefault(properties);
        String database = PGProperty.PG_DBNAME.getOrDefault(properties);
        String url = "jdbc:postgresql://" + host + ":" + port + "/" + URLCoder.encode(database);
        PGProperty.SOCKET_FACTORY.set(properties, AiRuntimeJdbcSocketFactory.class.getName());
        PGProperty.LOGIN_TIMEOUT.set(properties, "0");
        if (!PGProperty.REQUIRE_AUTH.isPresent(properties)) {
            PGProperty.REQUIRE_AUTH.set(properties, "none,password,md5,scram-sha-256");
        }
        var driver = new Driver();
        var config = new HikariConfig();
        config.setPoolName("ai-runtime-jdbc");
        config.setMaximumPoolSize(2);
        config.setMinimumIdle(0);
        config.setInitializationFailTimeout(-1);
        config.setValidationTimeout(AiRuntimeJdbcDeadline.VALIDATION_MILLIS);
        config.setConnectionTimeout(5000);
        config.setKeepaliveTime(0);
        config.setSchema(source.getSchema());
        config.setCatalog(source.getCatalog());
        config.setTransactionIsolation(source.getTransactionIsolation());
        config.setAutoCommit(source.isAutoCommit());
        config.setReadOnly(source.isReadOnly());
        config.setThreadFactory(task -> {
            workers.removeIf(worker -> worker.getState() == Thread.State.TERMINATED);
            var thread = new Thread(task, "ai-runtime-jdbc-pool");
            thread.setDaemon(true);
            workers.add(thread);
            return thread;
        });
        config.setDataSource(new AbstractDataSource() {
            @Override
            public Connection getConnection() throws SQLException {
                return deadlines.connect(() -> driver.connect(url, properties));
            }

            @Override
            public Connection getConnection(String username, String password) throws SQLException {
                throw new SQLException("AI JDBC credentials override unavailable");
            }

            @Override
            public void setLoginTimeout(int seconds) {
                // AI startup is bounded through its owned sockets, without DriverManager mutation.
            }

            @Override
            public int getLoginTimeout() {
                return 1;
            }
        });
        return new HikariDataSource(config);
    }

    static Properties connectionProperties(HikariDataSource source) {
        validateSource(source);
        var defaults = new Properties();
        defaults.putAll(source.getDataSourceProperties());
        if (source.getUsername() != null) {
            PGProperty.USER.set(defaults, source.getUsername());
        }
        if (source.getPassword() != null) {
            PGProperty.PASSWORD.set(defaults, source.getPassword());
        }
        var properties = Driver.parseURL(source.getJdbcUrl(), defaults);
        if (properties == null || !literalIpv4(PGProperty.PG_HOST.getOrDefault(properties))
                || !"disable".equals(PGProperty.GSS_ENC_MODE.getOrDefault(properties))
                || PGProperty.USER.getOrDefault(properties) == null
                || PGProperty.PASSWORD.getOrDefault(properties) == null
                || PGProperty.PG_DBNAME.getOrDefault(properties) == null) {
            throw new IllegalArgumentException("AI JDBC endpoint unsupported");
        }
        for (var property : new PGProperty[]{
                PGProperty.SOCKET_FACTORY,
                PGProperty.SOCKET_FACTORY_ARG,
                PGProperty.CONNECT_EXECUTOR,
                PGProperty.CONNECT_EXECUTOR_ARG,
                PGProperty.SSL_HOSTNAME_VERIFIER,
                PGProperty.SSL_PASSWORD_CALLBACK,
                PGProperty.AUTHENTICATION_PLUGIN_CLASS_NAME}) {
            if (property.isPresent(properties)) {
                throw new IllegalArgumentException("AI JDBC custom connector unsupported");
            }
        }
        String sslFactory = PGProperty.SSL_FACTORY.getOrDefault(properties);
        if (sslFactory != null && !sslFactory.equals("org.postgresql.ssl.LibPQFactory")
                && !sslFactory.equals("org.postgresql.ssl.jdbc4.LibPQFactory")) {
            throw new IllegalArgumentException("AI JDBC TLS connector unsupported");
        }
        String local = PGProperty.LOCAL_SOCKET_ADDRESS.getOrDefault(properties);
        String authentication = PGProperty.REQUIRE_AUTH.getOrDefault(properties);
        if (local != null && !literalIpv4(local)) {
            throw new IllegalArgumentException("AI JDBC local endpoint unsupported");
        }
        if (authentication != null && !authentication
                .matches("(?:none|password|md5|scram-sha-256)" + "(?:,(?:none|password|md5|scram-sha-256))*")) {
            throw new IllegalArgumentException("AI JDBC authentication unsupported");
        }
        if (!"disable".equals(PGProperty.SSL_MODE.getOrDefault(properties))
                && !PGProperty.SSL_PASSWORD.isPresent(properties)) {
            throw new IllegalArgumentException("AI JDBC interactive connector unsupported");
        }
        return properties;
    }

    private static void validateSource(HikariDataSource source) {
        if (!"42.7.13".equals(Driver.class.getPackage().getImplementationVersion()) || source.getDataSource() != null
                || source.getDataSourceClassName() != null || source.getDataSourceJNDI() != null
                || source.getCredentialsProvider() != null || source.getConnectionInitSql() != null
                || source.isIsolateInternalQueries() || source.getConnectionTestQuery() != null
                || source.getJdbcUrl() == null || Boolean.getBoolean("com.zaxxer.hikari.enableRequestBoundaries")
                || !"org.postgresql.Driver".equals(source.getDriverClassName())) {
            throw new IllegalArgumentException("AI JDBC connector unsupported");
        }
    }

    @Override
    public void configure(Map<String, Object> properties) {
        ordinary.configure(properties);
    }

    private static boolean literalIpv4(String host) {
        if (host == null || !host.matches("(?:0|[1-9]\\d{0,2})(?:\\.(?:0|[1-9]\\d{0,2})){3}")) {
            return false;
        }
        for (String part : host.split("\\.")) {
            if (Integer.parseInt(part) > 255) {
                return false;
            }
        }
        return true;
    }

    @Override
    public Connection getConnection() throws SQLException {
        var budget = AiRuntimeJdbcBudget.current();
        if (budget == null) {
            return ordinary.getConnection();
        }
        long wait = budget.remaining().toMillis() - AiRuntimeJdbcDeadline.VALIDATION_MILLIS
                - AiRuntimeJdbcDeadline.CLEANUP_MILLIS;
        if (stopped || ai == null || wait < 1) {
            throw new AiRuntimeOperationBudget.Unavailable(false);
        }
        var connection = ((HikariPool) ai.getHikariPoolMXBean()).getConnection(wait);
        try {
            budget.remaining();
            if (stopped) {
                throw new AiRuntimeOperationBudget.Unavailable(false);
            }
            return deadlines.borrow(connection, budget, ai::evictConnection);
        } catch (RuntimeException | SQLException | Error failure) {
            ai.evictConnection(connection);
            throw failure;
        }
    }

    @Override
    public Connection getConnection(String username, String password) throws SQLException {
        if (AiRuntimeJdbcBudget.current() != null) {
            throw new AiRuntimeOperationBudget.Unavailable(false);
        }
        return ordinary.getConnection(username, password);
    }

    @Override
    public void closeConnection(Connection connection) throws SQLException {
        ordinary.closeConnection(connection);
    }

    @Override
    public boolean supportsAggressiveRelease() {
        return ordinary.supportsAggressiveRelease();
    }

    @Override
    public DatabaseConnectionInfo getDatabaseConnectionInfo(Dialect dialect) {
        return ordinary.getDatabaseConnectionInfo(dialect);
    }

    @Override
    public DatabaseConnectionInfo getDatabaseConnectionInfo(Dialect dialect, ExtractedDatabaseMetaData metadata) {
        return ordinary.getDatabaseConnectionInfo(dialect, metadata);
    }

    @Override
    public boolean isUnwrappableAs(Class<?> type) {
        return type.isInstance(this) || ordinary.isUnwrappableAs(type);
    }

    @Override
    public <T> T unwrap(Class<T> type) {
        return type.isInstance(this) ? type.cast(this) : ordinary.unwrap(type);
    }

    @Override
    public synchronized void stop() {
        if (stopped) {
            return;
        }
        stopped = true;
        ordinary.stop();
        try {
            try {
                deadlines.closeConnections();
            } finally {
                if (ai != null) {
                    ai.close();
                }
            }
            long end = System.nanoTime() + TimeUnit.SECONDS.toNanos(2);
            for (var worker : workers) {
                long left = end - System.nanoTime();
                if (left > 0) {
                    TimeUnit.NANOSECONDS.timedJoin(worker, left);
                }
                if (worker.isAlive()) {
                    throw new IllegalStateException("AI JDBC pool worker did not terminate");
                }
            }
        } catch (InterruptedException failure) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("AI JDBC pool shutdown interrupted");
        } finally {
            deadlines.close();
        }
    }
}
