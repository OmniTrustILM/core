package db.migration;

import com.otilm.api.model.core.auth.*;
import com.czertainly.core.model.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.czertainly.core.model.auth.ResourceSyncRequestDto;
import com.czertainly.core.security.authn.client.ResourceApiClient;
import com.czertainly.core.security.authn.client.RoleManagementApiClient;
import com.czertainly.core.util.DatabaseAuthMigration;
import com.czertainly.core.security.authn.client.UserManagementApiClient;
import com.czertainly.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.*;

/**
 * Migration script for the Access control changes.
 * The script will take the data from the core database and trigger API calls to the
 * Auth Service for creating, users, roles, RA Profile Authorizations. Once the migrations are completed,
 * then the data in the core will be cleaned up.
 */
public class V202209211100__Access_Control extends BaseJavaMigration {

    private static final String AUTH_SERVICE_BASE_URL_PROPERTY = "AUTH_SERVICE_BASE_URL";

    private static Properties properties;
    private final List<String> certificateUserUpdateCommands = new ArrayList<>();
    private final List<String> detailPermissionObjects = List.of(Resource.ACME_PROFILE.getCode(),
            Resource.RA_PROFILE.getCode(),
            Resource.AUTHORITY.getCode());
    private final List<String> certificatePermissions = List.of(ResourceAction.CREATE.getCode(),
            ResourceAction.DETAIL.getCode(),
            ResourceAction.UPDATE.getCode(),
            ResourceAction.RENEW.getCode(),
            ResourceAction.REVOKE.getCode(),
            ResourceAction.LIST.getCode());
    private final Map<String, String> detailPermissionObjectsListingEndpoints = Map.of(
            Resource.ACME_PROFILE.getCode(), "/v1/acmeProfiles",
            Resource.RA_PROFILE.getCode(), "/v1/raProfiles",
            Resource.AUTHORITY.getCode(), "/v1/authorities");
    private WebClient client;
    private UserManagementApiClient userManagementApiClient;
    private RoleManagementApiClient roleManagementApiClient;
    private ResourceApiClient resourceApiClient;
    private String superAdministratorRoleUuid;
    private String administratorRoleUuid;

    public void setSuperAdministratorRoleUuid(String superAdministratorRoleUuid) {
        this.superAdministratorRoleUuid = superAdministratorRoleUuid;
    }

    public void setAdministratorRoleUuid(String administratorRoleUuid) {
        this.administratorRoleUuid = administratorRoleUuid;
    }

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202209211100__Access_Control.getChecksum();
    }

    public void migrate(Context context) throws Exception {
        String authUrl = getAuthServiceUrl();
        userManagementApiClient = new UserManagementApiClient(authUrl, client);
        roleManagementApiClient = new RoleManagementApiClient(authUrl, client);
        resourceApiClient = new ResourceApiClient(authUrl, client);
        try (Statement select = context.getConnection().createStatement()) {
            //Permissions will be seeded to the auth service for initial ACME Role registration
            seedResources();
            createSuperAdminRole();
            createAdminRole();
            createAcmeRole();
            createCertificateUserReference(select);
            List<String> adminNames = createAdministratorUsers(context);
            Map<String, String> clientRoleMap = createClientUsers(context, adminNames);
            updateRolePermissions(context, clientRoleMap);
            executeCommands(select, certificateUserUpdateCommands);
            performCleanups(select);
        }
    }

    private void createCertificateUserReference(Statement select) throws SQLException {
        String command = "ALTER TABLE certificate add column user_uuid uuid;";
        executeCommands(select, List.of(command));
    }

    private List<String> createAdministratorUsers(Context context) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT a.username, a.name, a.surname, a.email, a.certificate_uuid, a.enabled, a.role, a.description, c.fingerprint FROM admin a JOIN certificate c ON a.certificate_uuid = c.uuid;")) {
                List<String> adminNames = new ArrayList<>();
                while (rows.next()) {
                    UserRequestDto dto = new UserRequestDto();
                    String certificateUuid = rows.getString("certificate_uuid");
                    dto.setCertificateUuid(certificateUuid);
                    dto.setLastName(rows.getString("surname"));
                    dto.setFirstName(rows.getString("name"));
                    dto.setUsername(rows.getString("username"));
                    dto.setEmail(rows.getString("email"));
                    dto.setEnabled(rows.getBoolean("enabled"));
                    dto.setDescription(rows.getString("description"));
                    dto.setCertificateFingerprint(rows.getString("fingerprint"));
                    UserDto response = DatabaseAuthMigration.getOrCreateUser(userManagementApiClient, dto);
                    assignRoles(response.getUuid(), rows.getString("role").equals("SUPERADMINISTRATOR") ? superAdministratorRoleUuid : administratorRoleUuid);
                    adminNames.add(dto.getUsername());
                    certificateUserUpdateCommands.add("update certificate SET user_uuid = '" + response.getUuid() + "' WHERE uuid = '" + certificateUuid + "'");
                }
                return adminNames;
            }
        }
    }

    private Map<String, String> createClientUsers(Context context, List<String> adminNames) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT a.uuid, a.name, a.certificate_uuid, a.enabled, a.description, c.fingerprint FROM client a JOIN certificate c ON a.certificate_uuid = c.uuid WHERE a.certificate_uuid NOT IN (SELECT b.certificate_uuid FROM admin b);")) {
                Map<String, String> clientRoleMap = new HashMap<>();
                while (rows.next()) {
                    UserRequestDto dto = new UserRequestDto();
                    String certificateUuid = rows.getString("certificate_uuid");
                    dto.setCertificateUuid(certificateUuid);
                    String clientName = rows.getString("name");
                    if (adminNames.contains(clientName)) {
                        dto.setUsername("Client_" + clientName);
                    } else {
                        dto.setUsername(clientName);
                    }
                    dto.setEnabled(rows.getBoolean("enabled"));
                    dto.setCertificateFingerprint(rows.getString("fingerprint"));
                    dto.setDescription(rows.getString("description"));
                    UserDto response = DatabaseAuthMigration.getOrCreateUser(userManagementApiClient, dto);
                    String roleUuid = createClientRoles(response.getUuid(), clientName);
                    clientRoleMap.put(rows.getString("uuid"), roleUuid);
                    certificateUserUpdateCommands.add("update certificate SET user_uuid = '" + response.getUuid() + "' WHERE uuid = '" + certificateUuid + "'");
                }
                return clientRoleMap;
            }
        }
    }

    private String getAuthServiceUrl() throws IOException, URISyntaxException {

        String authServiceUrl = System.getenv(AUTH_SERVICE_BASE_URL_PROPERTY);
        if (authServiceUrl != null && !authServiceUrl.isEmpty()) {
            return authServiceUrl;
        }

        ClassLoader classLoader = getClass().getClassLoader();
        URL resource = classLoader.getResource("application.properties");
        File file = new File(resource.toURI());

        InputStream targetStream = new FileInputStream(file);
        Properties properties = new Properties();
        properties.load(targetStream);
        String[] splitData = ((String) properties.get("auth-service.base-url")).split(AUTH_SERVICE_BASE_URL_PROPERTY);
        return splitData[splitData.length - 1].replace("}", "");
    }

    private String createClientRoles(String clientUuid, String clientName) {
        RoleRequestDto dto = new RoleRequestDto();
        dto.setName("Client_Role_" + clientName);
        dto.setDescription("Role created during migration for the client " + clientName);
        dto.setSystemRole(false);
        RoleDto response = DatabaseAuthMigration.getOrCreateRole(roleManagementApiClient, dto);
        assignRoles(clientUuid, response.getUuid());
        return response.getUuid();
    }

    private void assignClientPermission(String roleUuid, Set<String> raProfileUuids, Set<String> authorityUuids) {
        if (raProfileUuids.isEmpty()) return;

        RolePermissionsRequestDto roleRequest = new RolePermissionsRequestDto();
        roleRequest.setAllowAllResources(false);

        List<ResourcePermissionsRequestDto> listResources = new ArrayList<>();

        // Set RA Profile Permissions
        ResourcePermissionsRequestDto raProfileResourceRequest = new ResourcePermissionsRequestDto();
        raProfileResourceRequest.setName(Resource.RA_PROFILE.getCode());
        raProfileResourceRequest.setAllowAllActions(false);
        raProfileResourceRequest.setActions(List.of());
        List<ObjectPermissionsRequestDto> objects = new ArrayList<>();
        for (String raProfileUuid : raProfileUuids) {
            ObjectPermissionsRequestDto dto = new ObjectPermissionsRequestDto();
            String[] raProfileUuidSplit = raProfileUuid.split(":#");
            dto.setName(raProfileUuidSplit[1]);
            dto.setUuid(raProfileUuidSplit[0]);
            dto.setAllow(List.of(ResourceAction.LIST.getCode(), ResourceAction.DETAIL.getCode()));
            dto.setDeny(List.of());
            objects.add(dto);
        }
        raProfileResourceRequest.setObjects(objects);
        listResources.add(raProfileResourceRequest);

        // Set Authority Permissions
        ResourcePermissionsRequestDto authorityResourceRequest = new ResourcePermissionsRequestDto();
        authorityResourceRequest.setName(Resource.AUTHORITY.getCode());
        authorityResourceRequest.setAllowAllActions(false);
        authorityResourceRequest.setActions(List.of());
        List<ObjectPermissionsRequestDto> authorityObjects = new ArrayList<>();
        for (String authorityUuid : authorityUuids) {
            ObjectPermissionsRequestDto dto = new ObjectPermissionsRequestDto();
            String[] authorityUuidSplit = authorityUuid.split(":#");
            dto.setUuid(authorityUuidSplit[0]);
            dto.setName(authorityUuidSplit[1]);
            dto.setAllow(List.of(ResourceAction.DETAIL.getCode()));
            dto.setDeny(List.of());
            authorityObjects.add(dto);
        }
        authorityResourceRequest.setObjects(authorityObjects);
        listResources.add(authorityResourceRequest);

        // Set Certificate Permissions
        ResourcePermissionsRequestDto certificateResourceRequest = new ResourcePermissionsRequestDto();
        certificateResourceRequest.setName(Resource.CERTIFICATE.getCode());
        certificateResourceRequest.setAllowAllActions(true);
        certificateResourceRequest.setActions(List.of());
        certificateResourceRequest.setObjects(List.of());
        listResources.add(certificateResourceRequest);

        //Set permissions to the role dto
        roleRequest.setResources(listResources);

        // Update Permissions using API Client
        roleManagementApiClient.savePermissions(roleUuid, roleRequest);
    }

    private void assignRoles(String userUuid, String roleUUid) {
        userManagementApiClient.updateRole(userUuid, roleUUid);
    }

    private void updateRolePermissions(Context context, Map<String, String> clientRoleMap) throws Exception {
        try (Statement select = context.getConnection().createStatement()) {
            try (ResultSet rows = select.executeQuery("SELECT a.ra_profile_uuid, a.client_uuid, r.authority_instance_ref_uuid, r.name, r.authority_instance_name FROM client_authorization a JOIN ra_profile r ON a.ra_profile_uuid = r.uuid;")) {
                Map<String, Set<String>> raProfileMap = new HashMap<>();
                Map<String, Set<String>> authorityMap = new HashMap<>();
                while (rows.next()) {
                    String clientUuid = rows.getString("client_uuid");
                    String raProfileUuid = rows.getString("ra_profile_uuid");
                    String raProfileName = rows.getString("name");
                    String authorityUuid = rows.getString("authority_instance_ref_uuid");
                    String authorityName = rows.getString("authority_instance_name");
                    raProfileMap.computeIfAbsent(clientUuid, k -> new HashSet<>()).add(raProfileUuid + ":#" + raProfileName);
                    if (authorityUuid != null) {
                        authorityMap.computeIfAbsent(clientUuid, k -> new HashSet<>()).add(authorityUuid + ":#" + authorityName);
                    }
                }
                for (Map.Entry<String, String> entry : clientRoleMap.entrySet()) {
                    assignClientPermission(entry.getValue(), raProfileMap.getOrDefault(entry.getKey(), Set.of()), authorityMap.getOrDefault(entry.getKey(), Set.of()));
                }
            }
        }
    }

    private void performCleanups(Statement select) throws SQLException {
        List<String> cleanupCommands = new ArrayList<>();
        cleanupCommands.add("drop table client_authorization");
        cleanupCommands.add("drop table admin");
        cleanupCommands.add("drop table client");
        executeCommands(select, cleanupCommands);
    }

    private void executeCommands(Statement select, List<String> commands) throws SQLException {
        for (String command : commands) {
            select.execute(command);
        }
    }

    private void seedResources() {
        List<ResourceSyncRequestDto> resources = new ArrayList<>();

        for (String permissionObject : detailPermissionObjects) {
            ResourceSyncRequestDto requestDto = new ResourceSyncRequestDto();
            requestDto.setName(Resource.findByCode(permissionObject));
            requestDto.setActions(List.of(ResourceAction.DETAIL.getCode(), ResourceAction.LIST.getCode()));
            requestDto.setListObjectsEndpoint(detailPermissionObjectsListingEndpoints.get(permissionObject));
            resources.add(requestDto);
        }

        //Certificate Operations
        ResourceSyncRequestDto requestDto = new ResourceSyncRequestDto();
        requestDto.setName(Resource.CERTIFICATE);
        requestDto.setActions(certificatePermissions);

        resources.add(requestDto);

        //Acme Account Operations
        ResourceSyncRequestDto acmeAccountRequestDto = new ResourceSyncRequestDto();
        acmeAccountRequestDto.setName(Resource.ACME_ACCOUNT);
        acmeAccountRequestDto.setActions(List.of(ResourceAction.DETAIL.getCode(), ResourceAction.LIST.getCode()));
        resources.add(acmeAccountRequestDto);

        resourceApiClient.syncResources(resources);
    }

    private RolePermissionsRequestDto getPermissionPayload() {
        RolePermissionsRequestDto request = new RolePermissionsRequestDto();
        request.setAllowAllResources(false);

        List<ResourcePermissionsRequestDto> resourcePermissionsRequestDtos = new ArrayList<>();

        for (String permissionObject : detailPermissionObjects) {
            ResourcePermissionsRequestDto requestDto = new ResourcePermissionsRequestDto();
            requestDto.setName(permissionObject);
            requestDto.setActions(List.of(ResourceAction.DETAIL.getCode(), ResourceAction.LIST.getCode()));
            requestDto.setAllowAllActions(false);
            requestDto.setObjects(List.of());
            resourcePermissionsRequestDtos.add(requestDto);
        }

        //Add Certificate Permissions
        ResourcePermissionsRequestDto clientOperationsRequestDto = new ResourcePermissionsRequestDto();
        clientOperationsRequestDto.setName(Resource.CERTIFICATE.getCode());
        clientOperationsRequestDto.setActions(certificatePermissions);
        clientOperationsRequestDto.setAllowAllActions(false);
        clientOperationsRequestDto.setObjects(List.of());
        resourcePermissionsRequestDtos.add(clientOperationsRequestDto);

        //Add Acme Account Permissions
        ResourcePermissionsRequestDto acmeAccountRequestDto = new ResourcePermissionsRequestDto();
        acmeAccountRequestDto.setName(Resource.ACME_ACCOUNT.getCode());
        acmeAccountRequestDto.setActions(List.of());
        acmeAccountRequestDto.setAllowAllActions(true);
        acmeAccountRequestDto.setObjects(List.of());
        resourcePermissionsRequestDtos.add(acmeAccountRequestDto);


        request.setResources(resourcePermissionsRequestDtos);
        return request;
    }

    private void createSuperAdminRole() {
        RoleRequestDto requestDto = new RoleRequestDto();
        requestDto.setName("superadmin");
        requestDto.setDescription("System role with all permissions");
        requestDto.setSystemRole(true);
        requestDto.setPermissions(getAdminPermissions());
        RoleDetailDto response = DatabaseAuthMigration.getOrCreateRole(roleManagementApiClient, requestDto);
        setSuperAdministratorRoleUuid(response.getUuid());
    }

    private void createAdminRole() {
        RoleRequestDto requestDto = new RoleRequestDto();
        requestDto.setName("admin");
        requestDto.setDescription("System role with all administration permissions");
        requestDto.setSystemRole(true);
        requestDto.setPermissions(getAdminPermissions());
        RoleDetailDto response = DatabaseAuthMigration.getOrCreateRole(roleManagementApiClient, requestDto);
        setAdministratorRoleUuid(response.getUuid());
    }

    private void createAcmeRole() {
        RoleRequestDto requestDto = new RoleRequestDto();
        requestDto.setName("acme");
        requestDto.setDescription("System role with all ACME permissions");
        requestDto.setSystemRole(true);
        requestDto.setPermissions(getPermissionPayload());
        RoleDetailDto response = DatabaseAuthMigration.getOrCreateRole(roleManagementApiClient, requestDto);
        String acmeUser = createAcmeUser();
        assignRoles(acmeUser, response.getUuid());
    }

    private String createAcmeUser() {
        UserRequestDto requestDto = new UserRequestDto();
        requestDto.setUsername("acme");
        requestDto.setDescription("System User for ACME Operations");
        requestDto.setEnabled(true);
        requestDto.setSystemUser(true);
        requestDto.setCertificateFingerprint("");
        return DatabaseAuthMigration.getOrCreateUser(userManagementApiClient, requestDto).getUuid();
    }

    private RolePermissionsRequestDto getAdminPermissions() {
        RolePermissionsRequestDto requestDto = new RolePermissionsRequestDto();
        requestDto.setAllowAllResources(true);
        return requestDto;
    }
}