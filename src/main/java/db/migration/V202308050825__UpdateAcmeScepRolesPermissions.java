package db.migration;

import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.core.auth.*;
import com.otilm.core.model.auth.Resource;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.model.auth.ResourceSyncRequestDto;
import com.otilm.core.security.authn.client.ResourceApiClient;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.util.AuthHelper;
import com.otilm.core.util.DatabaseMigration;
import org.flywaydb.core.api.migration.BaseJavaMigration;
import org.flywaydb.core.api.migration.Context;
import org.springframework.web.reactive.function.client.WebClient;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

/**
 * Migration script for the Access control changes.
 * The script will take the data from the core database and trigger API calls to the
 * Auth Service for updating ACME and SCEP role, to add all necessary certificate permissions
 */
public class V202308050825__UpdateAcmeScepRolesPermissions extends BaseJavaMigration {

    private static final String AUTH_SERVICE_BASE_URL_PROPERTY = "AUTH_SERVICE_BASE_URL";

    private final List<String> certificatePermissions = List.of(
            ResourceAction.CREATE.getCode(),
            ResourceAction.ISSUE.getCode(),
            ResourceAction.DETAIL.getCode(),
            ResourceAction.UPDATE.getCode(),
            ResourceAction.RENEW.getCode(),
            ResourceAction.REVOKE.getCode(),
            ResourceAction.LIST.getCode());

    private WebClient client;
    private RoleManagementApiClient roleManagementApiClient;
    private ResourceApiClient resourceApiClient;

    @Override
    public Integer getChecksum() {
        return DatabaseMigration.JavaMigrationChecksums.V202308050825__UpdateAcmeScepRolesPermissions.getChecksum();
    }

    public void migrate(Context context) throws Exception {
        String authUrl = getAuthServiceUrl();
        roleManagementApiClient = new RoleManagementApiClient(authUrl, client);
        resourceApiClient = new ResourceApiClient(authUrl, client);

        // seed issue action for certificate
        List<ResourceSyncRequestDto> resources = new ArrayList<>();
        ResourceSyncRequestDto resourceSyncRequestDto = new ResourceSyncRequestDto();
        resourceSyncRequestDto.setName(Resource.findByCode(com.otilm.api.model.core.auth.Resource.CERTIFICATE.getCode()));
        resourceSyncRequestDto.setActions(List.of(ResourceAction.ISSUE.getCode()));
        resources.add(resourceSyncRequestDto);
        resourceApiClient.addResources(resources);

        // get ACME and SCEP roles
        RoleDto acmeRole = null;
        RoleDto scepRole = null;
        List<RoleDto> roles = roleManagementApiClient.getRoles().getData();
        for (RoleDto role: roles) {
            if (role.getSystemRole()) {
                if (role.getName().equals(AuthHelper.ACME_USERNAME)) acmeRole = role;
                else if (role.getName().equals(AuthHelper.SCEP_USERNAME)) scepRole = role;
            }
        }
        if (acmeRole == null || scepRole == null) throw new ValidationException("Migration cannot find system ACME or SCEP role");

        // update certificate permissions
        updatedPermissions(acmeRole);
        updatedPermissions(scepRole);
    }

    private void updatedPermissions(RoleDto role) {
        SubjectPermissionsDto permissions = roleManagementApiClient.getPermissions(role.getUuid());

        RolePermissionsRequestDto request = new RolePermissionsRequestDto();
        List<ResourcePermissionsRequestDto> resourcePermissionsRequests = new ArrayList<>();
        request.setAllowAllResources(permissions.getAllowAllResources());
        for (ResourcePermissionsDto resourcePermissions: permissions.getResources()) {
            ResourcePermissionsRequestDto requestDto = new ResourcePermissionsRequestDto();
            requestDto.setName(resourcePermissions.getName());
            requestDto.setActions(resourcePermissions.getName().equals(com.otilm.api.model.core.auth.Resource.CERTIFICATE.getCode()) ? certificatePermissions : resourcePermissions.getActions());
            requestDto.setAllowAllActions(resourcePermissions.getAllowAllActions());
            requestDto.setObjects(List.of());
            resourcePermissionsRequests.add(requestDto);
        }
        request.setResources(resourcePermissionsRequests);
        roleManagementApiClient.savePermissions(role.getUuid(), request);
    }

    private String getAuthServiceUrl() throws IOException, URISyntaxException {

        String authServiceUrl = System.getenv(AUTH_SERVICE_BASE_URL_PROPERTY);
        if (authServiceUrl != null && !authServiceUrl.isEmpty()) {
            return authServiceUrl;
        }

        ClassLoader classLoader = getClass().getClassLoader();
        URL resource = classLoader.getResource("application.properties");
        File file = new File(resource.toURI());

        final Properties properties = new Properties();
        try (InputStream targetStream = new FileInputStream(file)) {
            properties.load(targetStream);
        }
        String[] splitData = ((String) properties.get("auth-service.base-url")).split(AUTH_SERVICE_BASE_URL_PROPERTY);
        return splitData[splitData.length - 1].replace("}", "");
    }
}
