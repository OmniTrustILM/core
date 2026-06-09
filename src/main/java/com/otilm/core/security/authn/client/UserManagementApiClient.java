package com.otilm.core.security.authn.client;

import com.otilm.api.model.core.auth.RoleDto;
import com.otilm.api.model.core.auth.SubjectPermissionsDto;
import com.otilm.api.model.core.auth.UserDetailDto;
import com.otilm.api.model.core.auth.UserRequestDto;
import com.otilm.api.model.core.auth.UserUpdateRequestDto;
import com.otilm.api.model.core.auth.UserWithPaginationDto;
import com.otilm.core.model.auth.AuthenticationRequestDto;
import org.springframework.http.HttpMethod;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.ArrayList;
import java.util.List;

public class UserManagementApiClient extends PlatformBaseAuthenticationClient {

    private static final String USER_BASE_CONTEXT = "/auth/users";
    private static final String USER_DETAIL_CONTEXT = USER_BASE_CONTEXT + "/{userUuid}";

    private static final String USER_IDENTIFY_CONTEXT = USER_BASE_CONTEXT + "/identify";
    private static final String USER_PERMISSION_CONTEXT = USER_DETAIL_CONTEXT + "/permissions";
    private static final String USER_ROLE_CONTEXT = USER_DETAIL_CONTEXT + "/roles";

    private static final List<String> listTypeRef = new ArrayList<>();

    public UserManagementApiClient(String authServiceBaseUrl, WebClient client) {
        super(authServiceBaseUrl, client);
    }

    public UserManagementApiClient() {
    }

    public UserWithPaginationDto getUsers() {

        WebClient.RequestBodySpec request = prepareRequest(HttpMethod.GET).uri(USER_BASE_CONTEXT);

        return processRequest(r -> r
                        .retrieve()
                        .toEntity(UserWithPaginationDto.class)
                        .block().getBody(),
                request);
    }


    public UserDetailDto getUserDetail(String userUuid) {
        WebClient.RequestBodySpec request = prepareRequest(HttpMethod.GET).uri(USER_DETAIL_CONTEXT.replace("{userUuid}", userUuid));

        return processRequest(r -> r
                        .retrieve()
                        .toEntity(UserDetailDto.class)
                        .block().getBody(),
                request);
    }

    public UserDetailDto identifyUser(AuthenticationRequestDto requestDto) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.POST);

        return processRequest(r -> r
                        .uri(USER_IDENTIFY_CONTEXT)
                        .body(Mono.just(requestDto), UserRequestDto.class)
                        .retrieve()
                        .toEntity(UserDetailDto.class)
                        .block().getBody(),
                request);
    }

    public UserDetailDto createUser(UserRequestDto requestDto) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.POST);

        return processRequest(r -> r
                        .uri(USER_BASE_CONTEXT)
                        .body(Mono.just(requestDto), UserRequestDto.class)
                        .retrieve()
                        .toEntity(UserDetailDto.class)
                        .block().getBody(),
                request);
    }

    public UserDetailDto updateUser(String userUuid, UserUpdateRequestDto requestDto) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.PUT);

        return processRequest(r -> r
                        .uri(USER_DETAIL_CONTEXT, userUuid)
                        .body(Mono.just(requestDto), UserRequestDto.class)
                        .retrieve()
                        .toEntity(UserDetailDto.class)
                        .block().getBody(),
                request);
    }

    public void removeUser(String userUuid) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.DELETE);

        processRequest(r -> r
                        .uri(USER_DETAIL_CONTEXT, userUuid)
                        .retrieve()
                        .toEntity(Void.class)
                        .block().getBody(),
                request);
    }

    public List<RoleDto> getUserRoles(String userUuid) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.GET);

        return processRequest(r -> r
                        .uri(USER_ROLE_CONTEXT, userUuid)
                        .retrieve()
                        .toEntityList(RoleDto.class)
                        .block().getBody(),
                request);
    }

    public SubjectPermissionsDto getPermissions(String userUuid) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.GET);

        return processRequest(r -> r
                        .uri(USER_PERMISSION_CONTEXT, userUuid)
                        .retrieve()
                        .toEntity(SubjectPermissionsDto.class)
                        .block().getBody(),
                request);
    }

    public UserDetailDto updateRoles(String userUuid, List<String> roles) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.PATCH);

        return processRequest(r -> r
                        .uri(USER_ROLE_CONTEXT, userUuid)
                        .body(Mono.just(roles), listTypeRef.getClass())
                        .retrieve()
                        .toEntity(UserDetailDto.class)
                        .block().getBody(),
                request);
    }

    public UserDetailDto updateRole(String userUuid, String roleUuid) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.PUT);

        return processRequest(r -> r
                        .uri(USER_ROLE_CONTEXT + "/" + roleUuid, userUuid)
                        .retrieve()
                        .toEntity(UserDetailDto.class)
                        .block().getBody(),
                request);
    }

    public UserDetailDto removeRole(String userUuid, String roleUuid) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.DELETE);

        return processRequest(r -> r
                        .uri(USER_ROLE_CONTEXT + "/" + roleUuid, userUuid)
                        .retrieve()
                        .toEntity(UserDetailDto.class)
                        .block().getBody(),
                request);
    }

    public UserDetailDto enableUser(String userUuid) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.PATCH);

        return processRequest(r -> r
                        .uri(USER_DETAIL_CONTEXT + "/enable", userUuid)
                        .retrieve()
                        .toEntity(UserDetailDto.class)
                        .block().getBody(),
                request);
    }

    public UserDetailDto disableUser(String userUuid) {
        WebClient.RequestBodyUriSpec request = prepareRequest(HttpMethod.PATCH);

        return processRequest(r -> r
                        .uri(USER_DETAIL_CONTEXT + "/disable", userUuid)
                        .retrieve()
                        .toEntity(UserDetailDto.class)
                        .block().getBody(),
                request);
    }
}
