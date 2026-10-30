package com.otilm.core.integration.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserWithPaginationDto;
import com.otilm.api.model.core.certificate.group.GroupDto;
import com.otilm.api.model.core.certificate.group.GroupRequestDto;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import com.otilm.core.security.authz.SecuredParentUUID;
import com.otilm.core.security.authz.SecuredUUID;
import com.otilm.core.security.authz.SecurityFilter;
import com.otilm.core.service.GroupExternalService;
import com.otilm.core.service.GroupInternalService;
import com.otilm.core.util.BaseSpringBootTest;
import com.otilm.core.util.mockbeans.ManagementApiMocks;
import java.util.List;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Import;
import org.springframework.security.access.AccessDeniedException;

import static org.mockito.Mockito.when;

@Import(ManagementApiMocks.class)
public class GroupServiceITest extends BaseSpringBootTest {

    private static final String CERTIFICATE_GROUP_NAME = "testCertificateGroup1";

    @Autowired
    private GroupExternalService groupService;

    @Autowired
    private GroupInternalService groupInternalService;

    @Autowired
    private GroupRepository groupRepository;

    @Autowired
    private UserManagementApiClient userManagementApiClient;

    private Group group;

    @BeforeEach
    public void setUp() {
        group = new Group();
        group.setName(CERTIFICATE_GROUP_NAME);
        group = groupRepository.save(group);
    }

    @Test
    public void testListCertificateGroups() {
        List<GroupDto> certificateGroups = groupService.listGroups(SecurityFilter.create());
        Assertions.assertNotNull(certificateGroups);
        Assertions.assertFalse(certificateGroups.isEmpty());
        Assertions.assertEquals(1, certificateGroups.size());
        Assertions.assertEquals(group.getUuid().toString(), certificateGroups.get(0).getUuid());
    }

    @Test
    public void testGetCertificateGroup() throws NotFoundException {
        GroupDto dto = groupService.getGroup(group.getSecuredUuid());
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(group.getUuid().toString(), dto.getUuid());
        Assertions.assertEquals(group.getName(), dto.getName());
    }

    @Test
    public void testGetCertificateGroup_notFound() {
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> groupService.getGroup(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void testAddCertificateGroup()
            throws ValidationException, AlreadyExistException, NotFoundException, AttributeException {
        GroupRequestDto request = new GroupRequestDto();
        request.setName("test");

        GroupDto dto = groupService.createGroup(request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getName(), dto.getName());
    }

    @Test
    public void testAddCertificateGroup_validationFail() {
        GroupRequestDto request = new GroupRequestDto();
        Assertions.assertThrows(ValidationException.class, () -> groupService.createGroup(request));
    }

    @Test
    public void testAddCertificateGroup_alreadyExist() {
        GroupRequestDto request = new GroupRequestDto();
        request.setName(CERTIFICATE_GROUP_NAME); // certificateGroup with same name exist

        Assertions.assertThrows(AlreadyExistException.class, () -> groupService.createGroup(request));
    }

    @Test
    public void testEditCertificateGroup() throws NotFoundException, AttributeException {
        GroupRequestDto request = new GroupRequestDto();
        request.setName("Test");
        request.setDescription("some description");

        GroupDto dto = groupService.editGroup(group.getSecuredUuid(), request);
        Assertions.assertNotNull(dto);
        Assertions.assertEquals(request.getDescription(), dto.getDescription());
    }

    @Test
    public void testEditCertificateGroup_notFound() {
        GroupRequestDto request = new GroupRequestDto();
        Assertions
                .assertThrows(NotFoundException.class, () -> groupService
                        .editGroup(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), request));
    }

    @Test
    public void testRemoveCertificateGroup() throws NotFoundException {
        groupService.deleteGroup(group.getSecuredUuid());
        Assertions.assertThrows(NotFoundException.class, () -> groupService.getGroup(group.getSecuredUuid()));
    }

    @Test
    public void testRemoveCertificateGroup_notFound() {
        Assertions
                .assertThrows(NotFoundException.class,
                        () -> groupService.deleteGroup(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void testBulkRemove() {
        groupService.bulkDeleteGroup(List.of(group.getSecuredUuid()));
        Assertions.assertThrows(NotFoundException.class, () -> groupService.getGroup(group.getSecuredUuid()));
    }

    @Test
    public void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = groupInternalService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, dtos.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = groupInternalService.getResourceObjectInternal(group.getUuid());
        Assertions.assertEquals(group.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(group.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = groupInternalService.getResourceObjectExternal(group.getSecuredUuid());
        Assertions.assertEquals(group.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(group.getName(), nameAndUuidDto.getName());
    }

    @Test
    void getGroupUsersReturnsUsersAssignedToTheGroupAsNameAndUuid() throws NotFoundException {
        UserDto member = user("11111111-1111-1111-1111-111111111111", "member",
                new NameAndUuidDto(group.getUuid().toString(), group.getName()));
        UserDto outsider = user("22222222-2222-2222-2222-222222222222", "outsider",
                new NameAndUuidDto("33333333-3333-3333-3333-333333333333", "otherGroup"));
        stubUsers(member, outsider);

        List<NameAndUuidDto> users = groupService.getGroupUsers(SecuredParentUUID.fromUUID(group.getUuid()));

        Assertions.assertEquals(1, users.size());
        Assertions.assertEquals("11111111-1111-1111-1111-111111111111", users.get(0).getUuid());
        Assertions.assertEquals("member", users.get(0).getName());
    }

    @Test
    void getGroupUsersReturnsEmptyListWhenNoUserIsAssigned() throws NotFoundException {
        stubUsers(user("22222222-2222-2222-2222-222222222222", "outsider",
                new NameAndUuidDto("33333333-3333-3333-3333-333333333333", "otherGroup")));

        Assertions.assertTrue(groupService.getGroupUsers(SecuredParentUUID.fromUUID(group.getUuid())).isEmpty());
    }

    @Test
    void getGroupUsersThrowsNotFoundForUnknownGroup() {
        Assertions
                .assertThrows(NotFoundException.class, () -> groupService
                        .getGroupUsers(SecuredParentUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    void getGroupUsersReturnsUserBelongingToSeveralGroups() throws NotFoundException {
        stubUsers(user("11111111-1111-1111-1111-111111111111", "member",
                new NameAndUuidDto("33333333-3333-3333-3333-333333333333", "otherGroup"),
                new NameAndUuidDto(group.getUuid().toString(), group.getName())));

        List<NameAndUuidDto> users = groupService.getGroupUsers(SecuredParentUUID.fromUUID(group.getUuid()));

        Assertions.assertEquals(1, users.size());
        Assertions.assertEquals("member", users.get(0).getName());
    }

    @Test
    void getGroupUsersDeniesCallerWithoutMembersPermission() {
        denyResourceAccess(Resource.GROUP, ResourceAction.MEMBERS);
        SecuredParentUUID groupUuid = SecuredParentUUID.fromUUID(group.getUuid());

        Assertions.assertThrows(AccessDeniedException.class, () -> groupService.getGroupUsers(groupUuid));
    }

    @Test
    void getGroupUsersDeniesCallerWithoutUserListPermission() {
        denyResourceAccess(Resource.USER, ResourceAction.LIST);
        SecuredParentUUID groupUuid = SecuredParentUUID.fromUUID(group.getUuid());

        Assertions.assertThrows(AccessDeniedException.class, () -> groupService.getGroupUsers(groupUuid));
    }

    // auth serves the user directory as a single capped page; members it did not return cannot be recovered here
    @Test
    void getGroupUsersReturnsTheMembersAuthServedWhenTheDirectoryIsTruncated() throws NotFoundException {
        UserWithPaginationDto response = new UserWithPaginationDto();
        response
                .setData(List
                        .of(user("11111111-1111-1111-1111-111111111111", "member",
                                new NameAndUuidDto(group.getUuid().toString(), group.getName()))));
        response.setTotalCount(1500);
        when(userManagementApiClient.getUsers()).thenReturn(response);

        List<NameAndUuidDto> users = groupService.getGroupUsers(SecuredParentUUID.fromUUID(group.getUuid()));

        Assertions.assertEquals(1, users.size());
    }

    private void stubUsers(UserDto... users) {
        UserWithPaginationDto response = new UserWithPaginationDto();
        response.setData(List.of(users));
        when(userManagementApiClient.getUsers()).thenReturn(response);
    }

    private UserDto user(String uuid, String username, NameAndUuidDto... groups) {
        UserDto dto = new UserDto();
        dto.setUuid(uuid);
        dto.setUsername(username);
        dto.setGroups(List.of(groups));
        return dto;
    }
}
