package com.czertainly.core.service;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.AttributeException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.exception.ValidationException;
import com.otilm.api.model.common.NameAndUuidDto;
import com.otilm.api.model.core.certificate.group.GroupDto;
import com.otilm.api.model.core.certificate.group.GroupRequestDto;
import com.czertainly.core.dao.entity.Group;
import com.czertainly.core.dao.repository.GroupRepository;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.security.authz.SecurityFilter;
import com.czertainly.core.util.BaseSpringBootTest;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.List;

public class GroupServiceTest extends BaseSpringBootTest {

    private static final String CERTIFICATE_GROUP_NAME = "testCertificateGroup1";

    @Autowired
    private GroupService groupService;

    @Autowired
    private GroupRepository groupRepository;

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
        Assertions.assertThrows(NotFoundException.class, () -> groupService.getGroup(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002")));
    }

    @Test
    public void testAddCertificateGroup() throws ValidationException, AlreadyExistException, NotFoundException, AttributeException {
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
        Assertions.assertThrows(
                NotFoundException.class,
                () -> groupService.editGroup(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"), request)
        );
    }

    @Test
    public void testRemoveCertificateGroup() throws NotFoundException {
        groupService.deleteGroup(group.getSecuredUuid());
        Assertions.assertThrows(
                NotFoundException.class,
                () -> groupService.getGroup(group.getSecuredUuid())
        );
    }

    @Test
    public void testRemoveCertificateGroup_notFound() {
        Assertions.assertThrows(
                NotFoundException.class,
                () -> groupService.deleteGroup(SecuredUUID.fromString("abfbc322-29e1-11ed-a261-0242ac120002"))
        );
    }

    @Test
    public void testBulkRemove() {
        groupService.bulkDeleteGroup(List.of(group.getSecuredUuid()));
        Assertions.assertThrows(
                NotFoundException.class,
                () -> groupService.getGroup(group.getSecuredUuid())
        );
    }

    @Test
    public void testGetObjectsForResource() {
        List<NameAndUuidDto> dtos = groupService.listResourceObjects(SecurityFilter.create(), null, null);
        Assertions.assertEquals(1, dtos.size());
    }

    @Test
    void testGetResourceObject() throws NotFoundException {
        NameAndUuidDto nameAndUuidDto = groupService.getResourceObjectInternal(group.getUuid());
        Assertions.assertEquals(group.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(group.getName(), nameAndUuidDto.getName());

        nameAndUuidDto = groupService.getResourceObjectExternal(group.getSecuredUuid());
        Assertions.assertEquals(group.getUuid().toString(), nameAndUuidDto.getUuid());
        Assertions.assertEquals(group.getName(), nameAndUuidDto.getName());
    }
}
