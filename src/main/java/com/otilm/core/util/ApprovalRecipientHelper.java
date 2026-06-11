package com.otilm.core.util;

import com.otilm.api.model.client.approval.ApprovalDetailStepDto;
import com.otilm.api.model.client.approval.ApprovalStepRecipientDto;
import com.otilm.api.model.client.approvalprofile.ApprovalStepDto;
import com.otilm.api.model.core.auth.RoleDto;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.core.dao.entity.Group;
import com.otilm.core.dao.repository.GroupRepository;
import com.otilm.core.security.authn.client.RoleManagementApiClient;
import com.otilm.core.security.authn.client.UserManagementApiClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

@Component
public class ApprovalRecipientHelper {

    private static final Logger logger = LoggerFactory.getLogger(ApprovalRecipientHelper.class);

    private GroupRepository groupRepository;
    private UserManagementApiClient userManagementApiClient;
    private RoleManagementApiClient roleManagementApiClient;

    private Map<String, String> groupNames;
    private Map<String, String> userNames;
    private Map<String, String> roleNames;

    @Autowired
    public void setGroupRepository(GroupRepository groupRepository) {
        this.groupRepository = groupRepository;
    }

    @Autowired
    public void setUserManagementApiClient(UserManagementApiClient userManagementApiClient) {
        this.userManagementApiClient = userManagementApiClient;
    }

    @Autowired
    public void setRoleManagementApiClient(RoleManagementApiClient roleManagementApiClient) {
        this.roleManagementApiClient = roleManagementApiClient;
    }

    public String getUsername(String userUuid) {
        if(userNames == null) {
            loadUsers();
        }

        return this.userNames.get(userUuid);
    }

    public String getRoleName(String roleUuid) {
        if(roleNames == null) {
            loadRoles();
        }

        return this.roleNames.get(roleUuid);
    }

    public String getGroupName(String groupUuid) {
        if(groupNames == null) {
            loadGroups();
        }

        return this.groupNames.get(groupUuid);
    }

    public void fillApprovalStepDto(ApprovalStepDto approvalStep) {
        if (approvalStep.getUserUuid() != null)
            approvalStep.setUsername(getUsername(approvalStep.getUserUuid().toString()));
        else if (approvalStep.getRoleUuid() != null)
            approvalStep.setRoleName(getRoleName(approvalStep.getRoleUuid().toString()));
        else if (approvalStep.getGroupUuid() != null)
            approvalStep.setGroupName(getGroupName(approvalStep.getGroupUuid().toString()));
    }

    public void fillApprovalDetailStepDto(ApprovalDetailStepDto approvalStep) {
        fillApprovalStepDto(approvalStep);
        for (ApprovalStepRecipientDto recipientDto : approvalStep.getApprovalStepRecipients()) {
            recipientDto.setUsername(getUsername(recipientDto.getUserUuid()));
        }
    }

    private void loadUsers() {
        try {
            this.userNames = this.userManagementApiClient.getUsers().getData().stream().collect(Collectors.toMap(UserDto::getUuid, UserDto::getUsername));
        }
        catch (Exception e) {
            logger.error("Failed to load usernames from Auth service: {}", e.getMessage());
            this.userNames = new HashMap<>();
        }
    }

    private void loadRoles() {
        try {
            this.roleNames = this.roleManagementApiClient.getRoles().getData().stream().collect(Collectors.toMap(RoleDto::getUuid, RoleDto::getName));
        }
        catch (Exception e) {
            logger.error("Failed to load role names from Auth service: {}", e.getMessage());
            this.roleNames = new HashMap<>();
        }
    }

    private void loadGroups() {
        this.groupNames = this.groupRepository.findAll().stream().collect(Collectors.toMap(g -> g.getUuid().toString(), Group::getName));
    }

}
