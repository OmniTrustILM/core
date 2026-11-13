package com.otilm.core.util.seeders;

import com.otilm.api.exception.AlreadyExistException;
import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.client.approval.UserApprovalDto;
import com.otilm.api.model.client.approvalprofile.ApprovalProfileRequestDto;
import com.otilm.api.model.client.approvalprofile.ApprovalStepRequestDto;
import com.otilm.api.model.core.auth.UserDto;
import com.otilm.api.model.core.auth.UserProfileDto;
import com.otilm.api.model.core.logging.enums.AuthMethod;
import com.otilm.core.dao.entity.ApprovalProfile;
import com.otilm.core.dao.entity.RaProfile;
import com.otilm.core.security.authn.PlatformAuthenticationToken;
import com.otilm.core.security.authn.PlatformUserDetails;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.service.ApprovalExternalService;
import com.otilm.core.service.ApprovalProfileExternalService;
import com.otilm.core.service.RaProfileExternalService;
import com.otilm.core.util.PrincipalFixtures;
import java.util.List;
import java.util.UUID;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

/**
 * Seeds the approval that an RA Profile asks for before it issues, through the services that an administrator uses: an
 * enabled approval profile of one step, which one approval by the approver decides and which expires after a day,
 * associated with the RA Profile. An issue queued through the RA Profile then waits for that approval, which the
 * approver gives or refuses through the services that an approver uses.
 */
@Component
public class ApprovalProfileSeeder {

    private static final int EXPIRY_HOURS = 24;
    private static final String APPROVER_USERNAME = "test-approver";

    @Autowired
    private ApprovalProfileExternalService approvalProfileService;

    @Autowired
    private RaProfileExternalService raProfileService;

    @Autowired
    private ApprovalExternalService approvalService;

    /** Makes the RA Profile ask the approver for one approval before it issues, and returns the approval profile. */
    public ApprovalProfile requireApproval(RaProfile raProfile, UUID approverUuid)
            throws NotFoundException, AlreadyExistException {
        ApprovalStepRequestDto step = new ApprovalStepRequestDto();
        step.setOrder(1);
        step.setUserUuid(approverUuid);
        step.setRequiredApprovals(1);
        ApprovalProfileRequestDto profileRequest = new ApprovalProfileRequestDto();
        profileRequest.setName(raProfile.getName() + "-approval");
        profileRequest.setEnabled(true);
        profileRequest.setExpiry(EXPIRY_HOURS);
        profileRequest.getApprovalSteps().add(step);
        ApprovalProfile approvalProfile = approvalProfileService.createApprovalProfile(profileRequest);
        raProfileService
                .associateApprovalProfile(raProfile.getAuthorityInstanceReferenceUuid().toString(),
                        raProfile.getUuid().toString(), approvalProfile.getSecuredUuid());
        return approvalProfile;
    }

    /**
     * Gives the approval as the approver, who is not the user that asked for it. The platform queues the answer of the
     * approval once the decision has committed, for the caller to deliver, and the caller is authenticated as before
     * once the decision is made.
     */
    public void approveAs(UUID approverUuid, UUID approvalUuid) throws NotFoundException {
        UserApprovalDto decision = new UserApprovalDto();
        decision.setComment("approved");
        decideAs(approverUuid, () -> approvalService.approveApprovalRecipient(approvalUuid.toString(), decision));
    }

    /** As {@link #approveAs}, but the approver refuses the approval. */
    public void refuseAs(UUID approverUuid, UUID approvalUuid) throws NotFoundException {
        UserApprovalDto decision = new UserApprovalDto();
        decision.setComment("refused");
        decideAs(approverUuid, () -> approvalService.rejectApprovalRecipient(approvalUuid.toString(), decision));
    }

    private static void decideAs(UUID approverUuid, Decision decision) throws NotFoundException {
        SecurityContext context = SecurityContextHolder.getContext();
        Authentication caller = context.getAuthentication();
        context.setAuthentication(approverAuthentication(approverUuid));
        try {
            decision.make();
        } finally {
            context.setAuthentication(caller);
        }
    }

    /** The approver as the platform sees a user that the Auth service identified, with no roles. */
    private static Authentication approverAuthentication(UUID approverUuid) {
        UserDto user = new UserDto();
        user.setUuid(approverUuid.toString());
        user.setUsername(APPROVER_USERNAME);
        user.setSystemUser(true);
        UserProfileDto profile = new UserProfileDto();
        profile.setUser(user);
        profile.setRoles(List.of());
        AuthenticationInfo info = new AuthenticationInfo(AuthMethod.USER_PROXY, approverUuid.toString(),
                APPROVER_USERNAME, List.of(), PrincipalFixtures.principal(profile));
        return new PlatformAuthenticationToken(new PlatformUserDetails(info));
    }

    @FunctionalInterface
    private interface Decision {
        void make() throws NotFoundException;
    }
}
