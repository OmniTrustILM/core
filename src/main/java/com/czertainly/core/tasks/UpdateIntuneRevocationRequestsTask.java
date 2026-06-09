package com.czertainly.core.tasks;

import com.otilm.api.exception.NotFoundException;
import com.otilm.api.model.core.authority.CertificateRevocationReason;
import com.otilm.api.model.core.certificate.CertificateState;
import com.otilm.api.model.core.certificate.CertificateValidationStatus;
import com.otilm.api.model.core.v2.ClientCertificateRevocationDto;
import com.otilm.api.model.scheduler.SchedulerJobExecutionStatus;
import com.czertainly.core.dao.entity.Certificate;
import com.czertainly.core.dao.entity.scep.ScepProfile;
import com.czertainly.core.dao.repository.scep.ScepProfileRepository;
import com.czertainly.core.intune.carequest.CARequestErrorCodes;
import com.czertainly.core.intune.carequest.CARevocationRequest;
import com.czertainly.core.intune.carequest.CARevocationResult;
import com.czertainly.core.intune.scepvalidation.IntuneRevocationClient;
import com.czertainly.core.model.ScheduledTaskResult;
import com.czertainly.core.oid.OidHandler;
import com.czertainly.core.security.authz.SecuredParentUUID;
import com.czertainly.core.security.authz.SecuredUUID;
import com.czertainly.core.service.CertificateService;
import com.czertainly.core.service.v2.ClientOperationService;
import com.czertainly.core.util.AuthHelper;
import com.czertainly.core.util.CzertainlyX500NameStyle;
import lombok.NoArgsConstructor;
import org.bouncycastle.asn1.x500.X500Name;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.slf4j.MarkerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.security.auth.x500.X500Principal;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.UUID;

@Component
@NoArgsConstructor
@Transactional
public class UpdateIntuneRevocationRequestsTask implements ScheduledJobTask {

    private static final Logger logger = LoggerFactory.getLogger(UpdateIntuneRevocationRequestsTask.class);

    // scheduled for every hour, to process revocation requests from Intune enabled SCEP profiles
    private static  final String CRON_EXPRESSION = "0 30 * ? * *";

    private static final String JOB_NAME = "updateIntuneRevocationRequestsJob";

    @Value("${app.version}")
    private String appVersion;

    private static final int MAX_CA_REQUESTS_TO_DOWNLOAD = 500;

    private ScepProfileRepository scepProfileRepository;

    private CertificateService certificateService;

    private ClientOperationService clientOperationService;

    private AuthHelper authHelper;

    @Autowired
    public void setAuthHelper(AuthHelper authHelper) {
        this.authHelper = authHelper;
    }

    @Autowired
    public void setScepProfileRepository(ScepProfileRepository scepProfileRepository) {
        this.scepProfileRepository = scepProfileRepository;
    }

    @Autowired
    public void setCertificateService(CertificateService certificateService) {
        this.certificateService = certificateService;
    }

    @Autowired
    public void setClientOperationService(ClientOperationService clientOperationService) {
        this.clientOperationService = clientOperationService;
    }

    public String getDefaultJobName() {
        return JOB_NAME;
    }

    public String getDefaultCronExpression() {
        return CRON_EXPRESSION;
    }

    public boolean isDefaultOneTimeJob() {
        return false;
    }

    public String getJobClassName() {
        return this.getClass().getName();
    }

    public boolean isSystemJob() {
        return true;
    }

    public ScheduledTaskResult performJob(final ScheduledJobInfo scheduledJobInfo, final Object taskData) {
        logger.info(MarkerFactory.getMarker("scheduleInfo"), "Executing Intune revocation requests update task");
        authHelper.authenticateAsSystemUser(AuthHelper.SCEP_USERNAME);

        List<ScepProfile> scepProfiles = scepProfileRepository.findByIntuneEnabled(true);
        for (ScepProfile scepProfile : scepProfiles) {
            logger.info(MarkerFactory.getMarker("scheduleInfo"), "Processing Intune revocation requests for SCEP profile: {}", scepProfile.getName());

            Properties configProperties = new Properties();
            configProperties.put("AAD_APP_ID", scepProfile.getIntuneApplicationId());
            configProperties.put("AAD_APP_KEY", scepProfile.getIntuneApplicationKey());
            configProperties.put("TENANT", scepProfile.getIntuneTenant());
            configProperties.put("PROVIDER_NAME_AND_VERSION", "CZERTAINLY-V" + appVersion);

            IntuneRevocationClient intuneRevocationClient = new IntuneRevocationClient(configProperties);

            List<CARevocationRequest> revocationRequests;
            try {
                revocationRequests = downloadRevocationRequests(intuneRevocationClient);
            } catch (Exception e) {
                logger.error(MarkerFactory.getMarker("scheduleInfo"), "Error downloading CA revocation requests", e);
                return new ScheduledTaskResult(SchedulerJobExecutionStatus.FAILED, "Error downloading CA revocation requests");
            }

            List<CARevocationResult> revocationResults = processRevocationRequests(revocationRequests);

            try {
                uploadRevocationResults(intuneRevocationClient, revocationResults);
            } catch (Exception e) {
                logger.error(MarkerFactory.getMarker("scheduleInfo"), "Error uploading revocation results", e);
            }
        }
        return new ScheduledTaskResult(SchedulerJobExecutionStatus.SUCCESS, "Processed Intune revocation requests for %d SCEP profiles".formatted(scepProfiles.size()));
    }

    private List<CARevocationRequest> downloadRevocationRequests(IntuneRevocationClient intuneRevocationClient) throws Exception {
        String downloadTransactionId = UUID.randomUUID().toString();

        if (logger.isDebugEnabled()) {
            logger.debug(MarkerFactory.getMarker("scheduleInfo"), "Downloading CA revocation requests: transactionId={}, maxCARequestsToDownload={}, issuerDN={}",
                    downloadTransactionId, MAX_CA_REQUESTS_TO_DOWNLOAD, null);
        }

        List<CARevocationRequest> revocationRequests = intuneRevocationClient.DownloadCARevocationRequests(
                downloadTransactionId,
                MAX_CA_REQUESTS_TO_DOWNLOAD,
                null
        );

        if (logger.isDebugEnabled()) {
            logger.debug(MarkerFactory.getMarker("scheduleInfo"), "Downloaded {} revocation requests", revocationRequests.size());
        }

        return revocationRequests;
    }

    private List<CARevocationResult> processRevocationRequests(List<CARevocationRequest> revocationRequests) {
        List<CARevocationResult> revocationResults = new ArrayList<>();

        for (CARevocationRequest revocationRequest : revocationRequests) {
            try {
                String issuerName = X500Name.getInstance(new CzertainlyX500NameStyle(true), new X500Principal(revocationRequest.issuerName, OidHandler.getCodeToOidMap()).getEncoded()).toString();
                Certificate certificate = certificateService.getCertificateEntityByIssuerDnNormalizedAndSerialNumber(
                        issuerName,
                        revocationRequest.serialNumber
                );
                // TODO: Improve handling of certificate status and revocation reason
                // there may be different certificate status we need to handle
                // when the certificate is already revoked, we just need to send the message to Intune
                if (certificate.getState().equals(CertificateState.REVOKED)) {
                    revocationResults.add(new CARevocationResult(
                                    revocationRequest.requestContext,
                                    true,
                                    CARequestErrorCodes.None,
                                    ""
                            )
                    );
                    continue;
                }
                // this should not happen, but if the certificate is expired, Intune should not try to revoke it
                if (certificate.getValidationStatus().equals(CertificateValidationStatus.EXPIRED)) {
                    revocationResults.add(new CARevocationResult(
                                    revocationRequest.requestContext,
                                    false,
                                    CARequestErrorCodes.NonRetryableServiceException,
                                    "Certificate already expired"
                            )
                    );
                    continue;
                }

                ClientCertificateRevocationDto revocationDto = new ClientCertificateRevocationDto();
                revocationDto.setReason(CertificateRevocationReason.UNSPECIFIED);
                revocationDto.setAttributes(new ArrayList<>());

                // if certificate is already revoked, do not try to revoke by CA
                if (certificate.getState() != CertificateState.REVOKED) {
                    clientOperationService.revokeCertificate(
                            SecuredParentUUID.fromUUID(certificate.getRaProfile().getAuthorityInstanceReferenceUuid()),
                            SecuredUUID.fromUUID(certificate.getRaProfileUuid()),
                            certificate.getUuid().toString(),
                            revocationDto
                    );
                }

                revocationResults.add(new CARevocationResult(
                                revocationRequest.requestContext,
                                true,
                                CARequestErrorCodes.None,
                                ""
                        )
                );
                logger.debug(MarkerFactory.getMarker("scheduleInfo"), "Certificate for Intune revocation processed successfully: UUID={}, serialNumber={}, fingerprint={}",
                        certificate.getUuid().toString(), certificate.getSerialNumber(), certificate.getFingerprint());
            } catch (NotFoundException e) {
                logger.debug(MarkerFactory.getMarker("scheduleInfo"), "Certificate for Intune revocation not found in inventory: issuerDN={}, serialNumber={}",
                        revocationRequest.issuerName, revocationRequest.serialNumber);
                revocationResults.add(new CARevocationResult(
                                revocationRequest.requestContext,
                                false,
                                CARequestErrorCodes.CertificateNotFoundError,
                                "Certificate not found in inventory"
                        )
                );
            } catch (Exception e) {
                logger.debug(MarkerFactory.getMarker("scheduleInfo"), "Failed to revoke certificate for Intune request: issuerDN={}, serialNumber={}",
                        revocationRequest.issuerName, revocationRequest.serialNumber, e);
                revocationResults.add(new CARevocationResult(
                                revocationRequest.requestContext,
                                false,
                                CARequestErrorCodes.RetryableServiceException,
                                e.getMessage()
                        )
                );
            }
        }

        return revocationResults;
    }

    private void uploadRevocationResults(IntuneRevocationClient intuneRevocationClient, List<CARevocationResult> revocationResults) throws Exception {
        // we upload only when there are some results
        if (!revocationResults.isEmpty()) {
            String uploadTransactionId = UUID.randomUUID().toString();

            if (logger.isDebugEnabled()) {
                logger.debug(MarkerFactory.getMarker("scheduleInfo"), "Uploading {} revocation results: transactionId={}",
                        revocationResults.size(), uploadTransactionId);
            }

            intuneRevocationClient.UploadRevocationResults(
                    uploadTransactionId,
                    revocationResults
            );
        }
    }


}
