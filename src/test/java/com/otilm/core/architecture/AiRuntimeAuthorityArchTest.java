package com.otilm.core.architecture;

import com.otilm.ai.runtime.protocol.RunDispatchEnvelope;
import com.otilm.api.model.core.auth.Resource;
import com.otilm.core.dao.repository.ai.AiModelDispatchRepository;
import com.otilm.core.dao.repository.ai.AiModelManagementSessionRepository;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.ManagementRedemption;
import com.otilm.core.model.ai.AiModelDispatchState.RunPreparation;
import com.otilm.core.model.ai.AiModelDispatchState.RunRedemption;
import com.otilm.core.model.ai.AiModelManagementSession.Spec;
import com.otilm.core.model.ai.AiRuntimeState.Expected;
import com.otilm.core.model.auth.ResourceAction;
import com.otilm.core.security.ai.AiModelManagementAuthorization;
import com.otilm.core.security.ai.AiModelUseAuthorization;
import com.otilm.core.security.ai.RuntimePeer;
import com.otilm.core.security.ai.RuntimeProxyCertificateClaims;
import com.otilm.core.security.authn.client.AuthenticationInfo;
import com.otilm.core.security.authz.AuthorizationEnforcer;
import com.otilm.core.service.ai.AiModelManagementSessionService;
import com.otilm.core.service.ai.AiModelRunDispatchService;
import com.otilm.core.service.ai.AiRuntimeGatewayServiceImpl;
import com.otilm.core.service.ai.AiRuntimeOperationBudget;
import com.otilm.core.service.writer.ai.AiModelDispatchWriter;
import com.otilm.core.service.writer.ai.AiModelManagementSessionWriter;
import com.tngtech.archunit.core.domain.AccessTarget.CodeUnitAccessTarget;
import com.tngtech.archunit.core.domain.JavaAccess;
import com.tngtech.archunit.core.domain.JavaClass;
import com.tngtech.archunit.core.importer.ClassFileImporter;
import com.tngtech.archunit.core.importer.ImportOption;
import com.tngtech.archunit.junit.AnalyzeClasses;
import com.tngtech.archunit.junit.ArchTest;
import com.tngtech.archunit.lang.ArchCondition;
import com.tngtech.archunit.lang.ArchRule;
import com.tngtech.archunit.lang.ConditionEvents;
import com.tngtech.archunit.lang.SimpleConditionEvent;
import java.time.Duration;
import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;

import static com.tngtech.archunit.lang.syntax.ArchRuleDefinition.classes;
import static org.assertj.core.api.Assertions.assertThat;

/** Keeps fresh business authorization on every production model dispatch path. */
@AnalyzeClasses(packages = "com.otilm.core", importOptions = ImportOption.DoNotIncludeTests.class)
class AiRuntimeAuthorityArchTest {

    @ArchTest
    static final ArchRule currentPrincipalAndActorChecksCannotBeBypassed = classes()
            .should(new ArchCondition<>("use the model authority entry points") {
                @Override
                public void check(JavaClass item, ConditionEvents events) {
                    item.getMethodCallsFromSelf().forEach(call -> checkAccess(call, events));
                    item.getMethodReferencesFromSelf().forEach(reference -> checkAccess(reference, events));
                }
            });

    private static void checkAccess(JavaAccess<? extends CodeUnitAccessTarget> access, ConditionEvents events) {
        CodeUnitAccessTarget target = access.getTarget();
        String caller = access.getOriginOwner().getName();
        boolean currentPrincipal = target.getOwner().isAssignableTo(AuthorizationEnforcer.class)
                && target.getName().equals("enforce")
                && target
                        .getRawParameterTypes()
                        .stream()
                        .anyMatch(type -> type.isEquivalentTo(AuthenticationInfo.class));
        boolean legacyDispatch = target.getOwner().isAssignableTo(AiModelDispatchWriter.class)
                && (target.getName().equals("prepareRun") || target.getName().equals("consumeRun"))
                && target.getRawParameterTypes().size() == 2;
        boolean actorDispatch = target.getOwner().isAssignableTo(AiModelDispatchWriter.class)
                && (target.getName().equals("prepareRun") || target.getName().equals("consumeRun"))
                && target.getRawParameterTypes().size() >= 3;
        boolean nativeConsume = target.getOwner().isAssignableTo(AiModelRunDispatchService.class)
                && target.getName().equals("consume");
        boolean nativeCaller = caller.equals("com.otilm.core.service.ai.AiNativeGatewayOperations")
                && target.getRawParameterTypes().size() == 4;
        boolean repositoryMutation = target.getOwner().isAssignableTo(AiModelDispatchRepository.class)
                && (target.getName().startsWith("consume") || target.getName().startsWith("reserve")
                        || target.getName().startsWith("insert") && target.getName().endsWith("Intent"));
        boolean sessionMutation = target.getOwner().isAssignableTo(AiModelManagementSessionRepository.class)
                && (target.getName().equals("insert") || target.getName().equals("close"));
        boolean sessionCreate = target.getOwner().isAssignableTo(AiModelManagementSessionWriter.class)
                && target.getName().equals("create");
        if (managementBypass(target, caller) || runOutcomeBypass(target, caller) || cleanupBypass(target, caller)
                || nativeStartupBypass(target, caller) || legacyRuntimeBudgetBypass(target, caller)
                || (currentPrincipal && !caller.equals(AiModelUseAuthorization.class.getName())
                        && !caller.equals(AiModelManagementAuthorization.class.getName()))
                || (legacyDispatch && !caller.equals(AiModelDispatchWriter.class.getName()))
                || (actorDispatch && !caller.equals(AiModelDispatchWriter.class.getName())
                        && !caller.equals(AiModelRunDispatchService.class.getName()))
                || (nativeConsume && !nativeCaller && !caller.equals(AiModelRunDispatchService.class.getName()))
                || (repositoryMutation && !caller.equals(AiModelDispatchWriter.class.getName()))
                || (sessionMutation && !caller.equals(AiModelManagementSessionWriter.class.getName()))
                || (sessionCreate && !caller.equals(AiModelManagementSessionWriter.class.getName())
                        && !caller.equals(AiModelManagementSessionService.class.getName()))) {
            events.add(SimpleConditionEvent.violated(access, access.getDescription()));
        }
    }

    private static boolean legacyRuntimeBudgetBypass(CodeUnitAccessTarget target, String caller) {
        int arity = target.getRawParameterTypes().size();
        boolean legacy = switch (target.getName()) {
            case "snapshot", "observe", "invalidate" -> arity == 1;
            case "control" -> arity == 0;
            case "bootstrap", "heartbeat" -> arity == 2;
            default -> false;
        };
        if (!legacy) {
            return false;
        }
        String kernel = com.otilm.core.service.ai.AiRuntimeKernel.class.getName();
        String writer = com.otilm.core.service.writer.ai.AiRuntimeWriter.class.getName();
        if (target.getOwner().isAssignableTo(com.otilm.core.service.ai.AiRuntimeKernel.class)) {
            return !caller.equals(kernel);
        }
        return target.getOwner().isAssignableTo(com.otilm.core.service.writer.ai.AiRuntimeWriter.class)
                && !caller.equals(writer) && !caller.equals(kernel);
    }

    private static boolean managementBypass(CodeUnitAccessTarget target, String caller) {
        return nativeFactoryBypass(target, caller) || managementDispatchBypass(target, caller)
                || managementRepositoryBypass(target, caller) || managementPublisherBypass(target, caller)
                || managementOutcomeBypass(target, caller);
    }

    private static boolean nativeFactoryBypass(CodeUnitAccessTarget target, String caller) {
        if (!target.getOwner().getName().equals("com.otilm.core.service.ai.AiNativeGatewayOperations")) {
            return false;
        }
        return switch (target.getName()) {
            case "run" -> !caller.equals(AiRuntimeGatewayServiceImpl.class.getName());
            case "management" ->
                !caller.equals(com.otilm.core.service.ai.AiRuntimeManagementGatewayServiceImpl.class.getName());
            default -> false;
        };
    }

    private static boolean managementDispatchBypass(CodeUnitAccessTarget target, String caller) {
        String composition = com.otilm.core.service.ai.AiModelManagementDispatchService.class.getName();
        if (target.getOwner().isAssignableTo(AiModelDispatchWriter.class)
                && java.util.Set.of("prepareManagement", "consumeManagement").contains(target.getName())) {
            return !caller.equals(AiModelDispatchWriter.class.getName())
                    && (target.getRawParameterTypes().size() == 2 || !caller.equals(composition));
        }
        if (target.getOwner().isAssignableTo(com.otilm.core.service.ai.AiModelManagementDispatchService.class)
                && target.getName().equals("consume")) {
            return !caller.equals(composition) && !(target.getRawParameterTypes().size() == 4
                    && caller.equals("com.otilm.core.service.ai.AiNativeGatewayOperations"));
        }
        if (target.getOwner().isAssignableTo(AiModelDispatchWriter.class)
                && target.getName().startsWith("preparedManagement")) {
            return !caller.equals(composition);
        }
        if (target.getOwner().isAssignableTo(AiModelDispatchRepository.class)
                && (target.getName().startsWith("preparedManagement")
                        || target.getName().startsWith("managementIntentBy"))) {
            return !caller.equals(AiModelDispatchRepository.class.getName())
                    && !caller.equals(AiModelDispatchWriter.class.getName());
        }
        return false;
    }

    private static boolean managementRepositoryBypass(CodeUnitAccessTarget target, String caller) {
        if (target.getOwner().isAssignableTo(com.otilm.core.dao.repository.ai.AiRuntimeGatewayRepository.class)
                && java.util.Set.of("configure", "observe", "revoke").contains(target.getName())) {
            return !caller.equals(com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter.class.getName());
        }
        if (target
                .getOwner()
                .isAssignableTo(com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository.class)
                && java.util.Set
                        .of("configure", "disable", "observe", "revoke", "clearObservations", "startupDeny")
                        .contains(target.getName())) {
            String startup = com.otilm.core.service.writer.ai.AiRuntimeNativeStartupWriter.class.getName();
            if (target.getName().equals("startupDeny")) {
                return !caller.equals(startup);
            }
            if (target.getName().equals("clearObservations") && caller.equals(startup)) {
                return false;
            }
            return !caller.equals(com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter.class.getName());
        }
        if (target.getOwner().isAssignableTo(com.otilm.core.dao.repository.ai.AiModelManagementGatewayRepository.class)
                && target.getName().equals("assign")) {
            return !caller.equals(com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter.class.getName());
        }
        if (target.getOwner().isAssignableTo(com.otilm.core.dao.repository.ai.AiModelManagementOutcomeRepository.class)
                && java.util.Set.of("append", "read").contains(target.getName())) {
            return !caller.equals(com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter.class.getName());
        }
        return false;
    }

    private static boolean managementPublisherBypass(CodeUnitAccessTarget target, String caller) {
        boolean management = target
                .getOwner()
                .isAssignableTo(com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter.class);
        boolean run = target
                .getOwner()
                .isAssignableTo(com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter.class);
        if ((management || run)
                && java.util.Set.of("configure", "disable", "observe", "revoke").contains(target.getName())) {
            String writer = management
                    ? com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter.class.getName()
                    : com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter.class.getName();
            if (target.getName().equals("observe")
                    && caller.equals("com.otilm.core.service.ai.AiRuntimeControllerRegistrationServiceImpl")) {
                return false;
            }
            return !caller.equals(writer);
        }
        return target.getOwner().isAssignableTo(com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter.class)
                && target.getName().equals("assign")
                && !caller.equals(com.otilm.core.service.writer.ai.AiModelManagementGatewayWriter.class.getName());
    }

    private static boolean managementOutcomeBypass(CodeUnitAccessTarget target, String caller) {
        String writer = com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter.class.getName();
        if (!target.getOwner().isAssignableTo(com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter.class)
                || caller.equals(writer)) {
            return false;
        }
        return switch (target.getName()) {
            case "read" -> !caller.equals(com.otilm.core.service.ai.AiModelManagementResultService.class.getName());
            case "append" -> !caller.equals("com.otilm.core.service.ai.AiNativeGatewayOperations");
            default -> false;
        };
    }

    private static boolean runOutcomeBypass(CodeUnitAccessTarget target, String caller) {
        return target.getOwner().isAssignableTo(com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter.class)
                && target.getName().equals("append")
                && !caller.equals("com.otilm.core.service.ai.AiNativeGatewayOperations")
                && !caller.equals(com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter.class.getName());
    }

    private static boolean cleanupBypass(CodeUnitAccessTarget target, String caller) {
        String writer = com.otilm.core.service.writer.ai.AiRuntimeCleanupWriter.class.getName();
        if (target.getOwner().isAssignableTo(com.otilm.core.service.writer.ai.AiRuntimeCleanupWriter.class)
                && target.getName().equals("complete")) {
            return !caller.equals(writer) && !caller.equals("com.otilm.core.service.ai.AiRuntimeControllerServiceImpl");
        }
        return target.getOwner().isAssignableTo(com.otilm.core.dao.repository.ai.AiRuntimeCleanupRepository.class)
                && target.getName().equals("complete") && !caller.equals(writer);
    }

    private static boolean nativeStartupBypass(CodeUnitAccessTarget target, String caller) {
        return target.getOwner().isAssignableTo(com.otilm.core.service.writer.ai.AiRuntimeNativeStartupWriter.class)
                && target.getName().equals("disableAndConfirm")
                && !caller.equals(com.otilm.core.service.writer.ai.AiRuntimeNativeStartupWriter.class.getName())
                && !caller.equals("com.otilm.core.security.ai.AiRuntimeNativeMaterialConfiguration");
    }

    @Test
    void rejectsCallerSuppliedPrincipalsAndLegacyDispatchCalls() {
        var classes = new ClassFileImporter().importClasses(BypassCalls.class);
        var result = currentPrincipalAndActorChecksCannotBeBypassed.evaluate(classes);
        assertThat(result.getFailureReport().getDetails()).hasSize(3);
        assertThat(result.hasViolation()).isTrue();
    }

    @Test
    void rejectsMethodReferencesToTheSameBypasses() {
        var classes = new ClassFileImporter().importClasses(BypassReferences.class);
        var result = currentPrincipalAndActorChecksCannotBeBypassed.evaluate(classes);
        assertThat(result.getFailureReport().getDetails()).hasSize(2);
        assertThat(result.hasViolation()).isTrue();
    }

    static class BypassCalls {
        void invoke(AuthorizationEnforcer authorization, AuthenticationInfo principal, UUID model,
                AiModelDispatchWriter writer, RunPreparation preparation, RunRedemption redemption,
                AiRuntimeOperationBudget budget) {
            authorization.enforce(Resource.AI_MODEL, ResourceAction.USE, principal, model, Duration.ofSeconds(1));
            writer.prepareRun(preparation, budget);
            writer.consumeRun(redemption, budget);
        }
    }

    @Test
    void rejectsNativeHandlersThatSkipAssignedGatewayOrBusinessAuthority() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(NativeBypassCalls.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(4);
        assertThat(result.hasViolation()).isTrue();
    }

    @Test
    void rejectsDirectRepositoryMutationsThatBypassTheDispatchWriter() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(RepositoryBypassCalls.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(7);
        assertThat(result.hasViolation()).isTrue();
    }

    @Test
    void rejectsMethodReferencesToDirectRepositoryMutations() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(RepositoryBypassReferences.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(1);
        assertThat(result.hasViolation()).isTrue();
    }

    static class RepositoryBypassCalls {
        void invoke(AiModelDispatchRepository repository, RunPreparation preparation, RunRedemption redemption,
                ManagementPreparation managementPreparation, ManagementRedemption managementRedemption,
                Expected expected, Instant cutoff, UUID intent, RuntimeProxyCertificateClaims peer) {
            repository.reserveRun(preparation, expected, cutoff);
            repository.reserveManagement(managementPreparation, cutoff);
            repository.insertRunIntent(preparation, expected, cutoff);
            repository.insertManagementIntent(managementPreparation, cutoff);
            repository.consumeRunIntent(redemption, expected, cutoff);
            repository.consumeAssignedRunIntent(redemption, expected, intent, "GATEWAY_RUN", peer, cutoff);
            repository.consumeManagementIntent(managementRedemption, cutoff);
        }
    }

    @Test
    void rejectsSessionMutationsOutsideFreshAuthorityAndItsWriter() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(SessionBypassCalls.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(3);
        assertThat(result.hasViolation()).isTrue();
    }

    @Test
    void rejectsMethodReferencesToSessionMutationBypasses() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(SessionBypassReferences.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(3);
        assertThat(result.hasViolation()).isTrue();
    }

    static class SessionBypassCalls {
        void invoke(AiModelManagementSessionRepository repository, AiModelManagementSessionWriter writer, Spec spec,
                UUID sessionId, Instant cutoff, AiRuntimeOperationBudget budget) {
            repository.insert(spec, cutoff);
            repository.close(sessionId, cutoff);
            writer.create(spec, budget);
        }
    }

    static class SessionBypassReferences {
        java.util.function.BiFunction<Spec, Instant, ?> insert(AiModelManagementSessionRepository repository) {
            return repository::insert;
        }

        java.util.function.BiFunction<UUID, Instant, ?> close(AiModelManagementSessionRepository repository) {
            return repository::close;
        }

        java.util.function.BiFunction<Spec, AiRuntimeOperationBudget, ?> create(AiModelManagementSessionWriter writer) {
            return writer::create;
        }
    }

    interface Reservation {
        int apply(RunPreparation preparation, Expected expected, Instant cutoff);
    }

    static class RepositoryBypassReferences {
        Reservation reference(AiModelDispatchRepository repository) {
            return repository::reserveRun;
        }
    }

    static class NativeBypassCalls {
        void invoke(AiModelDispatchWriter writer, RunRedemption redemption, UUID actor, RuntimePeer peer,
                AiRuntimeOperationBudget budget, AiModelRunDispatchService service, RunDispatchEnvelope envelope,
                UUID correlation) {
            writer.consumeRun(redemption, actor, budget);
            writer.consumeRun(redemption, actor, peer, budget);
            service.consume(envelope, correlation, budget);
            service.consume(envelope, correlation, peer, budget);
        }
    }

    static class BypassReferences {
        java.util.function.BiFunction<RunPreparation, AiRuntimeOperationBudget, ?> preparation(
                AiModelDispatchWriter writer) {
            return writer::prepareRun;
        }

        java.util.function.BiFunction<RunRedemption, AiRuntimeOperationBudget, ?> redemption(
                AiModelDispatchWriter writer) {
            return writer::consumeRun;
        }
    }

    @Test
    void rejectsAllNativeManagementBusinessPublicationAndProtectedReadBypasses() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(ManagementBypassCalls.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(12);
        assertThat(result.hasViolation()).isTrue();
    }

    @Test
    void rejectsManagementLegacyMethodReferences() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(ManagementBypassReferences.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(2);
        assertThat(result.hasViolation()).isTrue();
    }

    static class ManagementBypassCalls {
        void invoke(AiModelDispatchWriter writer, ManagementPreparation q, ManagementRedemption r,
                com.otilm.ai.runtime.protocol.ManagementDispatchEnvelope envelope,
                com.otilm.core.service.ai.AiModelManagementDispatchService service, AiModelDispatchRepository models,
                com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository registry,
                com.otilm.core.dao.repository.ai.AiModelManagementGatewayRepository assignments,
                com.otilm.core.dao.repository.ai.AiModelManagementOutcomeRepository outcomes,
                com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter protectedReader,
                com.otilm.core.service.ai.AiRuntimeManagementWire.OutcomeRequest outcome,
                com.otilm.core.model.ai.AiModelRunOutcome.DerivedResult derived,
                com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Observation observation, UUID id,
                RuntimePeer peer, Instant cutoff, AiRuntimeOperationBudget budget) {
            writer.prepareManagement(q, budget);
            writer.consumeManagement(r, budget);
            writer.prepareManagement(q, id, budget);
            writer.consumeManagement(r, id, peer, budget);
            service.consume(envelope, id, peer, budget);
            models.consumeAssignedManagementIntent(r, id, peer.role().name(), peer.subject(), cutoff);
            registry.observe(observation, cutoff);
            assignments.assign(id, peer.role().name(), peer.subject(), cutoff);
            outcomes.append(outcome, derived, peer.role().name(), peer.subject(), cutoff);
            protectedReader.read(id, id, id, budget);
            protectedReader.append(outcome, peer, budget);
            models.preparedManagementById(id, id);
        }
    }

    static class ManagementBypassReferences {
        java.util.function.BiFunction<ManagementPreparation, AiRuntimeOperationBudget, ?> legacy(
                AiModelDispatchWriter writer) {
            return writer::prepareManagement;
        }

        OutcomeAppend append(com.otilm.core.service.writer.ai.AiModelManagementOutcomeWriter writer) {
            return writer::append;
        }
    }

    interface OutcomeAppend {
        Object append(com.otilm.core.service.ai.AiRuntimeManagementWire.OutcomeRequest request, RuntimePeer peer,
                AiRuntimeOperationBudget budget);
    }

    @Test
    void concreteNativePhaseFactoriesCannotBeCalledByArbitraryProductionOwners() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter()
                        .importClasses(com.otilm.core.service.ai.AiNativeGatewayOperationsBypass.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(2);
        assertThat(result.hasViolation()).isTrue();
    }

    @Test
    void onlyTheConcreteCurrentControllerPublicationOwnerMayObserveGatewayRegistries() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter()
                        .importClasses(com.otilm.core.service.ai.AiRuntimeControllerRegistrationServiceImpl.class));
        assertThat(result.hasViolation()).isFalse();
    }

    @Test
    void arbitraryOwnersCannotPublishGatewayMembershipOrWriteItsRepository() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(GatewayPublicationBypass.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(3);
        assertThat(result.hasViolation()).isTrue();
    }

    @Test
    void anObserveMethodReferenceCannotHideAnArbitraryManagementPublisher() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(GatewayPublicationBypassReference.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(1);
        assertThat(result.hasViolation()).isTrue();
    }

    static class GatewayPublicationBypass {
        void invoke(com.otilm.core.service.writer.ai.AiRuntimeGatewayRegistrationWriter run,
                com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter management,
                com.otilm.core.dao.repository.ai.AiRuntimeGatewayRepository repository,
                com.otilm.core.model.ai.AiRuntimeGatewayState.Observation runObservation,
                com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Observation managementObservation,
                AiRuntimeOperationBudget budget) {
            run.observe(runObservation, budget);
            management.observe(managementObservation, budget);
            repository.observe("GATEWAY_RUN", runObservation);
        }
    }

    static class GatewayPublicationBypassReference {
        java.util.function.BiFunction<com.otilm.core.model.ai.AiRuntimeManagementGatewayState.Observation, AiRuntimeOperationBudget, ?> reference(
                com.otilm.core.service.writer.ai.AiRuntimeManagementGatewayWriter writer) {
            return writer::observe;
        }
    }

    @Test
    void rejectsRunOutcomeAppendOutsideTheNativeHelper() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(RunOutcomeBypassCalls.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(1);
        assertThat(result.hasViolation()).isTrue();
    }

    @Test
    void rejectsRunOutcomeAppendMethodReferencesOutsideTheNativeHelper() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(RunOutcomeBypassReferences.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(1);
        assertThat(result.hasViolation()).isTrue();
    }

    static class RunOutcomeBypassCalls {
        void invoke(com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter writer,
                com.otilm.core.service.ai.AiRuntimeGatewayWire.OutcomeRequest request, RuntimePeer peer,
                AiRuntimeOperationBudget budget) {
            writer.append(request, peer, budget);
        }
    }

    static class RunOutcomeBypassReferences {
        RunOutcomeAppend append(com.otilm.core.service.writer.ai.AiModelRunOutcomeWriter writer) {
            return writer::append;
        }
    }

    interface RunOutcomeAppend {
        Object append(com.otilm.core.service.ai.AiRuntimeGatewayWire.OutcomeRequest request, RuntimePeer peer,
                AiRuntimeOperationBudget budget);
    }

    @Test
    void cleanupCompletionCannotBeCalledByArbitraryProductionOwners() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(CleanupBypassCalls.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(2);
        assertThat(result.hasViolation()).isTrue();
    }

    @Test
    void cleanupCompletionMethodReferencesCannotEscapeTheClosedCallers() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(CleanupBypassReferences.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(2);
        assertThat(result.hasViolation()).isTrue();
    }

    static class CleanupBypassCalls {
        void invoke(com.otilm.core.service.writer.ai.AiRuntimeCleanupWriter writer,
                com.otilm.core.dao.repository.ai.AiRuntimeCleanupRepository repository, Expected expected,
                String jobUid, java.util.Set<com.otilm.core.model.ai.AiRuntimeState.WorkloadRef> workloads,
                AiRuntimeOperationBudget budget, Instant at) {
            writer.complete(expected, jobUid, workloads, budget);
            repository.complete(expected, jobUid, "[]", at, at);
        }
    }

    static class CleanupBypassReferences {
        CleanupCompletion writer(com.otilm.core.service.writer.ai.AiRuntimeCleanupWriter writer) {
            return writer::complete;
        }

        CleanupStatement repository(com.otilm.core.dao.repository.ai.AiRuntimeCleanupRepository repository) {
            return repository::complete;
        }
    }

    interface CleanupCompletion {
        Object complete(Expected expected, String jobUid,
                java.util.Set<com.otilm.core.model.ai.AiRuntimeState.WorkloadRef> workloads,
                AiRuntimeOperationBudget budget);
    }

    interface CleanupStatement {
        Object complete(Expected expected, String jobUid, String workloads, Instant at, Instant cutoff);
    }

    @Test
    void nativeStartupConfirmationIsRestrictedToTheExactConfiguration() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(NativeStartupBypassCalls.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(1);
        assertThat(result.hasViolation()).isTrue();
    }

    @Test
    void nativeStartupConfirmationReferencesCannotEscapeTheExactConfiguration() {
        var result = currentPrincipalAndActorChecksCannotBeBypassed
                .evaluate(new ClassFileImporter().importClasses(NativeStartupBypassReferences.class));
        assertThat(result.getFailureReport().getDetails()).hasSize(1);
        assertThat(result.hasViolation()).isTrue();
    }

    static class NativeStartupBypassCalls {
        void invoke(com.otilm.core.service.writer.ai.AiRuntimeNativeStartupWriter writer,
                AiRuntimeOperationBudget budget) {
            writer.disableAndConfirm(budget);
        }
    }

    static class NativeStartupBypassReferences {
        java.util.function.Consumer<AiRuntimeOperationBudget> reference(
                com.otilm.core.service.writer.ai.AiRuntimeNativeStartupWriter writer) {
            return writer::disableAndConfirm;
        }
    }

    @Test
    void rejectsStartupManagementMutations_whenTheCallerIsOutsideTheClosedWriter() {
        // given
        var classes = new ClassFileImporter().importClasses(StartupManagementBypassCalls.class);

        // when
        var result = currentPrincipalAndActorChecksCannotBeBypassed.evaluate(classes);

        // then
        assertThat(result.getFailureReport().getDetails()).hasSize(2);
        assertThat(result.hasViolation()).isTrue();
    }

    @Test
    void rejectsStartupManagementMutationReferences_whenTheCallerIsOutsideTheClosedWriter() {
        // given
        var classes = new ClassFileImporter().importClasses(StartupManagementBypassReferences.class);

        // when
        var result = currentPrincipalAndActorChecksCannotBeBypassed.evaluate(classes);

        // then
        assertThat(result.getFailureReport().getDetails()).hasSize(2);
        assertThat(result.hasViolation()).isTrue();
    }

    static class StartupManagementBypassCalls {
        void invoke(com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository repository, Instant cutoff) {
            repository.startupDeny(1, cutoff);
            repository.clearObservations();
        }
    }

    static class StartupManagementBypassReferences {
        java.util.function.BiFunction<Long, Instant, Integer> deny(
                com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository repository) {
            return repository::startupDeny;
        }

        java.util.function.IntSupplier clear(
                com.otilm.core.dao.repository.ai.AiRuntimeManagementGatewayRepository repository) {
            return repository::clearObservations;
        }
    }

    @Test
    void rejectsLegacyRuntimeBudgetCalls_whenCallerIsOutsideTheTrustedComponents() {
        // given
        var classes = new ClassFileImporter().importClasses(LegacyRuntimeBudgetCalls.class);

        // when
        var result = currentPrincipalAndActorChecksCannotBeBypassed.evaluate(classes);

        // then
        assertThat(result.hasViolation()).isTrue();
        assertThat(result.getFailureReport().getDetails()).hasSize(8);
    }

    @Test
    void rejectsLegacyRuntimeBudgetReferences_whenCallerIsOutsideTheTrustedComponents() {
        // given
        var classes = new ClassFileImporter().importClasses(LegacyRuntimeBudgetReferences.class);

        // when
        var result = currentPrincipalAndActorChecksCannotBeBypassed.evaluate(classes);

        // then
        assertThat(result.hasViolation()).isTrue();
        assertThat(result.getFailureReport().getDetails()).hasSize(8);
    }

    static class LegacyRuntimeBudgetCalls {
        void invoke(com.otilm.core.service.ai.AiRuntimeKernel kernel,
                com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation observation, Expected expected,
                com.otilm.core.model.ai.AiRuntimeState.WorkloadRef ref,
                com.otilm.core.model.ai.AiRuntimeState.ClaimBinding claim,
                com.otilm.core.service.writer.ai.AiRuntimeWriter writer) {
            kernel.snapshot(expected.runId());
            kernel.control();
            kernel.observe(observation);
            kernel.invalidate(expected);
            kernel.bootstrap(expected, ref);
            kernel.heartbeat(claim, 1);
            writer.observe(observation);
            writer.invalidate(expected);
        }
    }

    static class LegacyRuntimeBudgetReferences {
        java.util.function.Function<com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation, ?> writerObserve(
                com.otilm.core.service.writer.ai.AiRuntimeWriter writer) {
            return writer::observe;
        }

        java.util.function.Function<Expected, ?> writerInvalidate(
                com.otilm.core.service.writer.ai.AiRuntimeWriter writer) {
            return writer::invalidate;
        }

        java.util.function.Function<UUID, ?> snapshot(com.otilm.core.service.ai.AiRuntimeKernel kernel) {
            return kernel::snapshot;
        }

        java.util.function.Supplier<?> control(com.otilm.core.service.ai.AiRuntimeKernel kernel) {
            return kernel::control;
        }

        java.util.function.Function<com.otilm.core.model.ai.AiRuntimeState.WorkloadObservation, ?> observe(
                com.otilm.core.service.ai.AiRuntimeKernel kernel) {
            return kernel::observe;
        }

        java.util.function.Function<Expected, ?> invalidate(com.otilm.core.service.ai.AiRuntimeKernel kernel) {
            return kernel::invalidate;
        }

        java.util.function.BiFunction<Expected, com.otilm.core.model.ai.AiRuntimeState.WorkloadRef, ?> bootstrap(
                com.otilm.core.service.ai.AiRuntimeKernel kernel) {
            return kernel::bootstrap;
        }

        java.util.function.BiFunction<com.otilm.core.model.ai.AiRuntimeState.ClaimBinding, Long, ?> heartbeat(
                com.otilm.core.service.ai.AiRuntimeKernel kernel) {
            return kernel::heartbeat;
        }
    }
}
