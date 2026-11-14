# Kubernetes 1.36 field inventory

The live OpenAPI inventory is frozen for this version. Unlisted API versions are unsupported. Every field below is either constrained by the policy or required absent. Nested fixed objects are constrained explicitly; Kubernetes validates union structure.

## PodSpec

Constrained: `activeDeadlineSeconds`, `automountServiceAccountToken`, `containers`, `dnsConfig`, `dnsPolicy`, `enableServiceLinks`, `hostIPC`, `hostNetwork`, `hostPID`, `nodeName`, `os`, `preemptionPolicy`, `priority`, `restartPolicy`, `runtimeClassName`, `schedulerName`, `securityContext`, `serviceAccount`, `serviceAccountName`, `terminationGracePeriodSeconds`, `tolerations`, `volumes`.

Required absent: `affinity`, `ephemeralContainers`, `hostAliases`, `hostUsers`, `hostname`, `hostnameOverride`, `imagePullSecrets`, `initContainers`, `nodeSelector`, `overhead`, `priorityClassName`, `readinessGates`, `resourceClaims`, `resources`, `schedulingGates`, `schedulingGroup`, `setHostnameAsFQDN`, `shareProcessNamespace`, `subdomain`, `topologySpreadConstraints`.

## PodSecurityContext

Constrained: `fsGroup`, `runAsGroup`, `runAsNonRoot`, `runAsUser`, `seccompProfile`.

Required absent: `appArmorProfile`, `fsGroupChangePolicy`, `seLinuxChangePolicy`, `seLinuxOptions`, `supplementalGroups`, `supplementalGroupsPolicy`, `sysctls`, `windowsOptions`.

## Container

Constrained: `args`, `command`, `image`, `imagePullPolicy`, `name`, `resources`, `securityContext`, `stdin`, `stdinOnce`, `terminationMessagePath`, `terminationMessagePolicy`, `tty`, `volumeMounts`.

Required absent: `env`, `envFrom`, `lifecycle`, `livenessProbe`, `ports`, `readinessProbe`, `resizePolicy`, `restartPolicy`, `restartPolicyRules`, `startupProbe`, `volumeDevices`, `workingDir`.

## SecurityContext

Constrained: `allowPrivilegeEscalation`, `capabilities`, `privileged`, `readOnlyRootFilesystem`.

Required absent: `appArmorProfile`, `procMount`, `runAsGroup`, `runAsNonRoot`, `runAsUser`, `seLinuxOptions`, `seccompProfile`, `windowsOptions`.

## Volume

Constrained: `emptyDir`, `name`.

Required absent: `awsElasticBlockStore`, `azureDisk`, `azureFile`, `cephfs`, `cinder`, `configMap`, `csi`, `downwardAPI`, `ephemeral`, `fc`, `flexVolume`, `flocker`, `gcePersistentDisk`, `gitRepo`, `glusterfs`, `hostPath`, `image`, `iscsi`, `nfs`, `persistentVolumeClaim`, `photonPersistentDisk`, `portworxVolume`, `projected`, `quobyte`, `rbd`, `scaleIO`, `secret`, `storageos`, `vsphereVolume`.

## VolumeMount

Constrained: `mountPath`, `name`, `readOnly`.

Required absent: `mountPropagation`, `recursiveReadOnly`, `subPath`, `subPathExpr`.

## ResourceRequirements

Constrained: `limits` and `requests` each contain exactly cpu, memory and ephemeral-storage, with fixed semantic quantities. Required absent: `claims`.

## PodDNSConfig

Constrained: `nameservers` is exactly `[127.0.0.1]`. Required absent: `options`, `searches`.

## PodOS

Constrained: `name` is `linux`.

## Capabilities

Constrained: `drop` is exactly `[ALL]`; `add` is absent or empty.

## SeccompProfile

Constrained: `type` is `RuntimeDefault`. Required absent: `localhostProfile`.

## EmptyDirVolumeSource

Constrained: `medium` is `Memory`, `sizeLimit` is semantically 16Mi. `mode` is not a field in this exact API version.

The exact v1.36 inventory lacks PodSpec.evictionResponders, EmptyDirVolumeSource.mode and VolumeMount.bindMountOptions. Each current-target session must verify the exact server version and complete OpenAPI hash/property inventory. Before the original scratch-mode API_PRUNED control, all three unknown properties must fail a STRICT server dryrun with their exact unknown-field reason and be pruned by a separate controlled IGNORE dryrun while the complete recognized profile stays equal. IGNORE is never used for an actual Pod create or a fallback after failure. These native current-target controls remain unexecuted until separately released; this inventory does not cover a future API where those fields exist.

## Toleration

Constrained: exactly the two default node not-ready/unreachable tolerations, each with `key` from the fixed pair, `operator=Exists`, `effect=NoExecute`, `tolerationSeconds=300`; `value` is absent or empty. Distinct keys are required.
