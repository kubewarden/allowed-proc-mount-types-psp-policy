[![Kubewarden Policy Repository](https://github.com/kubewarden/community/blob/main/badges/kubewarden-policies.svg)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#policy-scope)
[![Stable](https://img.shields.io/badge/status-stable-brightgreen?style=for-the-badge)](https://github.com/kubewarden/community/blob/main/REPOSITORIES.md#stable)

# Kubewarden policy psp-allowed-proc-mount-types

## Description

Replacement for the Kubernetes Pod Security Policy that controls the
usage of proc mount types in containers within a pod.

## Settings

This policy works by defining what proc mount types are allowed in containers. They can be left
empty (defaulted by Kubernetes), `Default` or `Unmasked`. This policy protects against pods that
contain at least one container with `Unmasked` proc mount type, that can potentially expose host
information to the container.

The following setting keys are accepted for this policy:

* `allow_unmasked_proc_mount_type`: allows the containers, init containers or ephemeral containers
  within a pod to set `.spec.securityContext.procMount` to `Unmasked`. Otherwise, the pod or the
  ephemeral request subresource request will be rejected.

`allow_unmasked_proc_mount_type` is `false` by default.
