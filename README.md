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

## License

```
Copyright (C) 2021 Rafael Fernández López <rfernandezlopez@suse.com>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```
