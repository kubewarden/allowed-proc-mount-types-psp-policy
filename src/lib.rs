use guest::prelude::*;
use kubewarden_policy_sdk::wapc_guest as guest;

use k8s_openapi::api::core::v1 as apicore;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::Settings;

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;

    let pod = match serde_json::from_value::<apicore::Pod>(validation_request.request.object) {
        Ok(pod) => pod,
        Err(_) => return kubewarden::accept_request(),
    };

    let pod_spec = pod.spec.ok_or("invalid pod spec")?;
    let settings = validation_request.settings;

    if !settings.allow_unmasked_proc_mount_type && any_proc_mount_type_unmasked(&pod_spec) {
        return kubewarden::reject_request(
            Some("Pod has at least one container with Unmasked procMount".to_string()),
            None,
            None,
            None,
        );
    }

    kubewarden::accept_request()
}

fn any_proc_mount_type_unmasked(pod_spec: &apicore::PodSpec) -> bool {
    let offending_containers = pod_spec
        .containers
        .iter()
        .any(|container| is_proc_mount_type_unmasked(&container.security_context));

    let offending_init_containers = if let Some(init_containers) = &pod_spec.init_containers {
        init_containers
            .iter()
            .any(|container| is_proc_mount_type_unmasked(&container.security_context))
    } else {
        false
    };

    let offending_ephemeral_containers =
        if let Some(ephemeral_containers) = &pod_spec.ephemeral_containers {
            ephemeral_containers
                .iter()
                .any(|container| is_proc_mount_type_unmasked(&container.security_context))
        } else {
            false
        };

    offending_containers || offending_init_containers || offending_ephemeral_containers
}

fn is_proc_mount_type_unmasked(security_context: &Option<apicore::SecurityContext>) -> bool {
    if let Some(security_context) = security_context {
        security_context.proc_mount == Some("Unmasked".to_string())
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEFAULT: &str = "Default";
    const UNMASKED: &str = "Unmasked";

    #[test]
    fn pod_with_unmasked_container() {
        let pod_spec = apicore::PodSpec {
            containers: vec![apicore::Container {
                security_context: Some(apicore::SecurityContext {
                    proc_mount: Some(UNMASKED.to_string()),
                    ..apicore::SecurityContext::default()
                }),
                ..apicore::Container::default()
            }],
            ..apicore::PodSpec::default()
        };
        assert!(any_proc_mount_type_unmasked(&pod_spec));
    }

    #[test]
    fn pod_with_default_container() {
        let pod_spec = apicore::PodSpec {
            containers: vec![apicore::Container {
                security_context: Some(apicore::SecurityContext {
                    proc_mount: Some(DEFAULT.to_string()),
                    ..apicore::SecurityContext::default()
                }),
                ..apicore::Container::default()
            }],
            ..apicore::PodSpec::default()
        };
        assert!(!any_proc_mount_type_unmasked(&pod_spec));
    }

    #[test]
    fn pod_with_unmasked_init_container() {
        let pod_spec = apicore::PodSpec {
            init_containers: Some(vec![apicore::Container {
                security_context: Some(apicore::SecurityContext {
                    proc_mount: Some(UNMASKED.to_string()),
                    ..apicore::SecurityContext::default()
                }),
                ..apicore::Container::default()
            }]),
            ..apicore::PodSpec::default()
        };
        assert!(any_proc_mount_type_unmasked(&pod_spec));
    }

    #[test]
    fn pod_with_default_init_container() {
        let pod_spec = apicore::PodSpec {
            init_containers: Some(vec![apicore::Container {
                security_context: Some(apicore::SecurityContext {
                    proc_mount: Some(DEFAULT.to_string()),
                    ..apicore::SecurityContext::default()
                }),
                ..apicore::Container::default()
            }]),
            ..apicore::PodSpec::default()
        };
        assert!(!any_proc_mount_type_unmasked(&pod_spec));
    }

    #[test]
    fn pod_with_unmasked_ephemeral_container() {
        let pod_spec = apicore::PodSpec {
            ephemeral_containers: Some(vec![apicore::EphemeralContainer {
                security_context: Some(apicore::SecurityContext {
                    proc_mount: Some(UNMASKED.to_string()),
                    ..apicore::SecurityContext::default()
                }),
                ..apicore::EphemeralContainer::default()
            }]),
            ..apicore::PodSpec::default()
        };
        assert!(any_proc_mount_type_unmasked(&pod_spec));
    }

    #[test]
    fn pod_with_default_ephemeral_container() {
        let pod_spec = apicore::PodSpec {
            ephemeral_containers: Some(vec![apicore::EphemeralContainer {
                security_context: Some(apicore::SecurityContext {
                    proc_mount: Some(DEFAULT.to_string()),
                    ..apicore::SecurityContext::default()
                }),
                ..apicore::EphemeralContainer::default()
            }]),
            ..apicore::PodSpec::default()
        };
        assert!(!any_proc_mount_type_unmasked(&pod_spec));
    }
}
