// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Ergonomic builders for constructing OCSF events.
//!
//! Each event class has a builder that takes a `EventContext` reference
//! and provides chainable methods for setting event fields.

/// Generate the shared `severity`, `status`, and `message` setter methods that
/// appear identically on every OCSF event builder in this crate.
///
/// # Usage
/// ```ignore
/// impl_builder_setters!(MyBuilder);            // severity + status + message
/// impl_builder_setters!(MyBuilder, no_status); // severity + message only
/// ```
macro_rules! impl_builder_setters {
    ($builder:ident) => {
        impl<'a> $builder<'a> {
            /// Set the event severity.
            #[must_use]
            pub fn severity(mut self, id: $crate::enums::SeverityId) -> Self {
                self.severity = id;
                self
            }
            /// Set the overall event status.
            #[must_use]
            pub fn status(mut self, id: $crate::enums::StatusId) -> Self {
                self.status = Some(id);
                self
            }
            /// Set a human-readable event message.
            #[must_use]
            pub fn message(mut self, msg: impl Into<String>) -> Self {
                self.message = Some(msg.into());
                self
            }
        }
    };
    ($builder:ident, no_status) => {
        impl<'a> $builder<'a> {
            /// Set the event severity.
            #[must_use]
            pub fn severity(mut self, id: $crate::enums::SeverityId) -> Self {
                self.severity = id;
                self
            }
            /// Set a human-readable event message.
            #[must_use]
            pub fn message(mut self, msg: impl Into<String>) -> Self {
                self.message = Some(msg.into());
                self
            }
        }
    };
}

/// Generate the `activity` setter used by every event builder that carries an
/// `activity` field.
macro_rules! impl_activity_setter {
    ($builder:ident) => {
        impl<'a> $builder<'a> {
            /// Set the event activity identifier.
            #[must_use]
            pub fn activity(mut self, id: $crate::enums::ActivityId) -> Self {
                self.activity = id;
                self
            }
        }
    };
}

/// Generate `action` and `disposition` setters shared by network, HTTP, SSH,
/// process, and detection-finding builders.
macro_rules! impl_action_disposition_setters {
    ($builder:ident) => {
        impl<'a> $builder<'a> {
            /// Set the action taken.
            #[must_use]
            pub fn action(mut self, id: $crate::enums::ActionId) -> Self {
                self.action = Some(id);
                self
            }
            /// Set the disposition of the action.
            #[must_use]
            pub fn disposition(mut self, id: $crate::enums::DispositionId) -> Self {
                self.disposition = Some(id);
                self
            }
        }
    };
}

/// Generate the `actor_process` setter shared by network, HTTP, SSH, and
/// process-activity builders.
macro_rules! impl_actor_process_setter {
    ($builder:ident) => {
        impl<'a> $builder<'a> {
            /// Set the acting process.
            #[must_use]
            pub fn actor_process(mut self, process: $crate::objects::Process) -> Self {
                self.actor = Some($crate::objects::Actor::process(process));
                self
            }
        }
    };
}

/// Generate the `dst_endpoint` setter shared by network, HTTP, and SSH builders.
macro_rules! impl_dst_endpoint_setter {
    ($builder:ident) => {
        impl<'a> $builder<'a> {
            /// Set the destination endpoint.
            #[must_use]
            pub fn dst_endpoint(mut self, endpoint: $crate::objects::Endpoint) -> Self {
                self.dst_endpoint = Some(endpoint);
                self
            }
        }
    };
}

/// Generate the `src_endpoint_addr` setter shared by network and SSH builders.
macro_rules! impl_src_endpoint_addr_setter {
    ($builder:ident) => {
        impl<'a> $builder<'a> {
            /// Set the source endpoint from a raw IP address and port.
            #[must_use]
            pub fn src_endpoint_addr(mut self, ip: std::net::IpAddr, port: u16) -> Self {
                self.src_endpoint = Some($crate::objects::Endpoint::from_ip(ip, port));
                self
            }
        }
    };
}

mod api_activity;
mod authentication;
mod base;
mod config;
mod finding;
mod http;
mod lifecycle;
mod network;
mod process;
mod ssh;

pub use api_activity::ApiActivityBuilder;
pub use authentication::AuthenticationBuilder;
pub use base::BaseEventBuilder;
pub use config::ConfigStateChangeBuilder;
pub use finding::DetectionFindingBuilder;
pub use http::HttpActivityBuilder;
pub use lifecycle::AppLifecycleBuilder;
pub use network::NetworkActivityBuilder;
pub use process::ProcessActivityBuilder;
pub use ssh::SshActivityBuilder;

use std::net::IpAddr;
use std::sync::Arc;

use crate::OCSF_VERSION;
use crate::enums::StatusId;
use crate::events::base_event::BaseEventData;
use crate::objects::{Container, Device, Endpoint, Image, Metadata, Product, ResourceDetails};

/// Which `OpenShell` component produced an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EventOrigin {
    /// The supervisor process enforcing sandbox policy.
    Supervisor,
    /// The gateway process, which has no sandbox or container of its own.
    Gateway {
        /// Operator-assigned gateway name (`[openshell.gateway] name`).
        name: String,
    },
}

/// Immutable context created once at sandbox startup.
///
/// Passed to every event builder to populate shared OCSF fields
/// (metadata, container, device, proxy endpoint).
#[derive(Debug, Clone)]
pub struct EventContext {
    /// Sandbox unique identifier.
    pub sandbox_id: String,
    /// Sandbox display name.
    pub sandbox_name: String,
    /// Container image reference.
    pub container_image: String,
    /// Immutable workload image ID resolved by the compute driver at launch.
    pub container_image_uid: Option<String>,
    /// Device hostname.
    pub hostname: String,
    /// Product version string.
    pub product_version: String,
    /// Proxy listen IP address.
    pub proxy_ip: IpAddr,
    /// Proxy listen port.
    pub proxy_port: u16,
    /// Which component is emitting.
    pub origin: EventOrigin,
}

/// Event context borrowed from the caller or shared by a hosted sandbox
/// instance.
///
/// Builders accept either form, so events attributed to a hosted sandbox
/// instance need not leak a `'static` context for each instance.
#[derive(Debug, Clone)]
pub enum ContextRef<'a> {
    Borrowed(&'a EventContext),
    Shared(Arc<EventContext>),
}

impl std::ops::Deref for ContextRef<'_> {
    type Target = EventContext;

    fn deref(&self) -> &EventContext {
        match self {
            Self::Borrowed(context) => context,
            Self::Shared(context) => context,
        }
    }
}

impl<'a> From<&'a EventContext> for ContextRef<'a> {
    fn from(context: &'a EventContext) -> Self {
        Self::Borrowed(context)
    }
}

impl From<Arc<EventContext>> for ContextRef<'_> {
    fn from(context: Arc<EventContext>) -> Self {
        Self::Shared(context)
    }
}

impl<'a> From<&'a ContextRef<'_>> for ContextRef<'a> {
    fn from(context: &'a ContextRef<'_>) -> Self {
        Self::Borrowed(context)
    }
}

impl EventContext {
    /// Build the OCSF `Metadata` object for any event.
    #[must_use]
    pub fn metadata(&self, profiles: &[&str]) -> Metadata {
        let product = match self.origin {
            EventOrigin::Supervisor => Product::openshell_sandbox(&self.product_version),
            EventOrigin::Gateway { .. } => Product::openshell_gateway(&self.product_version),
        };
        let profiles: Vec<String> = profiles
            .iter()
            .filter(|p| **p != "container" || matches!(self.origin, EventOrigin::Supervisor))
            .map(|s| (*s).to_string())
            .collect();
        Metadata {
            version: OCSF_VERSION.to_string(),
            product,
            profiles,
            uid: Some(uuid::Uuid::new_v4().to_string()),
            log_source: None,
            correlation_uid: None,
        }
    }

    /// Build the OCSF `Container` object for an in-sandbox supervisor.
    #[must_use]
    pub fn container(&self) -> Option<Container> {
        if self.sandbox_id.is_empty() || matches!(self.origin, EventOrigin::Gateway { .. }) {
            return None;
        }
        Some(Container {
            name: self.sandbox_name.clone(),
            uid: Some(self.sandbox_id.clone()),
            image: self
                .container_image_uid
                .as_ref()
                .filter(|uid| !uid.trim().is_empty())
                .map(|uid| Image {
                    uid: uid.clone(),
                    name: self.container_image.clone(),
                }),
        })
    }

    /// Build the OCSF `Device` object, stamped with the host OS this build runs
    /// on (Linux for the in-sandbox supervisor, Windows for the MXC gateway).
    #[must_use]
    pub fn device(&self) -> Device {
        let mut device = match &self.origin {
            EventOrigin::Supervisor => Device::for_current_os(&self.hostname),
            EventOrigin::Gateway { name } => Device::gateway(&self.hostname, name),
        };
        device.container = self.container();
        device
    }

    /// Identify the affected sandbox without claiming it runs on the gateway device.
    pub(crate) fn add_sandbox_resource(&self, resources: &mut Vec<ResourceDetails>) {
        if self.sandbox_id.is_empty() || !matches!(self.origin, EventOrigin::Gateway { .. }) {
            return;
        }
        let existing = resources.iter().position(|r| {
            r.type_label.as_deref() == Some("sandbox") && r.uid.as_deref() == Some(&self.sandbox_id)
        });
        let mut resource = existing.map_or_else(
            || ResourceDetails::new("sandbox", &self.sandbox_id),
            |index| resources.remove(index),
        );
        if resource.name.is_none() && !self.sandbox_name.is_empty() {
            resource.name = Some(self.sandbox_name.clone());
        }
        // Keep the context sandbox first when an event also names other targets.
        resources.insert(0, resource);
    }

    /// Build the `proxy_endpoint` object for the Network Proxy profile.
    #[must_use]
    pub fn proxy_endpoint(&self) -> Endpoint {
        Endpoint::from_ip(self.proxy_ip, self.proxy_port)
    }

    /// Apply the fields common to every builder's `build()` method onto `base`:
    /// optional status, optional message, device info, and container info.
    pub fn apply_common_fields(
        &self,
        base: &mut BaseEventData,
        status: Option<StatusId>,
        message: Option<String>,
    ) {
        if let Some(s) = status {
            base.set_status(s);
        }
        if let Some(m) = message {
            base.set_message(m);
        }
        base.set_device(self.device());
        // These classes have no resources attribute. Keep gateway attribution
        // in the standard extension object rather than on the gateway device.
        if matches!(self.origin, EventOrigin::Gateway { .. })
            && !self.sandbox_id.is_empty()
            && !matches!(base.class_uid, 6003 | 2004)
        {
            base.add_unmapped("sandbox_id", self.sandbox_id.clone());
            base.add_unmapped("sandbox_name", self.sandbox_name.clone());
        }
    }
}

#[cfg(test)]
pub(crate) fn test_sandbox_context() -> EventContext {
    EventContext {
        sandbox_id: "sandbox-abc123".to_string(),
        sandbox_name: "my-sandbox".to_string(),
        container_image: "ghcr.io/openshell/sandbox:latest".to_string(),
        container_image_uid: None,
        hostname: "sandbox-abc123".to_string(),
        product_version: "0.1.0".to_string(),
        proxy_ip: "10.42.0.1".parse().unwrap(),
        proxy_port: 3128,
        origin: EventOrigin::Supervisor,
    }
}

#[cfg(test)]
pub(crate) fn test_gateway_context() -> EventContext {
    EventContext {
        sandbox_id: String::new(),
        sandbox_name: String::new(),
        container_image: String::new(),
        container_image_uid: None,
        hostname: "openshell-gateway-0".to_string(),
        product_version: "0.1.0".to_string(),
        proxy_ip: IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        proxy_port: 0,
        origin: EventOrigin::Gateway {
            name: "openshell".to_string(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolved_container_image_matches_schema() {
        use crate::validation::schema::{
            load_object_schema, validate_known_fields, validate_required_fields,
        };
        let mut ctx = test_sandbox_context();
        ctx.container_image_uid = Some("sha256:resolved-workload".into());
        let json = serde_json::to_value(ctx.container().unwrap().image.unwrap()).unwrap();
        let schema = load_object_schema("image");
        validate_known_fields(&json, &schema);
        validate_required_fields(&json, &schema);
        assert_eq!(json["uid"], "sha256:resolved-workload");
    }

    #[test]
    fn sandbox_identity_matches_every_event_class_schema() {
        use crate::enums::HttpMethod;
        use crate::objects::{HttpRequest, Service, User};
        use crate::validation::schema::{
            load_class_schema, load_object_schema, validate_known_fields, validate_required_fields,
        };

        let ctx = test_sandbox_context();
        let events = [
            ("base_event", BaseEventBuilder::new(&ctx).build()),
            (
                "network_activity",
                NetworkActivityBuilder::new(&ctx)
                    .dst_endpoint(Endpoint::from_domain("example.com", 443))
                    .build(),
            ),
            (
                "http_activity",
                HttpActivityBuilder::new(&ctx)
                    .http_request(HttpRequest {
                        http_method: HttpMethod::Get,
                        url: None,
                    })
                    .build(),
            ),
            (
                "ssh_activity",
                SshActivityBuilder::new(&ctx)
                    .src_endpoint_addr("192.0.2.1".parse().unwrap(), 48201)
                    .build(),
            ),
            (
                "process_activity",
                ProcessActivityBuilder::new(&ctx).build(),
            ),
            (
                "detection_finding",
                DetectionFindingBuilder::new(&ctx).build(),
            ),
            (
                "application_lifecycle",
                AppLifecycleBuilder::new(&ctx).build(),
            ),
            (
                "device_config_state_change",
                ConfigStateChangeBuilder::new(&ctx).build(),
            ),
            (
                "api_activity",
                ApiActivityBuilder::new(&ctx, "test").build(),
            ),
            (
                "authentication",
                AuthenticationBuilder::new(&ctx, User::unidentified(), Service::new("gateway"))
                    .build(),
            ),
        ];
        for (class_name, event) in events {
            let json = event.to_json().unwrap();
            let class = load_class_schema(class_name);
            // Check the identity fields against each class independently of
            // unrelated class-specific payload attributes.
            validate_known_fields(
                &serde_json::json!({
                    "device": json["device"], "metadata": json["metadata"],
                }),
                &class,
            );
            validate_required_fields(&json, &class);
            assert!(json.get("container").is_none(), "{class_name}");
            if class_name == "authentication" {
                assert!(json["device"].get("container").is_none());
                assert!(event.sandbox_id().is_none());
                continue;
            }
            assert!(
                json["metadata"]["profiles"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|p| p == "container"),
                "{class_name}"
            );
            let device = &json["device"];
            let container = &device["container"];
            for (object, value) in [("device", device), ("container", container)] {
                let schema = load_object_schema(object);
                validate_known_fields(value, &schema);
                validate_required_fields(value, &schema);
            }
            assert_eq!(container["uid"], ctx.sandbox_id, "{class_name}");
            assert_eq!(container["name"], ctx.sandbox_name, "{class_name}");
            assert!(
                container.get("image").is_none(),
                "image reference alone is insufficient"
            );
            let decoded: crate::OcsfEvent = serde_json::from_value(json.clone()).unwrap();
            assert_eq!(decoded.to_json().unwrap(), json, "{class_name}");
        }
    }

    #[test]
    fn test_sandbox_context_metadata() {
        let ctx = test_sandbox_context();
        let meta = ctx.metadata(&["security_control", "container"]);
        assert_eq!(meta.version, "1.8.0");
        assert_eq!(meta.product.name, "OpenShell Sandbox Supervisor");
        assert_eq!(meta.profiles.len(), 2);
        let uid = meta.uid.as_deref().expect("uid is set");
        assert!(!uid.is_empty());
        assert_ne!(uid, "sandbox-abc123");
    }

    #[test]
    fn test_emitted_device_matches_vendored_schema() {
        use crate::validation::schema::{
            load_object_schema, validate_enum_value, validate_required_fields,
        };

        let device = serde_json::to_value(test_sandbox_context().device()).unwrap();
        let schema = load_object_schema("device");
        validate_required_fields(&device, &schema);
        validate_enum_value(&device, "type_id", &schema);
    }

    #[test]
    fn test_sandbox_context_container() {
        let ctx = test_sandbox_context();
        let container = ctx.container().expect("sandbox context has a container");
        assert_eq!(container.name, "my-sandbox");
        assert_eq!(container.uid.as_deref(), Some("sandbox-abc123"));
    }

    #[test]
    fn test_sandbox_context_device() {
        let ctx = test_sandbox_context();
        let device = ctx.device();
        assert_eq!(device.hostname, "sandbox-abc123");
    }

    #[test]
    fn test_sandbox_context_proxy_endpoint() {
        let ctx = test_sandbox_context();
        let ep = ctx.proxy_endpoint();
        assert_eq!(ep.ip.as_deref(), Some("10.42.0.1"));
        assert_eq!(ep.port, Some(3128));
    }
}
