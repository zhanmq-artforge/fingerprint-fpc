//! PolicyKit authorization gate for D-Bus client requests.
//!
//! Directly addresses PR #15: Requiring PolicyKit verification for sensitive operations
//! (`EnrollStart`, `DeleteEnrolledFingers`, `DeleteEnrolledFinger`) to prevent unauthorized local privilege escalation.

use std::collections::HashMap;
use tracing::{debug, warn};
use zbus::{zvariant::Value, Connection};

use crate::error::{FpcError, Result};

/// Standard PolicyKit actions shipped by fprintd policy file.
pub const ACTION_ENROLL: &str = "net.reactivated.fprint.device.enroll";
pub const ACTION_SET_USERNAME: &str = "net.reactivated.fprint.device.setusername";
pub const ACTION_VERIFY: &str = "net.reactivated.fprint.device.verify";

/// Check whether the D-Bus caller is authorized for the requested PolicyKit action.
///
/// # Errors
/// Returns [`FpcError::PolkitDenied`] if unauthorized or verification fails.
pub async fn check_authorization(
    connection: &Connection,
    sender: &str,
    action_id: &str,
    interactive: bool,
) -> Result<()> {
    debug!("Checking Polkit authorization for sender {sender} on action {action_id}");

    let mut subject_details = HashMap::new();
    subject_details.insert("name".to_string(), Value::new(sender));
    let subject = ("system-bus-name", subject_details);

    let details: HashMap<String, String> = HashMap::new();
    let flags: u32 = if interactive { 1 } else { 0 };
    let cancellation_id = "";

    let message = connection
        .call_method(
            Some("org.freedesktop.PolicyKit1"),
            "/org/freedesktop/PolicyKit1/Authority",
            Some("org.freedesktop.PolicyKit1.Authority"),
            "CheckAuthorization",
            &(subject, action_id, details, flags, cancellation_id),
        )
        .await?;

    let (is_authorized, _is_challenge, _details): (bool, bool, HashMap<String, String>) = message
        .body()
        .deserialize()
        .map_err(|e| FpcError::PolkitDenied(format!("Failed to parse PolicyKit response: {e}")))?;

    if is_authorized {
        debug!("Polkit authorization granted for {sender}");
        Ok(())
    } else {
        warn!("Polkit authorization denied for {sender} on action {action_id}");
        Err(FpcError::PolkitDenied(format!(
            "Action {action_id} not permitted for caller {sender}"
        )))
    }
}
