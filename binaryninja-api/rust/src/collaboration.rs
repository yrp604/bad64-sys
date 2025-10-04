//! The collaboration API is **unstable** and as such will undergo breaking changes in the near future!

mod changeset;
mod file;
mod folder;
mod group;
mod merge;
mod permission;
mod project;
mod remote;
mod snapshot;
mod sync;
mod undo;
mod user;

pub use changeset::*;
pub use file::*;
pub use folder::*;
pub use group::*;
pub use merge::*;
pub use permission::*;
pub use project::*;
pub use remote::*;
pub use snapshot::*;
use std::ffi::c_char;
use std::ptr::NonNull;
pub use sync::*;
pub use user::*;

use binaryninjacore_sys::*;

use crate::rc::{Array, Ref};
use crate::string::{BnString, IntoCStr};

// TODO: Should we pull metadata and information required to call a function? Or should we add documentation
// TODO: on what functions need to have been called prior? I feel like we should make the user have to pull
// TODO: the data because they have a greater understanding of where the function is being called from.

/// Check whether the client has collaboration support.
///
/// Call this if you intend on providing divergent behavior, as otherwise you will likely
/// crash calling collaboration APIs on unsupported builds of Binary Ninja.
pub fn has_collaboration_support() -> bool {
    let mut count = 0;
    let value = unsafe { BNCollaborationGetRemotes(&mut count) };
    !value.is_null()
}

/// Get the single actively connected Remote (for ux simplification), if any
pub fn active_remote() -> Option<Ref<Remote>> {
    let value = unsafe { BNCollaborationGetActiveRemote() };
    NonNull::new(value).map(|h| unsafe { Remote::ref_from_raw(h) })
}

/// Get the enterprise remote.
///
/// NOTE: There can only be one because that it is associated with the enterprise client user.
pub fn enterprise_remote() -> Option<Ref<Remote>> {
    for remote in &known_remotes() {
        if remote.is_enterprise().unwrap_or(false) {
            return Some(remote.clone());
        }
    }
    None
}

/// Set the single actively connected Remote
pub fn set_active_remote(remote: Option<&Remote>) {
    let remote_ptr = remote.map_or(std::ptr::null_mut(), |r| r.handle.as_ptr());
    unsafe { BNCollaborationSetActiveRemote(remote_ptr) }
}

/// Load the list of known Remotes from local Settings
pub fn load_remotes() -> Result<(), ()> {
    let success = unsafe { BNCollaborationLoadRemotes() };
    success.then_some(()).ok_or(())
}

/// List of known/connected Remotes
pub fn known_remotes() -> Array<Remote> {
    let mut count = 0;
    let value = unsafe { BNCollaborationGetRemotes(&mut count) };
    assert!(!value.is_null());
    unsafe { Array::new(value, count, ()) }
}

/// Get Remote by unique `id`
pub fn get_remote_by_id(id: &str) -> Option<Ref<Remote>> {
    let id = id.to_cstr();
    let value = unsafe { BNCollaborationGetRemoteById(id.as_ptr()) };
    NonNull::new(value).map(|h| unsafe { Remote::ref_from_raw(h) })
}

/// Get Remote by `address`
pub fn get_remote_by_address(address: &str) -> Option<Ref<Remote>> {
    let address = address.to_cstr();
    let value = unsafe { BNCollaborationGetRemoteByAddress(address.as_ptr()) };
    NonNull::new(value).map(|h| unsafe { Remote::ref_from_raw(h) })
}

/// Get Remote by `name`
pub fn get_remote_by_name(name: &str) -> Option<Ref<Remote>> {
    let name = name.to_cstr();
    let value = unsafe { BNCollaborationGetRemoteByName(name.as_ptr()) };
    NonNull::new(value).map(|h| unsafe { Remote::ref_from_raw(h) })
}

/// Remove a Remote from the list of known remotes (saved to Settings)
pub fn remove_known_remote(remote: &Remote) {
    unsafe { BNCollaborationRemoveRemote(remote.handle.as_ptr()) }
}

/// Save the list of known Remotes to local Settings
pub fn save_remotes() {
    unsafe { BNCollaborationSaveRemotes() }
}

pub fn store_data_in_keychain<I>(key: &str, data: I) -> bool
where
    I: IntoIterator<Item = (String, String)>,
{
    let key = key.to_cstr();
    let (data_keys, data_values): (Vec<_>, Vec<_>) = data
        .into_iter()
        .map(|(k, v)| (k.to_cstr(), v.to_cstr()))
        .unzip();
    let data_keys_ptr: Box<[*const c_char]> = data_keys.iter().map(|k| k.as_ptr()).collect();
    let data_values_ptr: Box<[*const c_char]> = data_values.iter().map(|v| v.as_ptr()).collect();
    unsafe {
        BNCollaborationStoreDataInKeychain(
            key.as_ptr(),
            data_keys_ptr.as_ptr() as *mut _,
            data_values_ptr.as_ptr() as *mut _,
            data_keys.len(),
        )
    }
}

pub fn has_data_in_keychain(key: &str) -> bool {
    let key = key.to_cstr();
    unsafe { BNCollaborationHasDataInKeychain(key.as_ptr()) }
}

pub fn get_data_from_keychain(key: &str) -> Option<(Array<BnString>, Array<BnString>)> {
    let key = key.to_cstr();
    let mut keys = std::ptr::null_mut();
    let mut values = std::ptr::null_mut();
    let count = unsafe { BNCollaborationGetDataFromKeychain(key.as_ptr(), &mut keys, &mut values) };
    let keys = (!keys.is_null()).then(|| unsafe { Array::new(keys, count, ()) });
    let values = (!values.is_null()).then(|| unsafe { Array::new(values, count, ()) });
    keys.zip(values)
}

pub fn delete_data_from_keychain(key: &str) -> bool {
    let key = key.to_cstr();
    unsafe { BNCollaborationDeleteDataFromKeychain(key.as_ptr()) }
}
