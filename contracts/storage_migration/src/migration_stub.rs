//! Shared state-machine helpers for migration-stub contracts.
//!
//! All three migration contracts (`callora-migrate`, `callora-emergency`,
//! `callora-stake`) implement the same five-step pattern:
//!
//! 1. `init`   — record admin + starting version.
//! 2. `migrate` — verify version, reshape legacy → current, advance version.
//! 3. `authorize_upgrade` — record (version, wasm_hash) guard.
//! 4. `get_current` — read reshaped state.
//! 5. `version` / `is_upgrade_authorised` — read-only checks.
//!
//! Each contract is a thin `#[contractimpl]` wrapper that:
//! * calls `require_auth` before delegating here,
//! * maps [`MigrationStubError`] to its own `#[contracterror]` enum,
//! * passes the event-publish closure and any contract-specific extras
//!   (TTL extension, legacy key removal, …) as callbacks.
//!
//! # Key-type contract
//!
//! Every helper is generic over `K`, the host contract's storage-key type.
//! The caller passes the specific variant it wants to read/write; the helper
//! never constructs keys on its own.

use soroban_sdk::{Address, BytesN, Env, IntoVal, TryFromVal, Val};

// ─── Canonical error vocabulary ───────────────────────────────────────────────

/// Error codes shared by all migration-stub helpers.
///
/// Each wrapper contract maps these to its own `#[contracterror]` enum,
/// preserving the numeric codes that clients depend on.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MigrationStubError {
    /// `init` has not been called.
    NotInitialized,
    /// `init` was called more than once.
    AlreadyInitialized,
    /// Caller is not the stored administrator.
    Unauthorized,
    /// No legacy state found under the legacy key.
    LegacyStateMissing,
    /// Legacy numeric field is negative (data integrity violation).
    InvalidLegacyBalance,
    /// `expected_version` does not match the stored version.
    VersionMismatch,
    /// `target_version` is not exactly `expected_version + 1`.
    InvalidTargetVersion,
    /// Reshaped current state already present in storage.
    AlreadyMigrated,
    /// No authorised upgrade recorded for the current version.
    UpgradeNotAuthorized,
    /// Version arithmetic would overflow `u32::MAX`.
    Overflow,
    /// Supplied WASM hash is all-zero bytes.
    WasmHashZero,
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

/// Record the administrator address and starting migration version.
///
/// Idempotency: returns [`MigrationStubError::AlreadyInitialized`] if the
/// admin slot is already populated.
///
/// # Arguments
/// * `admin_key` — the host's storage key for the admin slot.
/// * `version_key` — the host's storage key for the version counter.
/// * `admin` — the caller; `require_auth` **must** be called by the wrapper
///   before this function.
/// * `initial_version` — starting version written to `version_key`.
pub fn stub_init<K>(
    env: &Env,
    admin_key: K,
    version_key: K,
    admin: &Address,
    initial_version: u32,
) -> Result<(), MigrationStubError>
where
    K: IntoVal<Env, Val> + Clone,
{
    if env.storage().instance().has(&admin_key) {
        return Err(MigrationStubError::AlreadyInitialized);
    }
    env.storage().instance().set(&admin_key, admin);
    env.storage().instance().set(&version_key, &initial_version);
    Ok(())
}

/// Reshape legacy state into the current layout and advance the version.
///
/// The caller is responsible for:
/// * calling `caller.require_auth()` before this function,
/// * providing a `reshape` callback that reads the legacy record from storage
///   and writes the reshaped current record; it must return
///   `Err(MigrationStubError::…)` on invalid data,
/// * emitting any contract-specific events after a successful return,
/// * performing any post-migrate storage housekeeping (TTL, key removal, …).
///
/// The version advance (`stored → stored + 1`) is validated against
/// `expected_version` / `target_version` before the reshape runs, so the
/// callback only executes when all guards pass.
pub fn stub_migrate<K, F>(
    env: &Env,
    admin_key: K,
    version_key: K,
    current_key: K,
    caller: &Address,
    expected_version: u32,
    target_version: u32,
    reshape: F,
) -> Result<(), MigrationStubError>
where
    K: IntoVal<Env, Val> + Clone,
    F: FnOnce() -> Result<(), MigrationStubError>,
{
    // Admin check.
    let admin: Address = env
        .storage()
        .instance()
        .get(&admin_key)
        .ok_or(MigrationStubError::NotInitialized)?;
    if caller != &admin {
        return Err(MigrationStubError::Unauthorized);
    }

    // Version guards.
    let version: u32 = env
        .storage()
        .instance()
        .get(&version_key)
        .ok_or(MigrationStubError::NotInitialized)?;
    if version != expected_version {
        return Err(MigrationStubError::VersionMismatch);
    }
    let next_version = expected_version
        .checked_add(1)
        .ok_or(MigrationStubError::Overflow)?;
    if target_version != next_version {
        return Err(MigrationStubError::InvalidTargetVersion);
    }
    if env.storage().instance().has(&current_key) {
        return Err(MigrationStubError::AlreadyMigrated);
    }

    // Data reshape (contract-specific).
    reshape()?;

    // Advance the version only after the reshape succeeds.
    env.storage().instance().set(&version_key, &target_version);
    Ok(())
}

/// Record an authorised WASM hash for the current migration version.
///
/// The caller is responsible for calling `caller.require_auth()` before this
/// function and for emitting any events after a successful return.
///
/// Pass `check_zero_hash = true` to reject an all-zero `wasm_hash`
/// ([`MigrationStubError::WasmHashZero`]); `false` skips that guard.
pub fn stub_authorize_upgrade<K>(
    env: &Env,
    admin_key: K,
    version_key: K,
    auth_key: K,
    caller: &Address,
    target_version: u32,
    wasm_hash: &BytesN<32>,
    check_zero_hash: bool,
) -> Result<(), MigrationStubError>
where
    K: IntoVal<Env, Val> + Clone,
{
    let admin: Address = env
        .storage()
        .instance()
        .get(&admin_key)
        .ok_or(MigrationStubError::NotInitialized)?;
    if caller != &admin {
        return Err(MigrationStubError::Unauthorized);
    }

    let version: u32 = env
        .storage()
        .instance()
        .get(&version_key)
        .ok_or(MigrationStubError::NotInitialized)?;
    if target_version != version {
        return Err(MigrationStubError::VersionMismatch);
    }

    if check_zero_hash && *wasm_hash == BytesN::from_array(env, &[0u8; 32]) {
        return Err(MigrationStubError::WasmHashZero);
    }

    env.storage()
        .instance()
        .set(&auth_key, &(target_version, wasm_hash.clone()));
    Ok(())
}

/// Return the stored migration version (`None` if not initialised).
pub fn stub_version<K>(env: &Env, version_key: K) -> Option<u32>
where
    K: IntoVal<Env, Val>,
{
    env.storage().instance().get(&version_key)
}

/// Return the reshaped current state, if migration has completed.
pub fn stub_get_current<K, V>(env: &Env, current_key: K) -> Option<V>
where
    K: IntoVal<Env, Val>,
    V: TryFromVal<Env, Val>,
{
    env.storage().instance().get(&current_key)
}

/// Check whether `wasm_hash` is authorised for the current migration version.
pub fn stub_is_upgrade_authorised<K>(
    env: &Env,
    version_key: K,
    auth_key: K,
    wasm_hash: &BytesN<32>,
) -> bool
where
    K: IntoVal<Env, Val>,
{
    let stored_version: Option<u32> = env.storage().instance().get(&version_key);
    let authorisation: Option<(u32, BytesN<32>)> = env.storage().instance().get(&auth_key);
    match (stored_version, authorisation) {
        (Some(version), Some((auth_version, auth_hash))) => {
            version == auth_version && *wasm_hash == auth_hash
        }
        _ => false,
    }
}
