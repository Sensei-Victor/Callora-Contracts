//! Stake migration stub — data reshape + upgrade guard.

use callora_storage_migration::migration_stub::{
    stub_authorize_upgrade, stub_get_current, stub_init, stub_is_upgrade_authorised, stub_migrate,
    stub_version, MigrationStubError,
};
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, Address, BytesN, Env, Symbol,
};

// ─── Storage keys ─────────────────────────────────────────────────────────────

#[derive(Clone)]
#[contracttype]
pub enum StorageKey {
    Admin,
    Version,
    Legacy,
    Current,
    AuthorisedUpgrade,
}

// ─── Data types ───────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct LegacyStake {
    pub total_staked: i128,
    pub last_checkpoint: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct CurrentStake {
    pub total_staked: i128,
    pub last_checkpoint: u32,
    pub reserve: i128,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[contracterror]
#[repr(u32)]
pub enum StakeMigrateError {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    Unauthorized = 3,
    LegacyStateMissing = 4,
    InvalidLegacyBalance = 5,
    VersionMismatch = 6,
    InvalidTargetVersion = 7,
    AlreadyMigrated = 8,
    UpgradeNotAuthorized = 9,
    Overflow = 10,
    WasmHashZero = 11,
}

impl From<MigrationStubError> for StakeMigrateError {
    fn from(e: MigrationStubError) -> Self {
        match e {
            MigrationStubError::NotInitialized => StakeMigrateError::NotInitialized,
            MigrationStubError::AlreadyInitialized => StakeMigrateError::AlreadyInitialized,
            MigrationStubError::Unauthorized => StakeMigrateError::Unauthorized,
            MigrationStubError::LegacyStateMissing => StakeMigrateError::LegacyStateMissing,
            MigrationStubError::InvalidLegacyBalance => StakeMigrateError::InvalidLegacyBalance,
            MigrationStubError::VersionMismatch => StakeMigrateError::VersionMismatch,
            MigrationStubError::InvalidTargetVersion => StakeMigrateError::InvalidTargetVersion,
            MigrationStubError::AlreadyMigrated => StakeMigrateError::AlreadyMigrated,
            MigrationStubError::UpgradeNotAuthorized => StakeMigrateError::UpgradeNotAuthorized,
            MigrationStubError::Overflow => StakeMigrateError::Overflow,
            MigrationStubError::WasmHashZero => StakeMigrateError::WasmHashZero,
        }
    }
}

// ─── Event symbol helpers ─────────────────────────────────────────────────────

#[inline]
fn event_stake_migrated(env: &Env) -> Symbol {
    Symbol::new(env, "stake_migrated")
}

#[inline]
fn event_upgrade_authorised(env: &Env) -> Symbol {
    Symbol::new(env, "upg_authorised")
}

// ─── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct CalloraStakeMigrate;

#[contractimpl]
impl CalloraStakeMigrate {
    pub fn init(env: Env, admin: Address, initial_version: u32) -> Result<(), StakeMigrateError> {
        admin.require_auth();
        stub_init(
            &env,
            StorageKey::Admin,
            StorageKey::Version,
            &admin,
            initial_version,
        )
        .map_err(Into::into)
    }

    pub fn migrate(
        env: Env,
        caller: Address,
        expected_version: u32,
        target_version: u32,
    ) -> Result<CurrentStake, StakeMigrateError> {
        caller.require_auth();
        stub_migrate(
            &env,
            StorageKey::Admin,
            StorageKey::Version,
            StorageKey::Current,
            &caller,
            expected_version,
            target_version,
            || -> Result<(), MigrationStubError> {
                // Extend the instance TTL so migration state survives long enough
                // for the follow-on upgrade to be authorised and deployed.
                env.storage()
                    .instance()
                    .extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

                let legacy: LegacyStake = env
                    .storage()
                    .instance()
                    .get(&StorageKey::Legacy)
                    .ok_or(MigrationStubError::LegacyStateMissing)?;

                if legacy.total_staked < 0 {
                    return Err(MigrationStubError::InvalidLegacyBalance);
                }

                let current = CurrentStake {
                    total_staked: legacy.total_staked,
                    last_checkpoint: legacy.last_checkpoint,
                    reserve: 0,
                };

                env.storage().instance().set(&StorageKey::Current, &current);
                // Remove legacy record so a re-run cannot depend on stale input.
                env.storage().instance().remove(&StorageKey::Legacy);
                Ok(())
            },
        )
        .map_err(StakeMigrateError::from)?;

        let current: CurrentStake = env
            .storage()
            .instance()
            .get(&StorageKey::Current)
            .ok_or(StakeMigrateError::LegacyStateMissing)?;

        env.events()
            .publish((event_stake_migrated(&env),), target_version);

        Ok(current)
    }

    pub fn authorize_upgrade(
        env: Env,
        caller: Address,
        target_version: u32,
        wasm_hash: BytesN<32>,
    ) -> Result<(), StakeMigrateError> {
        caller.require_auth();
        stub_authorize_upgrade(
            &env,
            StorageKey::Admin,
            StorageKey::Version,
            StorageKey::AuthorisedUpgrade,
            &caller,
            target_version,
            &wasm_hash,
            true, // reject zero hash
        )
        .map_err(StakeMigrateError::from)?;

        env.events()
            .publish((event_upgrade_authorised(&env), wasm_hash), target_version);

        Ok(())
    }

    pub fn get_current(env: Env) -> Option<CurrentStake> {
        stub_get_current(&env, StorageKey::Current)
    }

    pub fn version(env: Env) -> Option<u32> {
        stub_version(&env, StorageKey::Version)
    }

    pub fn is_upgrade_authorised(env: Env, wasm_hash: BytesN<32>) -> bool {
        stub_is_upgrade_authorised(
            &env,
            StorageKey::Version,
            StorageKey::AuthorisedUpgrade,
            &wasm_hash,
        )
    }
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

const INSTANCE_TTL_THRESHOLD: u32 = 100;
const INSTANCE_TTL_EXTEND_TO: u32 = 10_000;
