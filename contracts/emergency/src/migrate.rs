//! Emergency migration stub — data reshape + upgrade guard.

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
pub struct LegacyEmergency {
    pub balance: i128,
    pub last_updated: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[contracttype]
pub struct CurrentEmergency {
    pub balance: i128,
    pub last_updated: u64,
    pub reserved: i128,
}

// ─── Errors ───────────────────────────────────────────────────────────────────

#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
#[contracterror]
#[repr(u32)]
pub enum EmergencyError {
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
}

impl From<MigrationStubError> for EmergencyError {
    fn from(e: MigrationStubError) -> Self {
        match e {
            MigrationStubError::NotInitialized => EmergencyError::NotInitialized,
            MigrationStubError::AlreadyInitialized => EmergencyError::AlreadyInitialized,
            MigrationStubError::Unauthorized => EmergencyError::Unauthorized,
            MigrationStubError::LegacyStateMissing => EmergencyError::LegacyStateMissing,
            MigrationStubError::InvalidLegacyBalance => EmergencyError::InvalidLegacyBalance,
            MigrationStubError::VersionMismatch => EmergencyError::VersionMismatch,
            MigrationStubError::InvalidTargetVersion => EmergencyError::InvalidTargetVersion,
            MigrationStubError::AlreadyMigrated => EmergencyError::AlreadyMigrated,
            MigrationStubError::UpgradeNotAuthorized => EmergencyError::UpgradeNotAuthorized,
            MigrationStubError::Overflow => EmergencyError::Overflow,
            // WasmHashZero is not checked in this contract's authorize_upgrade.
            MigrationStubError::WasmHashZero => EmergencyError::Unauthorized,
        }
    }
}

// ─── Event symbols ────────────────────────────────────────────────────────────

fn event_emergency_migrated(env: &Env) -> Symbol {
    Symbol::new(env, "emergency_migrated")
}

fn event_upgrade_authorised(env: &Env) -> Symbol {
    Symbol::new(env, "upgrade_authorised")
}

// ─── Contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct EmergencyMigrate;

#[contractimpl]
impl EmergencyMigrate {
    pub fn init(env: Env, admin: Address, initial_version: u32) -> Result<(), EmergencyError> {
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
    ) -> Result<CurrentEmergency, EmergencyError> {
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
                let legacy: LegacyEmergency = env
                    .storage()
                    .instance()
                    .get(&StorageKey::Legacy)
                    .ok_or(MigrationStubError::LegacyStateMissing)?;
                if legacy.balance < 0 {
                    return Err(MigrationStubError::InvalidLegacyBalance);
                }
                let current = CurrentEmergency {
                    balance: legacy.balance,
                    last_updated: legacy.last_updated,
                    reserved: 0,
                };
                env.storage().instance().set(&StorageKey::Current, &current);
                Ok(())
            },
        )
        .map_err(EmergencyError::from)?;

        let current: CurrentEmergency = env
            .storage()
            .instance()
            .get(&StorageKey::Current)
            .ok_or(EmergencyError::LegacyStateMissing)?;

        env.events()
            .publish((event_emergency_migrated(&env),), target_version);

        Ok(current)
    }

    pub fn authorize_upgrade(
        env: Env,
        caller: Address,
        target_version: u32,
        wasm_hash: BytesN<32>,
    ) -> Result<(), EmergencyError> {
        caller.require_auth();
        stub_authorize_upgrade(
            &env,
            StorageKey::Admin,
            StorageKey::Version,
            StorageKey::AuthorisedUpgrade,
            &caller,
            target_version,
            &wasm_hash,
            false, // no zero-hash check in this contract
        )
        .map_err(EmergencyError::from)?;

        env.events()
            .publish((event_upgrade_authorised(&env), wasm_hash), target_version);

        Ok(())
    }

    pub fn get_current(env: Env) -> Option<CurrentEmergency> {
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

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;
    use soroban_sdk::testutils::{Address as _, Events as _};
    use soroban_sdk::Env;

    fn setup(env: &Env, legacy_balance: i128, legacy_timestamp: u64) -> (Address, Address) {
        env.mock_all_auths();
        let admin = Address::generate(env);
        let contract = env.register(EmergencyMigrate, ());
        let client = EmergencyMigrateClient::new(env, &contract);
        client.init(&admin, &1);

        env.as_contract(&contract, || {
            env.storage().instance().set(
                &StorageKey::Legacy,
                &LegacyEmergency {
                    balance: legacy_balance,
                    last_updated: legacy_timestamp,
                },
            );
        });

        (admin, contract)
    }

    #[test]
    fn init_stores_admin_and_version() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let contract = env.register(EmergencyMigrate, ());
        let client = EmergencyMigrateClient::new(&env, &contract);

        client.init(&admin, &42);
        assert_eq!(client.version(), Some(42));
    }

    #[test]
    fn init_rejects_double_initialisation() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let contract = env.register(EmergencyMigrate, ());
        let client = EmergencyMigrateClient::new(&env, &contract);

        client.init(&admin, &1);
        let result = client.try_init(&admin, &2);
        assert!(result.is_err());
    }

    #[test]
    fn init_requires_auth() {
        let env = Env::default();
        let admin = Address::generate(&env);
        let contract = env.register(EmergencyMigrate, ());
        let client = EmergencyMigrateClient::new(&env, &contract);
        env.set_auths(&[]);
        let result = client.try_init(&admin, &0);
        assert!(result.is_err());
    }

    #[test]
    fn migrate_reshapes_data_and_advances_version() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 500, 42);
        let client = EmergencyMigrateClient::new(&env, &contract);

        let result = client.migrate(&admin, &1, &2);
        assert_eq!(result.balance, 500);
        assert_eq!(result.last_updated, 42);
        assert_eq!(result.reserved, 0);
        assert_eq!(client.version(), Some(2));
        assert_eq!(client.get_current(), Some(result));
    }

    #[test]
    fn migrate_preserves_zero_balance() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 0, 100);
        let client = EmergencyMigrateClient::new(&env, &contract);

        let result = client.migrate(&admin, &1, &2);
        assert_eq!(result.balance, 0);
        assert_eq!(result.last_updated, 100);
        assert_eq!(result.reserved, 0);
    }

    #[test]
    fn migrate_preserves_large_balance() {
        let env = Env::default();
        let large = i128::MAX;
        let (admin, contract) = setup(&env, large, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);

        let result = client.migrate(&admin, &1, &2);
        assert_eq!(result.balance, large);
        assert_eq!(client.version(), Some(2));
    }

    #[test]
    fn migrate_cannot_be_replayed() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);

        client.migrate(&admin, &1, &2);
        let result = client.try_migrate(&admin, &2, &3);
        assert!(result.is_err());
    }

    #[test]
    fn migrate_rejects_wrong_expected_version() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);

        let result = client.try_migrate(&admin, &0, &1);
        assert!(result.is_err());
    }

    #[test]
    fn migrate_rejects_non_incrementing_target() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);

        let result = client.try_migrate(&admin, &1, &3);
        assert!(result.is_err());
    }

    #[test]
    fn migrate_rejects_negative_legacy_balance() {
        let env = Env::default();
        let (admin, contract) = setup(&env, -1, 42);
        let client = EmergencyMigrateClient::new(&env, &contract);

        let result = client.try_migrate(&admin, &1, &2);
        assert!(result.is_err());
    }

    #[test]
    fn migrate_requires_admin_authorisation() {
        let env = Env::default();
        let (_admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);
        let outsider = Address::generate(&env);

        let result = client.try_migrate(&outsider, &1, &2);
        assert!(result.is_err());
    }

    #[test]
    fn migrate_fails_when_legacy_state_missing() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let contract = env.register(EmergencyMigrate, ());
        let client = EmergencyMigrateClient::new(&env, &contract);

        client.init(&admin, &1);
        let result = client.try_migrate(&admin, &1, &2);
        assert!(result.is_err());
    }

    #[test]
    fn migrate_fails_when_not_initialised() {
        let env = Env::default();
        env.mock_all_auths();
        let caller = Address::generate(&env);
        let contract = env.register(EmergencyMigrate, ());
        let client = EmergencyMigrateClient::new(&env, &contract);

        let result = client.try_migrate(&caller, &0, &1);
        assert!(result.is_err());
    }

    #[test]
    fn migrate_requires_auth_on_caller() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);
        env.set_auths(&[]);
        let result = client.try_migrate(&admin, &1, &2);
        assert!(result.is_err());
    }

    #[test]
    fn authorize_upgrade_stores_hash_for_version() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);
        let hash = BytesN::from_array(&env, &[0xAA; 32]);

        client.authorize_upgrade(&admin, &1, &hash);
        assert!(client.is_upgrade_authorised(&hash));
    }

    #[test]
    fn is_upgrade_authorised_rejects_wrong_hash() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);
        let good_hash = BytesN::from_array(&env, &[0xAA; 32]);
        let bad_hash = BytesN::from_array(&env, &[0xBB; 32]);

        client.authorize_upgrade(&admin, &1, &good_hash);
        assert!(client.is_upgrade_authorised(&good_hash));
        assert!(!client.is_upgrade_authorised(&bad_hash));
    }

    #[test]
    fn authorize_upgrade_rejects_wrong_version() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);
        let hash = BytesN::from_array(&env, &[0xAA; 32]);

        let result = client.try_authorize_upgrade(&admin, &2, &hash);
        assert!(result.is_err());
    }

    #[test]
    fn authorize_upgrade_requires_admin() {
        let env = Env::default();
        let (_admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);
        let outsider = Address::generate(&env);
        let hash = BytesN::from_array(&env, &[0xAA; 32]);

        let result = client.try_authorize_upgrade(&outsider, &1, &hash);
        assert!(result.is_err());
    }

    #[test]
    fn authorize_upgrade_requires_auth_on_caller() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);
        let hash = BytesN::from_array(&env, &[0xAA; 32]);

        env.set_auths(&[]);
        let result = client.try_authorize_upgrade(&admin, &1, &hash);
        assert!(result.is_err());
    }

    #[test]
    fn is_upgrade_authorised_false_before_authorisation() {
        let env = Env::default();
        let (_admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);
        let hash = BytesN::from_array(&env, &[0xAA; 32]);

        assert!(!client.is_upgrade_authorised(&hash));
    }

    #[test]
    fn is_upgrade_authorised_false_when_not_initialised() {
        let env = Env::default();
        let contract = env.register(EmergencyMigrate, ());
        let client = EmergencyMigrateClient::new(&env, &contract);
        let hash = BytesN::from_array(&env, &[0xAA; 32]);

        assert!(!client.is_upgrade_authorised(&hash));
    }

    #[test]
    fn get_current_is_none_before_migration() {
        let env = Env::default();
        let (_admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);

        assert_eq!(client.get_current(), None);
    }

    #[test]
    fn version_returns_none_before_init() {
        let env = Env::default();
        let contract = env.register(EmergencyMigrate, ());
        let client = EmergencyMigrateClient::new(&env, &contract);

        assert_eq!(client.version(), None);
    }

    #[test]
    fn full_lifecycle_init_migrate_authorize() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 1_000_000, 12345);
        let client = EmergencyMigrateClient::new(&env, &contract);
        let wasm_hash = BytesN::from_array(&env, &[0xCC; 32]);

        assert_eq!(client.version(), Some(1));

        let current = client.migrate(&admin, &1, &2);
        assert_eq!(current.balance, 1_000_000);
        assert_eq!(current.last_updated, 12345);
        assert_eq!(current.reserved, 0);
        assert_eq!(client.version(), Some(2));
        assert_eq!(client.get_current(), Some(current));

        client.authorize_upgrade(&admin, &2, &wasm_hash);
        assert!(client.is_upgrade_authorised(&wasm_hash));
    }

    #[test]
    fn migrate_emits_event() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 200, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);

        client.migrate(&admin, &1, &2);

        let all_events = env.events().all();
        let expected_topic = Symbol::new(&env, "emergency_migrated");
        let has_migrated_event = all_events
            .into_iter()
            .any(|(_addr, topics, _data)| topics.contains(expected_topic.to_val()));
        assert!(has_migrated_event);
    }

    #[test]
    fn authorize_upgrade_emits_event() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 200, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);
        let hash = BytesN::from_array(&env, &[0xDD; 32]);

        client.authorize_upgrade(&admin, &1, &hash);

        let all_events = env.events().all();
        let expected_topic = Symbol::new(&env, "upgrade_authorised");
        let has_auth_event = all_events
            .into_iter()
            .any(|(_addr, topics, _data)| topics.contains(expected_topic.to_val()));
        assert!(has_auth_event);
    }

    #[test]
    fn migrate_preserves_exact_timestamp() {
        let env = Env::default();
        let ts = 1_700_000_000u64;
        let (admin, contract) = setup(&env, 500, ts);
        let client = EmergencyMigrateClient::new(&env, &contract);

        let result = client.migrate(&admin, &1, &2);
        assert_eq!(result.last_updated, ts);
    }

    #[test]
    fn migrate_version_overflow_returns_overflow_error() {
        let env = Env::default();
        env.mock_all_auths();
        let admin = Address::generate(&env);
        let contract = env.register(EmergencyMigrate, ());
        let client = EmergencyMigrateClient::new(&env, &contract);

        client.init(&admin, &u32::MAX);
        env.as_contract(&contract, || {
            env.storage().instance().set(
                &StorageKey::Legacy,
                &LegacyEmergency {
                    balance: 100,
                    last_updated: 1,
                },
            );
        });

        let result = client.try_migrate(&admin, &u32::MAX, &0);
        assert!(
            result.is_err(),
            "migrate with u32::MAX expected_version must fail with Overflow"
        );
    }

    #[test]
    fn authorize_upgrade_accepts_zero_wasm_hash() {
        let env = Env::default();
        let (admin, contract) = setup(&env, 100, 1);
        let client = EmergencyMigrateClient::new(&env, &contract);
        let zero_hash = BytesN::from_array(&env, &[0u8; 32]);

        // Must succeed without error — this contract does not reject zero hashes.
        client.authorize_upgrade(&admin, &1, &zero_hash);
        assert!(client.is_upgrade_authorised(&zero_hash));
    }
}
