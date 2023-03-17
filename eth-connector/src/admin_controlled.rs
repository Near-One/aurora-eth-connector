use near_sdk::AccountId;

pub type PausedMask = u8;

/// Admin control flow flag indicates that all control flow unpause (unblocked).
pub const UNPAUSE_ALL: PausedMask = 0;
/// Admin control flow flag indicates that the deposit is paused.
pub const PAUSE_DEPOSIT: PausedMask = 1 << 0;
/// Admin control flow flag indicates that withdrawal is paused.
pub const PAUSE_WITHDRAW: PausedMask = 1 << 1;

pub trait AdminControlled {
    /// Return the current mask representing all paused events.
    fn get_paused_flags(&self) -> PausedMask;

    /// Update mask with all paused events.
    /// Implementor is responsible for guaranteeing that this function can only be
    /// called by owner of the contract.
    fn set_paused_flags(&mut self, paused: PausedMask);

    /// Return if the contract is paused for the current flag.
    /// If it's owner, result always `false` - unpaused.
    fn is_paused(&self, flag: PausedMask) -> bool {
        (self.get_paused_flags() & flag) != 0 && !self.is_owner()
    }

    /// Asserts the passed paused flag is not set. Returns `PausedError` if paused.
    fn assert_not_paused(&self, flag: PausedMask) -> Result<(), error::AdminControlledError> {
        if self.is_paused(flag) {
            Err(error::AdminControlledError::Paused)
        } else {
            Ok(())
        }
    }

    /// Set account access right for contract
    fn set_access_right(&mut self, account: &AccountId);

    /// Get account access right for contract
    fn get_access_right(&self) -> AccountId;

    /// Check access right for predecessor account
    fn assert_access_right(&self) -> Result<(), error::AdminControlledError> {
        if self.get_access_right() == near_sdk::env::predecessor_account_id()
            || self.is_owner()
            || near_sdk::env::predecessor_account_id() == near_sdk::env::current_account_id()
        {
            Ok(())
        } else {
            Err(error::AdminControlledError::AccessRight)
        }
    }

    /// Asseert only owners of contract access right
    fn assert_owner_access_right(&self) -> Result<(), error::AdminControlledError> {
        if self.is_owner()
            || near_sdk::env::predecessor_account_id() == near_sdk::env::current_account_id()
        {
            Ok(())
        } else {
            Err(error::AdminControlledError::AccessRight)
        }
    }

    /// Check is predecessor account ID is owner
    fn is_owner(&self) -> bool;
}

pub mod error {
    pub const ERR_PAUSED: &[u8; 10] = b"ERR_PAUSED";
    pub const ERR_ACCESS_RIGHT: &[u8; 16] = b"ERR_ACCESS_RIGHT";

    pub enum AdminControlledError {
        Paused,
        AccessRight,
    }

    impl AsRef<[u8]> for AdminControlledError {
        fn as_ref(&self) -> &[u8] {
            match self {
                Self::Paused => ERR_PAUSED,
                Self::AccessRight => ERR_ACCESS_RIGHT,
            }
        }
    }
}

#[test]
fn test_pause_control() {
    use crate::connector_impl::EthConnector;

    let mut connector = EthConnector {
        prover_account: "prover".parse().unwrap(),
        eth_custodian_address: Default::default(),
        paused_mask: UNPAUSE_ALL,
        account_with_access_right: "aurora".parse().unwrap(),
        owner_id: "aurora".parse().unwrap(),
    };

    assert!(connector.assert_not_paused(PAUSE_DEPOSIT).is_ok());
    assert!(connector.assert_not_paused(PAUSE_WITHDRAW).is_ok());

    connector.set_paused_flags(PAUSE_DEPOSIT);

    assert!(connector.assert_not_paused(PAUSE_DEPOSIT).is_err());
    assert!(connector.assert_not_paused(PAUSE_WITHDRAW).is_ok());

    connector.set_paused_flags(UNPAUSE_ALL);
    connector.set_paused_flags(PAUSE_WITHDRAW);

    assert!(connector.assert_not_paused(PAUSE_DEPOSIT).is_ok());
    assert!(connector.assert_not_paused(PAUSE_WITHDRAW).is_err());

    connector.set_paused_flags(PAUSE_WITHDRAW | PAUSE_DEPOSIT);

    assert!(connector.assert_not_paused(PAUSE_DEPOSIT).is_err());
    assert!(connector.assert_not_paused(PAUSE_WITHDRAW).is_err());

    connector.set_paused_flags(UNPAUSE_ALL);

    assert!(connector.assert_not_paused(PAUSE_DEPOSIT).is_ok());
    assert!(connector.assert_not_paused(PAUSE_WITHDRAW).is_ok());
}
