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

    /// Return if the contract is paused for the current flag and user
    fn is_paused(&self, flag: PausedMask, is_owner: bool) -> bool {
        (self.get_paused_flags() & flag) != 0 && !is_owner
    }

    /// Asserts the passed paused flag is not set. Returns `PausedError` if paused.
    fn assert_not_paused(
        &self,
        flag: PausedMask,
        is_owner: bool,
    ) -> Result<(), error::AdminControlledError> {
        if self.is_paused(flag, is_owner) {
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
            || near_sdk::env::predecessor_account_id() == near_sdk::env::current_account_id()
        {
            Ok(())
        } else {
            Err(error::AdminControlledError::AccessRight)
        }
    }
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
