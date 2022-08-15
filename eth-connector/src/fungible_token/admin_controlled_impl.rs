use crate::fungible_token::admin_controlled::PausedMask;
use crate::{AdminControlled, FungibleToken};

impl AdminControlled for FungibleToken {
    fn get_paused(&self) -> PausedMask {
        todo!()
    }

    fn set_paused(&mut self, _paused: PausedMask) {
        todo!()
    }
}
