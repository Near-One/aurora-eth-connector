use near_sdk::ext_contract;

#[ext_contract(ext_ft_core)]
pub trait ConnectorCore {
    fn withdraw(&mut self);

    fn deposit(&mut self);

    fn finish_deposit(&mut self);
}
