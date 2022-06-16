use ed25519_compact::*;

use chain::{Chain, Transaction};

fn main() {
    let my_key_pair: KeyPair = KeyPair::from_seed(Seed::default());
    let my_address = my_key_pair.pk.to_pem();

    let chain = &mut Chain::new(my_address.clone());

    let t1 = &mut Transaction::new(
        my_address.clone(),
        "B".to_string(),
        3,
        String::from("my transaction"),
    );
    t1.sign(my_key_pair);
    chain.add_transaction(t1.to_owned());
    chain.mine_pending_transactions_to_a_block();

    println!("Chain: {:#?}", chain);
    println!("Chain valid? {:#?}", chain.is_valid());
    println!("balance for `A`: {:#?}", chain.get_balance_for_address(my_address.clone()));

    println!("Hello, world!");
}
