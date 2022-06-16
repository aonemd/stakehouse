#[macro_use]
extern crate log;

use std::net::ToSocketAddrs;

use chrono::Utc;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use ed25519_compact::*;

const DIFFICULTY_PREFIX: &str = "00";
const DIFFICULTY_LEVEL: i32 = 2;
const GENESIS_ADDRESS: &str = "a_quark";
const MINING_ADDRESS: &str = "AA";

#[derive(Debug)]
pub struct Chain {
    pub blocks: Vec<Block>,
    pending_transactions: Vec<Transaction>,
    miner_address: String,
    miner_reward: i32,
}

impl Chain {
    pub fn new(miner_address: String) -> Self {
        let first_block = Self::genesis();
        Self {
            blocks: vec![first_block],
            pending_transactions: vec![],
            miner_address,
            miner_reward: 10,
        }
    }

    fn genesis() -> Block {
        let first_transaction = Transaction {
            from_address: GENESIS_ADDRESS.to_string(),
            to_address: GENESIS_ADDRESS.to_string(),
            amount: 0,
            reference: String::from("genesis!"),
            signature: None,
        };
        Block {
            timestamp: Utc::now().timestamp(),
            previous_hash: String::from("genesis"),
            transactions: vec![first_transaction],
            nonce: 2836,
            hash: "0000f816a87f806bb0073dcf026a64fb40c946b5abee2573702828694d5b4c43".to_string(),
        }
    }

    pub fn add_transaction(&mut self, new_transaction: Transaction) {
        if !new_transaction.is_valid() {
            panic!("Invalid transaction! Cannot add to chain!!");
        }

        self.pending_transactions.push(new_transaction);

        // a predefined number of transactions every number (10) of minutes
        self.mine_pending_transactions_to_a_block();
    }

    fn mine_pending_transactions_to_a_block(&mut self) {
        let previous_block = self.blocks.last().expect("there is at least one block");
        let block_to_add = Block::new(
            DIFFICULTY_LEVEL,
            previous_block.hash.clone(),
            self.pending_transactions.clone(),
        );

        if block_to_add.is_valid(previous_block) {
            self.blocks.push(block_to_add);
        } else {
            error!("could not add block -- invalid");
        }

        self.pending_transactions = vec![
            Transaction { from_address: self.miner_address.clone(), to_address: self.miner_address.clone(), amount: self.miner_reward, reference: "rewaaad".to_string() }
        ];
    }

    pub fn is_valid(&self) -> bool {
        for i in 1..self.blocks.len() {
            // ignore the genesis block -- the one before it all started

            let current_block = self.blocks.get(i).expect("has to exist");
            let previous_block = self.blocks.get(i - 1).expect("has to exist");

            if !current_block.has_valid_transactions() {
                return false;
            }

            // if one block fails validation, they all fail
            if !current_block.is_valid(previous_block) {
                return false;
            }
        }

        return true;
    }

    pub fn get_balance_for_address(&self, address: String) -> i32 {
        let mut balance: i32 = 0;
        for block in self.blocks.iter() {
            for transaction in block.transactions.iter() {
                if transaction.to_address == address {
                    balance += transaction.amount;
                } else if transaction.from_address == address {
                    balance -= transaction.amount;
                }
            }
        }

        balance
    }

    pub fn choose_chain<'a>(local: &'a Self, remote: &'a Self) -> &'a Self {
        let is_local_valid = local.is_valid();
        let is_remote_valid = remote.is_valid();

        if is_local_valid && is_remote_valid {
            if local.len() > remote.len() {
                return local;
            } else {
                return remote;
            }
        } else if is_remote_valid && !is_local_valid {
            return remote;
        } else if !is_remote_valid && is_local_valid {
            return local;
        } else {
            panic!("local and remote chains are both invalid");
        }
    }

    fn len(&self) -> usize {
        self.blocks.len()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    from_address: String,
    to_address: String,
    amount: i32,
    reference: String,
    signature: Option<Vec<u8>>,
}

impl Transaction {
    pub fn sign(&mut self, key_pair: KeyPair) {
        let hash = self.calculate_hash();
        let signature = key_pair.sk.sign(hash, Some(Noise::default()));
        self.signature = Some(signature.as_ref().to_vec());
    }

    pub fn is_valid(&self) -> bool {
        if self.from_address == MINING_ADDRESS.to_string() {
            return true;
        }

        if self.signature == None {
            return false;
        }

        let public_key = PublicKey::from_pem(&self.from_address).expect("Invalid `from_address`");
        let sig: Signature = match Signature::from_slice(self.signature.as_ref().unwrap()) {
            Ok(s) => s,
            _ => return false,
        };

        match public_key.verify(self.calculate_hash(), &sig) {
            Ok(_) => true,
            _ => false,
        }
    }

    fn calculate_hash(&self) -> Vec<u8> {
        let data = serde_json::json!({
            "from_address": self.from_address,
            "to_address": self.to_address,
            "amount": self.amount,
            "reference": self.reference,
        });

        let mut hasher = Sha256::new();
        hasher.update(data.to_string().as_bytes());

        hasher.finalize().as_slice().to_owned()
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: i64,
    pub transactions: Vec<Transaction>,
    pub nonce: u64,
}
impl Block {
    pub fn new(difficulty: i32, previous_hash: String, transactions: Vec<Transaction>) -> Self {
        let now = Utc::now();

        let (nonce, hash) = Self::mine(difficulty, now.timestamp(), &previous_hash, &transactions);

        Self {
            hash,
            timestamp: now.timestamp(),
            previous_hash,
            transactions,
            nonce,
        }
    }

    pub fn is_valid(&self, previous_block: &Block) -> bool {
        if self.previous_hash != previous_block.hash {
            warn!("block {} has wrong previous hash", self.timestamp);
            return false;
        } else if !Self::hash_to_binary_representation(
            &hex::decode(&self.hash).expect("can decode from hex"),
        )
        .starts_with(DIFFICULTY_PREFIX)
        {
            warn!("block {} has invalid difficulty", self.timestamp);
            return false;
        } else if hex::encode(Self::calculate_hash(
            self.timestamp,
            &self.previous_hash,
            &self.transactions,
            self.nonce,
        )) != self.hash
        {
            warn!("block {} has invalid hash", self.timestamp);
            return false;
        }

        return true;
    }

    pub fn has_valid_transactions(&self) -> bool {
        for tx in &self.transactions {
            if !tx.is_valid() {
                return false;
            }
        }

        true
    }

    fn mine(
        difficulty: i32,
        timestamp: i64,
        previous_hash: &str,
        transactions: &Vec<Transaction>,
    ) -> (u64, String) {
        info!("mining block...");

        let difficulty_prefix = (0..difficulty).map(|_| "0").collect::<String>();

        let mut nonce = 0;
        loop {
            if nonce % 100000 == 0 {
                info!("nonce: {}", nonce);
            }

            let hash = Self::calculate_hash(timestamp, previous_hash, transactions, nonce);
            let binary_hash = Self::hash_to_binary_representation(&hash);
            if binary_hash.starts_with(&difficulty_prefix) {
                info!(
                    "mined $$$$$$$$$$$$$$$! nonce: {}, hash: {}, binary hash: {}",
                    nonce,
                    hex::encode(&hash),
                    binary_hash
                );

                return (nonce, hex::encode(hash));
            }

            nonce += 1;
        }
    }

    fn calculate_hash(
        timestamp: i64,
        previous_hash: &str,
        transactions: &Vec<Transaction>,
        nonce: u64,
    ) -> Vec<u8> {
        let data = serde_json::json!({
            "previous_hash": previous_hash,
            "transactions": transactions,
            "timestamp": timestamp,
            "nonec": nonce,
        });

        let mut hasher = Sha256::new();
        hasher.update(data.to_string().as_bytes());

        hasher.finalize().as_slice().to_owned()
    }

    fn hash_to_binary_representation(hash: &[u8]) -> String {
        let mut res: String = String::default();
        for c in hash {
            res.push_str(&format!("{:b}", c));
        }

        res
    }
}

fn main() {
    env_logger::init();

    let chain = &mut Chain::new("ABC".to_string());
    let transaction_1 = Transaction {
        from_address: "A".to_string(),
        to_address: "B".to_string(),
        amount: 2,
        reference: String::from("my transaction"),
    };
    let transaction_2 = Transaction {
        from_address: "A".to_string(),
        to_address: "B".to_string(),
        amount: 3,
        reference: String::from("my transaction"),
    };
    chain.add_transaction(transaction_1);
    chain.add_transaction(transaction_2);
    println!("{:#?}", chain);
    println!("valid: {:#?}", chain.is_valid());

    println!("balance for `A`: {:#?}", chain.get_balance_for_address("A".to_string()));
    println!("balance for `B`: {:#?}", chain.get_balance_for_address("B".to_string()));
    println!("balance for `ABC`, AKA, The Miner: {:#?}", chain.get_balance_for_address("ABC".to_string()));

    println!("Hello, world!");
}
