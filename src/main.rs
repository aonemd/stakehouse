#[macro_use] extern crate log;

use chrono::Utc;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DIFFICULTY_PREFIX: &str = "00";
const DIFFICULTY_LEVEL: i32 = 2;


        nonce += 1;
    }
}

fn calculate_hash(timestamp: i64, previous_hash: &str, data: &str, nonce: u64) -> Vec<u8> {
    let data = serde_json::json!({
        "previous_hash": previous_hash,
        "data": data,
        "timestamp": timestamp,
        "nonec": nonce,
    });

    let mut hasher = Sha256::new();
    hasher.update(data.to_string().as_bytes());

    hasher.finalize().as_slice().to_owned()
}

#[derive(Debug)]
pub struct Chain {
    pub blocks: Vec<Block>,
}
impl Chain {
    pub fn new() -> Self {
        Self { blocks: vec![Self::genesis()] }
    }

    fn genesis() -> Block {
        Block {
            timestamp: Utc::now().timestamp(),
            previous_hash: String::from("genesis"),
            data: String::from("genesis!"),
            nonce: 2836,
            hash: "0000f816a87f806bb0073dcf026a64fb40c946b5abee2573702828694d5b4c43".to_string(),
        }
    }

    pub fn add_block(&mut self, new_block: NewBlock) {
        let previous_block = self.blocks.last().expect("there is at least one block");
        let block_to_add = Block::new(DIFFICULTY_LEVEL, previous_block.hash.clone(), new_block.data);

        if block_to_add.is_valid(previous_block) {
            self.blocks.push(block_to_add);
        } else {
            error!("could not add block -- invalid");
        }
    }

    pub fn is_valid(&self) -> bool {
        for i in 1..self.blocks.len() {
            // ignore the genesis block -- the one before it all started

            let current_block  = self.blocks.get(i).expect("has to exist");
            let previous_block = self.blocks.get(i - 1).expect("has to exist");

            // if one block fails validation, they all fail
            if !self.is_block_valid(current_block, previous_block) {
                return false;
            }
        }

        return true;
    }

    fn try_add_block(&mut self, block: Block) -> () {
        let latest_block = self.blocks.last().expect("there is at least one block");
        if self.is_block_valid(&block, latest_block) {
            self.blocks.push(block);
        } else {
            error!("could not add block -- invalid");
        }
    }

    fn is_block_valid(&self, block: &Block, previous_block: &Block) -> bool {
        if block.previous_hash != previous_block.hash {
            return false;
        } else if !hash_to_binary_representation(
            &hex::decode(&block.hash).expect("can decode from hex"),
        )
        .starts_with(DIFFICULTY_PREFIX)
        {
            return false;
        } else if hex::encode(calculate_hash(
            block.timestamp,
            &block.previous_hash,
            &block.data,
            block.nonce,
        )) != block.hash
        {
            return false;
        }

        return true;
    }

    fn is_chain_valid(&self, chain: &[Block]) -> bool {
        for i in 0..chain.len() {
            // ignore the genesis block -- the one before ut all started
            if i == 0 {
                continue;
            }

            let first = chain.get(i - 1).expect("has to exist");
            let second = chain.get(i).expect("has to exist");
            // if one block fails validation, they all fail
            if !self.is_block_valid(second, first) {
                return false;
            }
        }

        return true;
    }

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Transaction {
    data: String,
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

    fn mine(difficulty: i32, timestamp: i64, previous_hash: &str, transactions: &Vec<Transaction>) -> (u64, String) {
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

    fn calculate_hash(timestamp: i64, previous_hash: &str, transactions: &Vec<Transaction>, nonce: u64) -> Vec<u8> {
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


#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct NewBlock {
    pub data: String,
}

fn main() {
    env_logger::init();

    let mut chain = &mut Chain::new();
    let new_block = NewBlock { data: String::from("data") };
    chain.add_block(new_block);
    println!("{:#?}", chain);
    println!("valid: {:#?}", chain.is_valid());
    let new_block = Block::new(DIFFICULTY_LEVEL, String::from("123"), String::from("Invalid!!"));
    chain.blocks.push(new_block);
    println!("valid: {:#?}", chain.is_valid());

    println!("Hello, world!");
}
