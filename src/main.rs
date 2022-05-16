#[macro_use] extern crate log;

use chrono::Utc;
use log::{error, info, warn};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DIFFICULTY_PREFIX: &str = "00";
const DIFFICULTY_LEVEL: i32 = 2;

fn hash_to_binary_representation(hash: &[u8]) -> String {
    let mut res: String = String::default();
    for c in hash {
        res.push_str(&format!("{:b}", c));
    }

    res
}

fn mine_block(id: u64, timestamp: i64, previous_hash: &str, data: &str) -> (u64, String) {
    info!("mining block...");

    let mut nonce = 0;
    loop {
        if nonce % 100000 == 0 {
            info!("nonce: {}", nonce);
        }

        let hash = calculate_hash(id, timestamp, previous_hash, data, nonce);
        let binary_hash = hash_to_binary_representation(&hash);
        if binary_hash.starts_with(DIFFICULTY_PREFIX) {
            info!(
                "mined! nonce: {}, hash: {}, binary hash: {}",
                nonce,
                hex::encode(&hash),
                binary_hash
            );

            return (nonce, hex::encode(hash));
        }

        nonce += 1;
    }
}

fn calculate_hash(id: u64, timestamp: i64, previous_hash: &str, data: &str, nonce: u64) -> Vec<u8> {
    let data = serde_json::json!({
        "id": id,
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
            id: 0,
            timestamp: Utc::now().timestamp(),
            previous_hash: String::from("genesis"),
            data: String::from("genesis!"),
            nonce: 2836,
            hash: "0000f816a87f806bb0073dcf026a64fb40c946b5abee2573702828694d5b4c43".to_string(),
        }
    }

    pub fn add_block(&mut self, new_block: NewBlock) {
        let previous_block = self.blocks.last().expect("there is at least one block");
        let block_to_add = Block::new(DIFFICULTY_LEVEL, previous_block.id + 1, previous_block.hash.clone(), new_block.data);

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
            warn!("block with id: {} has wrong previous hash", block.id);
            return false;
        } else if !hash_to_binary_representation(
            &hex::decode(&block.hash).expect("can decode from hex"),
        )
        .starts_with(DIFFICULTY_PREFIX)
        {
            warn!("block with id: {} has invalid difficulty", block.id);
            return false;
        } else if block.id != previous_block.id + 1 {
            warn!(
                "block with id: {} is not the next block after the latest: {}",
                block.id, previous_block.id
            );
            return false;
        } else if hex::encode(calculate_hash(
            block.id,
            block.timestamp,
            &block.previous_hash,
            &block.data,
            block.nonce,
        )) != block.hash
        {
            warn!("block with id: {} has invalid hash", block.id);
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

    fn choose_chain(&mut self, local: Vec<Block>, remote: Vec<Block>) -> Vec<Block> {
        let is_local_valid = self.is_chain_valid(&local);
        let is_remote_valid = self.is_chain_valid(&remote);

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
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Block {
    pub id: u64,
    pub hash: String,
    pub previous_hash: String,
    pub timestamp: i64,
    pub data: String,
    pub nonce: u64,
}
impl Block {
    pub fn new(difficulty: i32, id: u64, previous_hash: String, data: String) -> Self {
        let now = Utc::now();

        let (nonce, hash) = Self::mine(difficulty, id, now.timestamp(), &previous_hash, &data);

        Self {
            id,
            hash,
            timestamp: now.timestamp(),
            previous_hash,
            data,
            nonce,
        }
    }

    pub fn is_valid(&self, previous_block: &Block) -> bool {
        if self.previous_hash != previous_block.hash {
            warn!("block with id: {} has wrong previous hash", self.id);
            return false;
        } else if !hash_to_binary_representation(
            &hex::decode(&self.hash).expect("can decode from hex"),
        )
            .starts_with(DIFFICULTY_PREFIX)
        {
            warn!("block with id: {} has invalid difficulty", self.id);
            return false;
        } else if self.id != previous_block.id + 1 {
            warn!(
                "block with id: {} is not the next block after the latest: {}",
                self.id, previous_block.id
            );
            return false;
        } else if hex::encode(calculate_hash(
            self.id,
            self.timestamp,
            &self.previous_hash,
            &self.data,
            self.nonce,
        )) != self.hash
        {
            warn!("block with id: {} has invalid hash", self.id);
            return false;
        }

        return true;
    }

    fn mine(difficulty: i32, id: u64, timestamp: i64, previous_hash: &str, data: &str) -> (u64, String) {
        info!("mining block...");

        let difficulty_prefix = (0..difficulty).map(|_| "0").collect::<String>();

        let mut nonce = 0;
        loop {
            if nonce % 100000 == 0 {
                info!("nonce: {}", nonce);
            }

            let hash = calculate_hash(id, timestamp, previous_hash, data, nonce);
            let binary_hash = hash_to_binary_representation(&hash);
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
    let new_block = Block::new(DIFFICULTY_LEVEL, 1, String::from("123"), String::from("Invalid!!"));
    chain.blocks.push(new_block);
    println!("valid: {:#?}", chain.is_valid());

    println!("Hello, world!");
}
