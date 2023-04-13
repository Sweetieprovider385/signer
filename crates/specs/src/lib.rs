//! Consensus presets and specs used by r-signer as defined at
//! https://github.com/ethereum/consensus-specs/tree/dev/specs and
//! https://github.com/ethereum/consensus-specs/tree/dev/presets
//!

#[cfg(test)]
mod tests;

use anyhow::{anyhow, Context, Result};
use figment::{
    providers::{Format, Yaml},
    Figment,
};
use serde::Deserialize;
use std::fs::File;
use std::io::prelude::*;
use std::path::Path;

const PRESETS_MINIMAL: [&str; 5] = [
    include_str!("../presets/minimal/phase0.yaml"),
    include_str!("../presets/minimal/altair.yaml"),
    include_str!("../presets/minimal/bellatrix.yaml"),
    include_str!("../presets/minimal/capella.yaml"),
    include_str!("../presets/minimal/deneb.yaml"),
];

const PRESETS_MAINNET: [&str; 5] = [
    include_str!("../presets/mainnet/phase0.yaml"),
    include_str!("../presets/mainnet/altair.yaml"),
    include_str!("../presets/mainnet/bellatrix.yaml"),
    include_str!("../presets/mainnet/capella.yaml"),
    include_str!("../presets/mainnet/deneb.yaml"),
];

static PREDEFINED_CONFIGS: phf::Map<&'static str, &'static str> = phf::phf_map! {
    "minimal" => include_str!("../configs/minimal/config.yaml"),
    "mainnet" => include_str!("../configs/mainnet/config.yaml")
};

// use constants instead of deriving from the preset yaml files
const SYNC_COMMITTEE_SUBNET_COUNT: usize = 4;
pub const SYNC_COMMITTEE_CONT_SIZE_MAINNET: usize = 512 / SYNC_COMMITTEE_SUBNET_COUNT;
pub const SYNC_COMMITTEE_CONT_SIZE_MIMIMAL: usize = 32 / SYNC_COMMITTEE_SUBNET_COUNT;

#[derive(Debug, PartialEq, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub struct Spec {
    //../configs/mainnet.yaml
    preset_base: String,
    config_name: String,
    // commenting out fields which are not used for signing root calculation and have difficulty in
    // serde yaml deserialization
    //terminal_total_difficulty: U256,
    //terminal_block_hash: U256, //hex
    //terminal_block_hash_activation_epoch: u64,
    min_genesis_active_validator_count: u64,
    min_genesis_time: u64,
    genesis_fork_version: u32,
    genesis_delay: u64,
    altair_fork_version: u32,
    altair_fork_epoch: u64,
    bellatrix_fork_version: u32,
    bellatrix_fork_epoch: u64,
    capella_fork_version: u32,
    capella_fork_epoch: u64,
    deneb_fork_version: u32,
    deneb_fork_epoch: u64,
    seconds_per_slot: u64,
    seconds_per_eth1_block: u64,
    min_validator_withdrawability_delay: u64,
    shard_committee_period: u64,
    eth1_follow_distance: u64,
    inactivity_score_bias: u64,
    inactivity_score_recovery_rate: u64,
    ejection_balance: u64,
    min_per_epoch_churn_limit: u64,
    churn_limit_quotient: u64,
    proposer_score_boost: u64,
    deposit_chain_id: u64,
    deposit_network_id: u64,
    //deposit_contract_address: Address, //hex

    //../presets/mainnet/phase0.yaml
    max_committees_per_slot: u64,
    target_committee_size: u64,
    max_validators_per_committee: u64, // used in 'Attestation' to calculate aggregation_bits
    shuffle_round_count: u64,
    hysteresis_quotient: u64,
    hysteresis_downward_multiplier: u64,
    hysteresis_upward_multiplier: u64,
    min_deposit_amount: u64,
    max_effective_balance: u64,
    effective_balance_increment: u64,
    min_attestation_inclusion_delay: u64,
    slots_per_epoch: u64,
    min_seed_lookahead: u64,
    max_seed_lookahead: u64,
    epochs_per_eth1_voting_period: u64,
    slots_per_historical_root: u64,
    min_epochs_to_inactivity_penalty: u64,
    epochs_per_historical_vector: u64,
    epochs_per_slashings_vector: u64,
    historical_roots_limit: u64,
    validator_registry_limit: u64,
    base_reward_factor: u64,
    whistleblower_reward_quotient: u64,
    proposer_reward_quotient: u64,
    inactivity_penalty_quotient: u64,
    min_slashing_penalty_quotient: u64,
    proportional_slashing_multiplier: u64,
    max_proposer_slashings: u64,
    max_attester_slashings: u64,
    max_attestations: u64,
    max_deposits: u64,
    max_voluntary_exits: u64,
    //../presets/mainnet/altair.yaml
    inactivity_penalty_quotient_altair: u64,
    min_slashing_penalty_quotient_altair: u64,
    proportional_slashing_multiplier_altair: u64,
    sync_committee_size: u32,
    epochs_per_sync_committee_period: u64,
    min_sync_committee_participants: u64,
    update_timeout: u64,
    //../presets/mainnet/bellatrix.yaml
    inactivity_penalty_quotient_bellatrix: u64,
    min_slashing_penalty_quotient_bellatrix: u64,
    proportional_slashing_multiplier_bellatrix: u64,
    max_bytes_per_transaction: u64,
    max_transactions_per_payload: u64,
    bytes_per_logs_bloom: u64,
    max_extra_data_bytes: u64,
    //../presets/mainnet/capella.yaml
    max_bls_to_execution_changes: u64,
    max_withdrawals_per_payload: u64,
    max_validators_per_withdrawals_sweep: u64,
    // ../presets/mainnet/deneb.yaml
    field_elements_per_blob: u64,
    max_blobs_per_block: u64,
}

impl Spec {
    pub fn new(network: &str) -> Result<Self> {
        let config_figment = if PREDEFINED_CONFIGS.contains_key(network) {
            let config = PREDEFINED_CONFIGS
                .get(network)
                .ok_or(anyhow!("Predefined config {} does not exist", network))?;

            Figment::new().merge(Yaml::string(config))
        } else {
            let config_path = Path::new(network);
            let mut file = File::open(config_path).with_context(|| {
                format!("Failed to read config file: {}", config_path.display())
            })?;
            let mut contents = String::new();
            file.read_to_string(&mut contents)?;
            Figment::new().merge(Yaml::string(&contents))
        };

        // determine PRESET_BASE and load appropriate preset first, then merge config with it.
        let preset_base_value = config_figment.find_value("PRESET_BASE")?;
        let preset_base = preset_base_value
            .as_str()
            .ok_or(anyhow!("preset_base as_str error"))?;

        let mut preset_figment = Figment::new();
        preset_figment = match preset_base {
            "mainnet" => {
                for presets in PRESETS_MAINNET {
                    preset_figment = preset_figment.merge(Yaml::string(presets));
                }
                preset_figment
            }
            "minimal" => {
                for presets in PRESETS_MINIMAL {
                    preset_figment = preset_figment.merge(Yaml::string(presets));
                }
                preset_figment
            }
            _ => anyhow::bail!("PRESET_BASE not yet supported {}", preset_base),
        };

        preset_figment
            .merge(config_figment)
            .extract()
            .map_err(|e| anyhow!("Error extracting config {}: {}", network, e))
    }

    /// Compute epoch at slot
    pub fn compute_epoch_at_slot(&self, slot: u64) -> u64 {
        slot / self.slots_per_epoch
    }

    pub fn genesis_fork_version(&self) -> [u8; 4] {
        self.genesis_fork_version.to_be_bytes()
    }

    pub fn is_minimal_preset(&self) -> bool {
        self.preset_base.to_lowercase() == "minimal"
    }
}
