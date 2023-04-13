use super::*;
use crate::Hash256;
use anyhow::Result;
use ssz_rs::prelude::*;

pub trait SigningRoot {
    fn compute_signing_root(&mut self, domain: &Hash256) -> Result<Hash256>;
}

#[derive(PartialEq, Eq, Debug, Default, SimpleSerialize)]
struct Bytes32 {
    pub beacon_block_root: [u8; 32],
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct SszU64(pub u64);

impl SigningRoot for SszU64 {
    fn compute_signing_root(&mut self, domain: &Hash256) -> Result<Hash256> {
        let root = InternalSigningData {
            object_root: self.hash_tree_root()?,
            domain: *domain.as_fixed_bytes(),
        }
        .hash_tree_root()?;
        Ok(Hash256::from_slice(root.as_ref()))
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalBeaconBlockHeader {
    pub slot: u64,
    pub proposer_index: u64,
    pub parent_root: [u8; 32],
    pub state_root: [u8; 32],
    pub body_root: [u8; 32],
}

impl TryFrom<&BeaconBlockHeader> for InternalBeaconBlockHeader {
    type Error = anyhow::Error;

    fn try_from(value: &BeaconBlockHeader) -> Result<Self, Self::Error> {
        Ok(Self {
            slot: value.slot,
            proposer_index: value.proposer_index,
            parent_root: *value.parent_root.as_fixed_bytes(),
            state_root: *value.state_root.as_fixed_bytes(),
            body_root: *value.body_root.as_fixed_bytes(),
        })
    }
}

impl SigningRoot for InternalBeaconBlockHeader {
    fn compute_signing_root(&mut self, domain: &Hash256) -> Result<Hash256> {
        let root = InternalSigningData {
            object_root: self.hash_tree_root()?,
            domain: *domain.as_fixed_bytes(),
        }
        .hash_tree_root()?;
        Ok(Hash256::from_slice(root.as_ref()))
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalForkData {
    pub current_version: [u8; 4],
    pub genesis_validators_root: [u8; 32],
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalSigningData {
    pub object_root: Node,
    pub domain: [u8; 32],
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalCheckpoint {
    pub epoch: u64,
    pub root: [u8; 32],
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalVoluntaryExit {
    pub epoch: u64,
    pub validator_index: u64,
}

impl TryFrom<&VoluntaryExit> for InternalVoluntaryExit {
    type Error = anyhow::Error;

    fn try_from(value: &VoluntaryExit) -> Result<Self, Self::Error> {
        Ok(Self {
            epoch: value.epoch,
            validator_index: value.validator_index,
        })
    }
}

impl SigningRoot for InternalVoluntaryExit {
    fn compute_signing_root(&mut self, domain: &Hash256) -> Result<Hash256> {
        let root = InternalSigningData {
            object_root: self.hash_tree_root()?,
            domain: *domain.as_fixed_bytes(),
        }
        .hash_tree_root()?;
        Ok(Hash256::from_slice(root.as_ref()))
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalAttestationData {
    pub slot: u64,
    pub index: u64,
    pub beacon_block_root: [u8; 32],
    pub source: InternalCheckpoint,
    pub target: InternalCheckpoint,
}

impl TryFrom<&AttestationData> for InternalAttestationData {
    type Error = anyhow::Error;

    fn try_from(value: &AttestationData) -> Result<Self, Self::Error> {
        Ok(Self {
            slot: value.slot,
            index: value.index,
            beacon_block_root: *value.beacon_block_root.as_fixed_bytes(),
            source: InternalCheckpoint {
                epoch: value.source.epoch,
                root: *value.source.root.as_fixed_bytes(),
            },
            target: InternalCheckpoint {
                epoch: value.target.epoch,
                root: *value.target.root.as_fixed_bytes(),
            },
        })
    }
}

impl SigningRoot for InternalAttestationData {
    fn compute_signing_root(&mut self, domain: &Hash256) -> Result<Hash256> {
        let root = InternalSigningData {
            object_root: self.hash_tree_root()?,
            domain: *domain.as_fixed_bytes(),
        }
        .hash_tree_root()?;
        Ok(Hash256::from_slice(root.as_ref()))
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalAttestation {
    pub aggregation_bits: Bitlist<2048>, //TODO: the size of bit list is supposed to be maxValidatorsPerCommittee. Mainnet contains 2048
    pub data: InternalAttestationData,
    pub signature: Vector<u8, 96>,
}

impl TryFrom<&Attestation> for InternalAttestation {
    type Error = anyhow::Error;

    fn try_from(value: &Attestation) -> Result<Self, Self::Error> {
        let aggregation_bits: Bitlist<2048> = Bitlist::try_from(value.aggregation_bits.as_slice())?;
        let data = InternalAttestationData::try_from(&value.data)?;
        let signature = Vector::<u8, 96>::try_from(value.signature.clone())
            .map_err(|_| anyhow::anyhow!("Error converting signature bytes to ssz Vector"))?;

        Ok(Self {
            aggregation_bits,
            data,
            signature,
        })
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalAggregateAndProof {
    pub aggregator_index: u64,
    pub aggregate: InternalAttestation,
    pub selection_proof: Vector<u8, 96>,
}

impl TryFrom<&AggregateAndProof> for InternalAggregateAndProof {
    type Error = anyhow::Error;

    fn try_from(value: &AggregateAndProof) -> Result<Self, Self::Error> {
        let aggregator_index = value.aggregator_index;
        let aggregate = InternalAttestation::try_from(&value.aggregate)?;
        let selection_proof = Vector::<u8, 96>::try_from(value.selection_proof.clone())
            .map_err(|_| anyhow::anyhow!("Error converting selection_proof bytes to ssz Vector"))?;

        Ok(Self {
            aggregator_index,
            aggregate,
            selection_proof,
        })
    }
}

impl SigningRoot for InternalAggregateAndProof {
    fn compute_signing_root(&mut self, domain: &Hash256) -> Result<Hash256> {
        let root = InternalSigningData {
            object_root: self.hash_tree_root()?,
            domain: *domain.as_fixed_bytes(),
        }
        .hash_tree_root()?;
        Ok(Hash256::from_slice(root.as_ref()))
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalDepositMessage {
    pub pubkey: Vector<u8, 48>,
    pub withdrawal_credentials: [u8; 32],
    pub amount: u64,
}

impl TryFrom<&DepositMessage> for InternalDepositMessage {
    type Error = anyhow::Error;

    fn try_from(value: &DepositMessage) -> Result<Self, Self::Error> {
        let pubkey = Vector::<u8, 48>::try_from(value.pubkey.clone())
            .map_err(|_| anyhow::anyhow!("Error converting pubkey bytes to ssz Vector"))?;
        let withdrawal_credentials = *value.withdrawal_credentials.as_fixed_bytes();
        let amount = value.amount;

        Ok(Self {
            pubkey,
            withdrawal_credentials,
            amount,
        })
    }
}

impl SigningRoot for InternalDepositMessage {
    fn compute_signing_root(&mut self, domain: &Hash256) -> Result<Hash256> {
        let root = InternalSigningData {
            object_root: self.hash_tree_root()?,
            domain: *domain.as_fixed_bytes(),
        }
        .hash_tree_root()?;
        Ok(Hash256::from_slice(root.as_ref()))
    }
}

impl Domain for ForkInfo {
    fn compute_domain(&self, domain_type: &DomainType, epoch: u64) -> Result<Hash256> {
        let fork_version = if epoch < self.fork.epoch {
            self.fork.previous_version
        } else {
            self.fork.current_version
        };

        let mut fork_data = InternalForkData {
            current_version: fork_version,
            genesis_validators_root: *self.genesis_validators_root.as_fixed_bytes(),
        };

        let fork_data_root = fork_data.hash_tree_root()?;
        let domain_root = [&domain_type.value(), &fork_data_root.as_ref()[..28]].concat();

        Ok(Hash256::from_slice(&domain_root))
    }
}

impl DepositMessage {
    pub fn compute_domain(&self) -> Result<Hash256> {
        let domain_type = DomainType::Deposit;

        let mut fork_data = InternalForkData {
            current_version: self.genesis_fork_version,
            genesis_validators_root: [0; 32],
        };

        let fork_data_root = fork_data.hash_tree_root()?;
        let domain_root = [&domain_type.value(), &fork_data_root.as_ref()[..28]].concat();

        Ok(Hash256::from_slice(&domain_root))
    }
}

impl ValidatorRegistration {
    pub fn compute_domain(&self, genesis_fork_version: &[u8; 4]) -> Result<Hash256> {
        let domain_type = DomainType::ApplicationBuilder;

        let mut fork_data = InternalForkData {
            current_version: *genesis_fork_version,
            genesis_validators_root: [0; 32],
        };

        let fork_data_root = fork_data.hash_tree_root()?;
        let domain_root = [&domain_type.value(), &fork_data_root.as_ref()[..28]].concat();

        Ok(Hash256::from_slice(&domain_root))
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalValidatorRegistration {
    pub fee_recipient: Vector<u8, 20>,
    pub gas_limit: u64,
    pub timestamp: u64,
    pub pubkey: Vector<u8, 48>,
}

impl TryFrom<&ValidatorRegistration> for InternalValidatorRegistration {
    type Error = anyhow::Error;

    fn try_from(value: &ValidatorRegistration) -> Result<Self, Self::Error> {
        let fee_recipient = Vector::<u8, 20>::try_from(value.fee_recipient.clone())
            .map_err(|_| anyhow::anyhow!("Error converting fee_recipient bytes to ssz Vector"))?;

        let gas_limit = value.gas_limit;
        let timestamp = value.timestamp;

        let pubkey = Vector::<u8, 48>::try_from(value.pubkey.clone())
            .map_err(|_| anyhow::anyhow!("Error converting pubkey bytes to ssz Vector"))?;

        Ok(Self {
            fee_recipient,
            gas_limit,
            timestamp,
            pubkey,
        })
    }
}

impl SigningRoot for InternalValidatorRegistration {
    fn compute_signing_root(&mut self, domain: &Hash256) -> Result<Hash256> {
        let root = InternalSigningData {
            object_root: self.hash_tree_root()?,
            domain: *domain.as_fixed_bytes(),
        }
        .hash_tree_root()?;
        Ok(Hash256::from_slice(root.as_ref()))
    }
}

impl SyncCommitteeMessage {
    pub fn compute_signing_root(&self, domain: &Hash256) -> Result<Hash256> {
        let mut bytes32 = Bytes32 {
            beacon_block_root: *self.beacon_block_root.as_fixed_bytes(),
        };
        let root = InternalSigningData {
            object_root: bytes32.hash_tree_root()?,
            domain: *domain.as_fixed_bytes(),
        }
        .hash_tree_root()?;
        Ok(Hash256::from_slice(root.as_ref()))
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalSyncAggregatorSelectionData {
    pub slot: u64,
    pub subcommittee_index: u64,
}

impl TryFrom<&SyncAggregatorSelectionData> for InternalSyncAggregatorSelectionData {
    type Error = anyhow::Error;

    fn try_from(value: &SyncAggregatorSelectionData) -> Result<Self, Self::Error> {
        Ok(Self {
            slot: value.slot,
            subcommittee_index: value.subcommittee_index,
        })
    }
}

impl SigningRoot for InternalSyncAggregatorSelectionData {
    fn compute_signing_root(&mut self, domain: &Hash256) -> Result<Hash256> {
        let root = InternalSigningData {
            object_root: self.hash_tree_root()?,
            domain: *domain.as_fixed_bytes(),
        }
        .hash_tree_root()?;
        Ok(Hash256::from_slice(root.as_ref()))
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalSyncCommitteeContribution<const N: usize> {
    pub slot: u64,
    pub beacon_block_root: [u8; 32],
    pub subcommittee_index: u64,
    pub aggregation_bits: Bitvector<N>,
    pub signature: Vector<u8, 96>,
}

impl<const N: usize> TryFrom<&SyncCommitteeContribution> for InternalSyncCommitteeContribution<N> {
    type Error = anyhow::Error;

    fn try_from(value: &SyncCommitteeContribution) -> Result<Self, Self::Error> {
        let slot = value.slot;
        let beacon_block_root = *value.beacon_block_root.as_fixed_bytes();
        let subcommittee_index = value.subcommittee_index;
        let aggregation_bits = Bitvector::try_from(value.aggregation_bits.as_slice())?;
        let signature = Vector::<u8, 96>::try_from(value.signature.clone())
            .map_err(|_| anyhow::anyhow!("Error converting signature bytes to ssz Vector"))?;

        Ok(Self {
            slot,
            beacon_block_root,
            subcommittee_index,
            aggregation_bits,
            signature,
        })
    }
}

#[derive(PartialEq, Eq, Debug, Default, Clone, SimpleSerialize)]
pub struct InternalContributionAndProof<const N: usize> {
    pub aggregator_index: u64,
    pub contribution: InternalSyncCommitteeContribution<N>,
    pub selection_proof: Vector<u8, 96>,
}

impl<const N: usize> TryFrom<&ContributionAndProof> for InternalContributionAndProof<N> {
    type Error = anyhow::Error;

    fn try_from(value: &ContributionAndProof) -> Result<Self, Self::Error> {
        let aggregator_index = value.aggregator_index;
        let contribution = InternalSyncCommitteeContribution::try_from(&value.contribution)?;
        let selection_proof = Vector::<u8, 96>::try_from(value.selection_proof.clone())
            .map_err(|_| anyhow::anyhow!("Error converting selection_proof bytes to ssz Vector"))?;

        Ok(Self {
            aggregator_index,
            contribution,
            selection_proof,
        })
    }
}

impl<const N: usize> InternalContributionAndProof<N> {
    pub fn compute_signing_root(&mut self, domain: &Hash256) -> Result<Hash256> {
        let root = InternalSigningData {
            object_root: self.hash_tree_root()?,
            domain: *domain.as_fixed_bytes(),
        }
        .hash_tree_root()?;
        Ok(Hash256::from_slice(root.as_ref()))
    }
}
