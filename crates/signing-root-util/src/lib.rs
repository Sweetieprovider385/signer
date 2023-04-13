//! Library that exposes various datastructures and ssz hash tree root computation

mod internal;
#[cfg(test)]
mod tests;
pub mod types;

use crate::internal::*;
use crate::types::*;
use anyhow::Result;
use specs::{Spec, SYNC_COMMITTEE_CONT_SIZE_MAINNET, SYNC_COMMITTEE_CONT_SIZE_MIMIMAL};

pub struct SigningRootUtil<'a> {
    spec: &'a Spec,
}

impl<'a> SigningRootUtil<'a> {
    pub fn new(spec: &'a Spec) -> Self {
        SigningRootUtil { spec }
    }

    pub fn signing_root_for_sign_block_header(
        &self,
        block_header: &BeaconBlockHeader,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        let epoch = self.spec.compute_epoch_at_slot(block_header.slot);
        let domain = fork_info.compute_domain(&DomainType::BeaconProposer, epoch)?;

        InternalBeaconBlockHeader::try_from(block_header)?.compute_signing_root(&domain)
    }

    pub fn signing_root_for_randao_reveal(
        &self,
        randao_reveal: &RandaoReveal,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        let domain = fork_info.compute_domain(&DomainType::Randao, randao_reveal.epoch)?;

        SszU64(randao_reveal.epoch).compute_signing_root(&domain)
    }

    pub fn signing_root_for_voluntary_exit(
        &self,
        voluntary_exit: &VoluntaryExit,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        let domain = fork_info.compute_domain(&DomainType::VoluntaryExit, voluntary_exit.epoch)?;

        InternalVoluntaryExit::try_from(voluntary_exit)?.compute_signing_root(&domain)
    }

    pub fn signing_root_for_sign_attestation_data(
        &self,
        attestation_data: &AttestationData,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        let domain =
            fork_info.compute_domain(&DomainType::BeaconAttester, attestation_data.target.epoch)?;

        InternalAttestationData::try_from(attestation_data)?.compute_signing_root(&domain)
    }

    pub fn signing_root_for_sign_aggegation_slot(
        &self,
        aggregation_slot: &AggregationSlot,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        let epoch = self.spec.compute_epoch_at_slot(aggregation_slot.slot);
        let domain = fork_info.compute_domain(&DomainType::SelectionProof, epoch)?;

        SszU64(aggregation_slot.slot).compute_signing_root(&domain)
    }

    pub fn signing_root_for_sign_aggregate_and_proof(
        &self,
        aggregate_and_proof: &AggregateAndProof,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        let epoch = self
            .spec
            .compute_epoch_at_slot(aggregate_and_proof.aggregate.data.slot);

        let domain = fork_info.compute_domain(&DomainType::AggregateAndProof, epoch)?;

        InternalAggregateAndProof::try_from(aggregate_and_proof)?.compute_signing_root(&domain)
    }

    pub fn signing_root_for_deposit(&self, deposit_message: &DepositMessage) -> Result<Hash256> {
        let domain = deposit_message.compute_domain()?;
        InternalDepositMessage::try_from(deposit_message)?.compute_signing_root(&domain)
    }

    pub fn signing_root_for_validator_registration(
        &self,
        validator_registration: &ValidatorRegistration,
    ) -> Result<Hash256> {
        let genesis_fork_version = self.spec.genesis_fork_version();
        let domain = validator_registration.compute_domain(&genesis_fork_version)?;
        InternalValidatorRegistration::try_from(validator_registration)?
            .compute_signing_root(&domain)
    }

    pub fn signing_root_for_sync_committee_message(
        &self,
        sync_committee_message: &SyncCommitteeMessage,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        let epoch = self.spec.compute_epoch_at_slot(sync_committee_message.slot);
        let domain = fork_info.compute_domain(&DomainType::SyncCommittee, epoch)?;

        sync_committee_message.compute_signing_root(&domain)
    }

    pub fn signing_root_for_sync_aggregator_selection_data(
        &self,
        sync_aggregator_selection_data: &SyncAggregatorSelectionData,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        let epoch = self
            .spec
            .compute_epoch_at_slot(sync_aggregator_selection_data.slot);

        let domain = fork_info.compute_domain(&DomainType::SyncCommitteeSelectionProof, epoch)?;

        InternalSyncAggregatorSelectionData::try_from(sync_aggregator_selection_data)?
            .compute_signing_root(&domain)
    }

    pub fn signing_root_for_sync_committee_contribution_and_proof(
        &self,
        contribution_and_proof: &ContributionAndProof,
        fork_info: &ForkInfo,
    ) -> Result<Hash256> {
        let epoch = self
            .spec
            .compute_epoch_at_slot(contribution_and_proof.contribution.slot);

        let domain = fork_info.compute_domain(&DomainType::ContributionAndProof, epoch)?;

        if self.spec.is_minimal_preset() {
            InternalContributionAndProof::<SYNC_COMMITTEE_CONT_SIZE_MIMIMAL>::try_from(
                contribution_and_proof,
            )?
            .compute_signing_root(&domain)
        } else {
            InternalContributionAndProof::<SYNC_COMMITTEE_CONT_SIZE_MAINNET>::try_from(
                contribution_and_proof,
            )?
            .compute_signing_root(&domain)
        }
    }
}
