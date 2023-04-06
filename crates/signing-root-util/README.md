## Signing Root Util

This crate provide methods to compute signing roots as required by consensus layer.
Following methods are supported:

- [x] `signing_root_for_sign_block_header` (Bellatrix and onward)
- [x] `signing_root_for_sign_attestation_data`
- [x] `signing_root_for_sign_aggregate_and_proof`
- [x] `signing_root_for_sign_aggegation_slot`
- [x] `signing_root_for_randao_reveal`
- [x] `signing_root_for_voluntary_exit`
- [x] `signing_root_for_deposit`
Altair fork
- [ ] `signing_root_for_sync_committee_message`
- [ ] `signing_root_for_sync_aggregator_selection_data` (SYNC_COMMITTEE_SELECTION_PROOF)
- [ ] `signing_root_for_sync_committee_contribution_and_proof`
Builder API
- [ ] `signing_root_for_validator_registration`
