use super::*;
use hex_literal::hex;

#[test]
fn signing_root_for_sign_block_header_is_calculated() {
    let fork_info_json = r#"{
            "fork":{
                "previous_version":"0x00000001",
                "current_version":"0x00000001",
                "epoch":"1"
             },
            "genesis_validators_root":"0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
           }"#;
    let block_header_json = r#"{
        "slot":"0",
        "proposer_index":"4666673844721362956",
        "parent_root":"0x367cbd40ac7318427aadb97345a91fa2e965daf3158d7f1846f1306305f41bef",
        "state_root":"0xfd18cf40cc907a739be483f1ca0ee23ad65cdd3df23205eabc6d660a75d1f54e",
        "body_root":"0xe74b0fc13f19ae2077403afa03fdc155484f22d05d93eb084473951bb3a8d1ae"
    }"#;
    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();
    let block_header: BeaconBlockHeader = serde_json::from_str(block_header_json).unwrap();

    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);
    let signing_root = signing_root_util
        .signing_root_for_sign_block_header(&block_header, &fork_info)
        .unwrap()
        .to_fixed_bytes();
    assert_eq!(
        signing_root,
        hex!("26d0ee0b6c2261cd6010112a024de4f3d2e1e9844d11d60b057fac344c745464")
    );
}

#[test]
fn signing_root_for_sign_attestation_data_is_calculated() {
    let fork_info_json = r#"{
        "fork" : {
          "previous_version" : "0x00000001",
          "current_version" : "0x00000001",
          "epoch" : "1"
        },
        "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    }"#;
    let attestation_data_json = r#"{
        "slot" : "32",
        "index" : "0",
        "beacon_block_root" : "0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89",
        "source" : {
          "epoch" : "0",
          "root" : "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "target" : {
          "epoch" : "0",
          "root" : "0xb2eedb01adbd02c828d5eec09b4c70cbba12ffffba525ebf48aca33028e8ad89"
        }
    }"#;

    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();
    let attestation_data: AttestationData = serde_json::from_str(attestation_data_json).unwrap();

    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);

    let expected_signing_root =
        hex!("548c9a015f4c96cb8b1ddbbdfca85846f85bf9f344a434c140f378cdfb5341f0");
    let signing_root = *signing_root_util
        .signing_root_for_sign_attestation_data(&attestation_data, &fork_info)
        .unwrap()
        .as_fixed_bytes();

    assert_eq!(signing_root, expected_signing_root);
}

#[test]
fn signing_root_for_sign_aggegation_slot_is_calculated() {
    let fork_info_json = r#"{
        "fork" : {
          "previous_version" : "0x00000001",
          "current_version" : "0x00000001",
          "epoch" : "1"
        },
        "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    }"#;

    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();
    let aggregation_slot = AggregationSlot { slot: 119 };
    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);
    let expected_signing_root =
        hex!("1fb90dd6e8b2670e6949347bc4eaacd37f9b6cc6e42c559973e362c800e853b9");
    let signing_root = *signing_root_util
        .signing_root_for_sign_aggegation_slot(&aggregation_slot, &fork_info)
        .unwrap()
        .as_fixed_bytes();

    assert_eq!(signing_root, expected_signing_root);
}

#[test]
fn signing_root_for_randao_reveal_is_calculated() {
    let fork_info_json = r#"{
        "fork" : {
          "previous_version" : "0x00000001",
          "current_version" : "0x00000001",
          "epoch" : "1"
        },
        "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    }"#;

    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();
    let randao = RandaoReveal { epoch: 3 };
    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);
    let expected_signing_root =
        hex!("3d047c51a8b03630781dc4c5519c17f7de87174246ff2deed0f195c6c775f91e");
    let signing_root = *signing_root_util
        .signing_root_for_randao_reveal(&randao, &fork_info)
        .unwrap()
        .as_fixed_bytes();

    assert_eq!(signing_root, expected_signing_root);
}

#[test]
fn signing_root_for_voluntary_exit_is_calculated() {
    let fork_info_json = r#"{
        "fork" : {
          "previous_version" : "0x00000001",
          "current_version" : "0x00000001",
          "epoch" : "1"
        },
        "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    }"#;

    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();
    let voluntary_exit = VoluntaryExit {
        epoch: 119,
        validator_index: 0,
    };

    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);

    let expected_signing_root =
        hex!("38e9f1cfe7926ce5366b633b7fc7113129025737394002d2637faaeefc56913d");
    let signing_root = *signing_root_util
        .signing_root_for_voluntary_exit(&voluntary_exit, &fork_info)
        .unwrap()
        .as_fixed_bytes();

    assert_eq!(signing_root, expected_signing_root);
}

#[test]
fn signing_root_for_aggregate_and_proof_is_calculated() {
    let fork_info_json = r#"{
        "fork" : {
          "previous_version" : "0x00000001",
          "current_version" : "0x00000001",
          "epoch" : "1"
        },
        "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    }"#;

    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();

    let aggregate_and_proof_json = r#"{
        "aggregator_index" : "1",
        "aggregate" : {
          "aggregation_bits" : "0x00000101",
          "data" : {
            "slot" : "0",
            "index" : "0",
            "beacon_block_root" : "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd",
            "source" : {
              "epoch" : "0",
              "root" : "0x0000000000000000000000000000000000000000000000000000000000000000"
            },
            "target" : {
              "epoch" : "0",
              "root" : "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd"
            }
          },
          "signature" : "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875"
        },
        "selection_proof" : "0xa63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47"
      }"#;

    let aggregate_and_proof: AggregateAndProof =
        serde_json::from_str(aggregate_and_proof_json).unwrap();
    let expected_signing_root =
        hex!("8d777156899cb02e0e66217afd832886239752a59a393218f6c603bcf615b4f8");

    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);
    let computed_signing_root = *signing_root_util
        .signing_root_for_sign_aggregate_and_proof(&aggregate_and_proof, &fork_info)
        .unwrap()
        .as_fixed_bytes();

    assert_eq!(computed_signing_root, expected_signing_root);
}

#[test]
fn ssz_bit_list_hashroot() {
    use ssz_rs::prelude::*;

    #[derive(PartialEq, Eq, Debug, Default, Clone, ssz_rs::prelude::SimpleSerialize)]
    struct Sig {
        aggregation_bits: Bitlist<2048>,
    }

    let bytes = vec![0, 0, 1, 1];

    let aggregation_bits = Bitlist::try_from(bytes.as_slice()).unwrap();

    let mut sig = Sig { aggregation_bits };

    let expected_hash_tree_root =
        hex!("6b26c3291d48791b84c8339906d724f4f2e01b0f881638f07f4ba942b22187db");
    assert_eq!(sig.hash_tree_root().unwrap(), expected_hash_tree_root);
}

#[test]
fn bls_signature_hashroot() {
    use ssz_rs::prelude::*;

    #[derive(PartialEq, Eq, Debug, Default, Clone, ssz_rs::prelude::SimpleSerialize)]
    struct Sig {
        signature: ssz_rs::prelude::Vector<u8, 96>,
    }

    let bls_sig = hex!("a63f73a03f1f42b1fd0a988b614d511eb346d0a91c809694ef76df5ae021f0f144d64e612d735bc8820950cf6f7f84cd0ae194bfe3d4242fe79688f83462e3f69d9d33de71aab0721b7dab9d6960875e5fdfd26b171a75fb51af822043820c47");
    let bls_sig_vec = Vector::<u8, 96>::try_from(bls_sig.to_vec()).unwrap();
    let mut sig = Sig {
        signature: bls_sig_vec,
    };
    let hash_tree_root = sig.hash_tree_root().unwrap();
    let expected_hash_tree_root =
        hex!("c3879079ee826257c8172dab0252c619fa1f51292aba8917178c719189afd174");
    assert_eq!(hash_tree_root, expected_hash_tree_root);
}

#[test]
fn bls_signature_deserialize() {
    #[derive(PartialEq, Eq, Debug, Default, Clone, serde::Serialize, serde::Deserialize)]
    struct Sig {
        #[serde(with = "eth2_serde_utils::hex_vec")]
        signature: Vec<u8>,
    }

    let json_str = r#"
    {
        "signature" : "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875"
    }
    "#;

    let sig: Sig = serde_json::from_str(json_str).unwrap();
    assert_eq!(*sig.signature, hex!("a627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875"))
}

#[test]
fn aggregate_deserialize() {
    let json_str = r#"
    {
      "aggregation_bits" : "0x00000101",
      "data" : {
        "slot" : "0",
        "index" : "0",
        "beacon_block_root" : "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd",
        "source" : {
          "epoch" : "0",
          "root" : "0x0000000000000000000000000000000000000000000000000000000000000000"
        },
        "target" : {
          "epoch" : "0",
          "root" : "0x100814c335d0ced5014cfa9d2e375e6d9b4e197381f8ce8af0473200fdc917fd"
        }
      },
      "signature" : "0xa627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875"
    }
    "#;

    let sig: Attestation = serde_json::from_str(json_str).unwrap();
    assert_eq!(sig.aggregation_bits.as_slice(), hex!("00000101"));
    assert_eq!(*sig.signature, hex!("a627242e4a5853708f4ebf923960fb8192f93f2233cd347e05239d86dd9fb66b721ceec1baeae6647f498c9126074f1101a87854d674b6eebc220fd8c3d8405bdfd8e286b707975d9e00a56ec6cbbf762f23607d490f0bbb16c3e0e483d51875"))
}

#[test]
fn signing_root_for_deposit_is_calculated() {
    let json_str = r#"{
        "pubkey" : "0x8f82597c919c056571a05dfe83e6a7d32acf9ad8931be04d11384e95468cd68b40129864ae12745f774654bbac09b057",
        "withdrawal_credentials" : "0x39722cbbf8b91a4b9045c5e6175f1001eac32f7fcd5eccda5c6e62fc4e638508",
        "amount" : "32",
        "genesis_fork_version" : "0x00000001"
      }"#;
    let deposit_message: DepositMessage = serde_json::from_str(json_str).unwrap();
    let expected_signing_root =
        hex!("3a49cdd70862ee95fed10e7494a8caa16af1be2f53612fc74dad27260bb2d711");

    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);
    let computed_signing_root = *signing_root_util
        .signing_root_for_deposit(&deposit_message)
        .unwrap()
        .as_fixed_bytes();

    assert_eq!(computed_signing_root, expected_signing_root);
}

#[test]
fn signing_root_for_validator_registration_is_calculated() {
    let json_str = r#"{
        "fee_recipient" : "0x6fdfab408c56b6105a76eff5c0435d09fc6ed7a9",
        "gas_limit" : "4658411424342975020",
        "timestamp" : "4663368873993027404",
        "pubkey" : "0x8f82597c919c056571a05dfe83e6a7d32acf9ad8931be04d11384e95468cd68b40129864ae12745f774654bbac09b057"
      }"#;
    let validator_registration: ValidatorRegistration = serde_json::from_str(json_str).unwrap();
    let expected_signing_root =
        hex!("e4d2b3dd1e23807b90af0b1768cc7de12d4353320adb486f1bdaeed6b67009ea");

    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);
    let computed_signing_root = *signing_root_util
        .signing_root_for_validator_registration(&validator_registration)
        .unwrap()
        .as_fixed_bytes();

    assert_eq!(computed_signing_root, expected_signing_root);
}

#[test]
fn signing_root_for_sync_committee_message_is_calculated() {
    let fork_info_json = r#"{
        "fork" : {
          "previous_version" : "0x00000001",
          "current_version" : "0x00000001",
          "epoch" : "1"
        },
        "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    }"#;

    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();

    let json_str = r#"{
        "beacon_block_root" : "0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464",
        "slot" : "0"
      }"#;

    let sync_committee_message: SyncCommitteeMessage = serde_json::from_str(json_str).unwrap();
    let expected_signing_root =
        hex!("a6f60df2817ea5b52eed1fefebbad746ef64c6249fc05c90c9e0f520cc75bb95");

    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);
    let computed_signing_root = *signing_root_util
        .signing_root_for_sync_committee_message(&sync_committee_message, &fork_info)
        .unwrap()
        .as_fixed_bytes();

    assert_eq!(computed_signing_root, expected_signing_root);
}

#[test]
fn signing_root_for_sync_aggregator_selection_data_is_calculated() {
    let fork_info_json = r#"{
        "fork" : {
          "previous_version" : "0x00000001",
          "current_version" : "0x00000001",
          "epoch" : "1"
        },
        "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    }"#;

    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();

    let json_str = r#"{
        "slot" : "0",
        "subcommittee_index" : "0"
      }"#;

    let sync_aggregator_selection_data: SyncAggregatorSelectionData =
        serde_json::from_str(json_str).unwrap();
    let expected_signing_root =
        hex!("50d85c783ab27c1eb3f3efa914b91cb93ffd677137b15c27ba5bb548306e6963");

    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);
    let computed_signing_root = *signing_root_util
        .signing_root_for_sync_aggregator_selection_data(
            &sync_aggregator_selection_data,
            &fork_info,
        )
        .unwrap()
        .as_fixed_bytes();

    assert_eq!(computed_signing_root, expected_signing_root);
}

#[test]
fn signing_root_for_sync_committee_contribution_and_proof_is_calculated() {
    let fork_info_json = r#"{
        "fork" : {
          "previous_version" : "0x00000001",
          "current_version" : "0x00000001",
          "epoch" : "1"
        },
        "genesis_validators_root" : "0x04700007fabc8282644aed6d1c7c9e21d38a03a0c4ba193f3afe428824b3a673"
    }"#;

    let fork_info: ForkInfo = serde_json::from_str(fork_info_json).unwrap();

    let json_str = r#"{
        "aggregator_index" : "11",
        "selection_proof" : "0x8f5c34de9e22ceaa7e8d165fc0553b32f02188539e89e2cc91e2eb9077645986550d872ee3403204ae5d554eae3cac12124e18d2324bccc814775316aaef352abc0450812b3ca9fde96ecafa911b3b8bfddca8db4027f08e29c22a9c370ad933",
        "contribution" : {
          "slot" : "0",
          "beacon_block_root" : "0x235bc3400c2839fd856a524871200bd5e362db615fc4565e1870ed9a2a936464",
          "subcommittee_index" : "1",
          "aggregation_bits" : "0x24",
          "signature" : "0x9005ed0936f527d416609285b355fe6b9610d730c18b9d2f4942ba7d0eb95ba304ff46b6a2fb86f0c756bf09274db8e11399b7642f9fc5ae50b5bd9c1d87654277a19bfc3df78d36da16f44a48630d9550774a4ca9f3a5b55bbf33345ad2ec71"
        }
      }"#;

    let contribution_and_proof: ContributionAndProof = serde_json::from_str(json_str).unwrap();
    let expected_signing_root =
        hex!("ae94702468b584a3b1c422bc1b39cc523d9175ba3b9ac1cccb699c00507cc1a5");

    let spec = Spec::new("minimal").unwrap();
    let signing_root_util = SigningRootUtil::new(&spec);
    let computed_signing_root = *signing_root_util
        .signing_root_for_sync_committee_contribution_and_proof(&contribution_and_proof, &fork_info)
        .unwrap()
        .as_fixed_bytes();

    assert_eq!(computed_signing_root, expected_signing_root);
}
