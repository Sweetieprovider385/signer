use super::*;

#[test]
fn minimal_specs_works() {
    let spec = Spec::new("minimal").unwrap();
    assert_eq!(spec.max_committees_per_slot, 4);
    assert_eq!(spec.config_name, "minimal");
}

#[test]
fn mainnet_specs_works() {
    let spec = Spec::new("mainnet").unwrap();
    assert_eq!(spec.max_committees_per_slot, 64);
    assert_eq!(spec.config_name, "mainnet");
}

#[test]
fn invalid_network_config() {
    let result = Spec::new("invalid.yaml");
    dbg!(&result);
    assert!(result.is_err());
    assert_eq!(
        result.err().unwrap().to_string(),
        "Failed to read config file: invalid.yaml"
    );
}

#[test]
fn custom_network_config() {
    let spec = Spec::new("tests/custom_network_config.yaml").unwrap();
    assert_eq!(spec.config_name, "end-to-end");
    assert_eq!(spec.genesis_delay, 10);
}
