use binaryninja::base_detection::{BaseAddressDetectionConfidence, BaseAddressDetectionSettings};
use binaryninja::binary_view::BinaryViewExt;
use binaryninja::headless::Session;
use rstest::{fixture, rstest};
use std::path::PathBuf;

#[fixture]
#[once]
fn session() -> Session {
    Session::new().expect("Failed to initialize session")
}

#[rstest]
fn test_base_detection(_session: &Session) {
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();
    let view = binaryninja::load(out_dir.join("raw_base_detection_aarch64"))
        .expect("Failed to create view");
    let bad = view
        .base_address_detection()
        .expect("Failed to create base address detection");
    assert!(
        bad.detect(&BaseAddressDetectionSettings::default()),
        "Detection should succeed on this view"
    );
    let result = bad.scores(10);
    assert_eq!(result.scores.len(), 3);
    assert_eq!(
        result.confidence,
        BaseAddressDetectionConfidence::HighConfidence
    );
}
