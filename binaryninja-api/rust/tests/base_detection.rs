use binaryninja::architecture::CoreArchitecture;
use binaryninja::base_detection::{
    BaseAddressDetectionConfidence, BaseAddressDetectionPOIType,
    BaseAddressDetectionSamplingSettings, BaseAddressDetectionSettings,
};
use binaryninja::headless::Session;
use std::path::PathBuf;

#[test]
fn test_base_detection() {
    let _session = Session::new().expect("Failed to initialize session");
    let out_dir = env!("OUT_DIR").parse::<PathBuf>().unwrap();

    let view = binaryninja::load(out_dir.join("raw_base_detection_aarch64"))
        .expect("Failed to create view");
    let bad = view
        .base_address_detection()
        .expect("Failed to create base address detection");
    let arch = CoreArchitecture::list_all()
        .iter()
        .find(|arch| arch.name() == "aarch64")
        .copied()
        .expect("Failed to get aarch64 architecture");
    assert!(
        bad.detect_with_sampling(&BaseAddressDetectionSamplingSettings::default().arch(arch)),
        "Sampling detection should succeed on this view"
    );

    let result = bad.scores(10);
    assert!(!result.scores.is_empty());
    assert_eq!(result.scores[0].base_address, 0x100000000);
    assert_eq!(result.scores[0].score, 4);
    assert_eq!(
        result.confidence,
        BaseAddressDetectionConfidence::LowConfidence
    );

    let reasons = bad.get_reasons(result.scores[0].base_address);
    assert_eq!(reasons.len(), 4);
    assert!(reasons
        .iter()
        .all(|reason| reason.poi_type == BaseAddressDetectionPOIType::POIString));

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
