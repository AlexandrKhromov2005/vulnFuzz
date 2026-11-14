use serde_json::{Value, json};
use vulnFuzz::model::{
    AnalysisModel, Backend, CampaignManifest, ContractArtifact, CoverageSnapshot, DseAttempt,
    EpisodeResult, Finding, FindingLevel, HexBytes, HexU64, Quality, SolverResult, StepOutcome,
    TestCase,
};

fn example(name: &str) -> &'static str {
    match name {
        "scenario" => include_str!("../docs/contracts/examples/scenario.json"),
        "analysis-model" => include_str!("../docs/contracts/examples/analysis-model.json"),
        "episode-result" => include_str!("../docs/contracts/examples/episode-result.json"),
        "coverage-invalid" => include_str!("../docs/contracts/examples/coverage-invalid.json"),
        "dse-attempt" => include_str!("../docs/contracts/examples/dse-attempt.json"),
        "finding" => include_str!("../docs/contracts/examples/finding.json"),
        "campaign-manifest" => include_str!("../docs/contracts/examples/campaign-manifest.json"),
        _ => panic!("unknown example"),
    }
}

fn scenario() -> TestCase {
    TestCase::from_json(example("scenario")).unwrap()
}

fn analysis() -> AnalysisModel {
    AnalysisModel::from_json(example("analysis-model")).unwrap()
}

fn episode() -> EpisodeResult {
    EpisodeResult::from_json(example("episode-result")).unwrap()
}

fn attempt() -> DseAttempt {
    DseAttempt::from_json(example("dse-attempt")).unwrap()
}

fn round_trip<T>(json: &str)
where
    T: ContractArtifact + Eq + std::fmt::Debug,
{
    let parsed = T::from_json(json).unwrap();
    let encoded = parsed.to_json().unwrap();
    let reparsed = T::from_json(&encoded).unwrap();
    assert_eq!(parsed, reparsed);
    assert_eq!(
        serde_json::from_str::<Value>(json).unwrap(),
        serde_json::from_str::<Value>(&encoded).unwrap()
    );
}

#[test]
fn all_examples_round_trip_and_cross_validate() {
    round_trip::<TestCase>(example("scenario"));
    round_trip::<AnalysisModel>(example("analysis-model"));
    round_trip::<EpisodeResult>(example("episode-result"));
    round_trip::<CoverageSnapshot>(example("coverage-invalid"));
    round_trip::<DseAttempt>(example("dse-attempt"));
    round_trip::<Finding>(example("finding"));
    round_trip::<CampaignManifest>(example("campaign-manifest"));

    let scenario = scenario();
    let analysis = analysis();
    episode().validate_against(&scenario, &analysis).unwrap();
    let attempt = attempt();
    let patched = attempt.validate_against(&scenario, &analysis).unwrap();
    assert_eq!(attempt.patched_scenario_id, Some(patched.scenario_id));
    Finding::from_json(example("finding"))
        .unwrap()
        .validate_against_dse(&attempt)
        .unwrap();
}

#[test]
fn hex_u64_is_lossless_and_strict() {
    assert_eq!(
        serde_json::from_str::<HexU64>("\"0xffffffffffffffff\"")
            .unwrap()
            .get(),
        u64::MAX
    );
    assert_eq!(
        serde_json::to_string(&HexU64(u64::MAX)).unwrap(),
        "\"0xffffffffffffffff\""
    );
    for invalid in [
        "0xfffffffffffffff",
        "0x10000000000000000",
        "0X0000000000000000",
        "0xABCDEF0000000000",
        "0x000000000000000g",
        "0",
    ] {
        serde_json::from_str::<HexU64>(&format!("\"{invalid}\"")).unwrap_err();
    }
    serde_json::from_str::<HexU64>("18446744073709551615").unwrap_err();

    assert_eq!(
        serde_json::from_str::<HexBytes>("\"00ff\"")
            .unwrap()
            .as_bytes(),
        [0, 255]
    );
    for invalid in ["0", "FF", "00gg", "00 1"] {
        serde_json::from_str::<HexBytes>(&format!("\"{invalid}\"")).unwrap_err();
    }
}

#[test]
fn canonical_hashes_are_stable_and_action_order_is_semantic() {
    let scenario = scenario();
    assert_eq!(
        scenario.compute_scenario_id().unwrap().as_str(),
        "sha256:3d9d60e3c841cfd0918953c619e683ea49c16283524124fbd7827efd2ebae523"
    );
    let mut reordered = scenario.clone();
    reordered.actions.swap(1, 2);
    assert_ne!(
        reordered.compute_scenario_id().unwrap(),
        scenario.scenario_id
    );
    reordered.refresh_scenario_id().unwrap();
    reordered.validate().unwrap();

    let analysis: AnalysisModel = serde_json::from_str(example("analysis-model")).unwrap();
    assert_eq!(
        analysis.compute_analysis_revision().unwrap().as_str(),
        "sha256:6e85000e871f81869f1657b8a6d2bd30ad19cb8fe015f9daafe337ab269ec1a9"
    );
    let mut reordered = analysis.clone();
    reordered.blocks.reverse();
    reordered.edges.reverse();
    reordered.unknown_regions.reverse();
    reordered.executable_ranges.reverse();
    assert_eq!(
        reordered.compute_analysis_revision().unwrap(),
        analysis.analysis_revision
    );
    reordered.validate().unwrap();
}

#[test]
fn unknown_schema_artifact_fields_and_actions_are_rejected() {
    let original: Value = serde_json::from_str(example("scenario")).unwrap();
    let mut unknown_field = original.clone();
    unknown_field["unknown"] = json!(true);
    TestCase::from_json(&unknown_field.to_string()).unwrap_err();
    let mut unknown_vm_field = original.clone();
    unknown_vm_field["vm"]["unknown"] = json!(true);
    TestCase::from_json(&unknown_vm_field.to_string()).unwrap_err();
    let mut unknown_action_field = original.clone();
    unknown_action_field["actions"][0]["unknown"] = json!(true);
    TestCase::from_json(&unknown_action_field.to_string()).unwrap_err();
    for (pointer, value) in [
        ("/schema_version", json!("vulnFuzz/v1")),
        ("/artifact", json!("episode_result")),
        ("/actions/0/kind", json!("network_input")),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        TestCase::from_json(&changed.to_string()).unwrap_err();
    }
}

#[test]
fn foreign_runtime_and_analysis_ids_are_rejected() {
    let scenario = scenario();
    let analysis = analysis();

    let mut changed = episode();
    changed.steps[4]
        .coverage
        .as_mut()
        .unwrap()
        .analysis_revision =
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            .parse()
            .unwrap();
    changed.validate_against(&scenario, &analysis).unwrap_err();

    let mut changed = episode();
    changed.steps[4].mapping.as_mut().unwrap().binary_id =
        "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
            .parse()
            .unwrap();
    changed.validate_against(&scenario, &analysis).unwrap_err();

    let mut changed = episode();
    changed.state_nodes[0].scenario_id = changed.scenario_id.clone();
    changed.scenario_id = "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        .parse()
        .unwrap();
    changed.validate_against(&scenario, &analysis).unwrap_err();
}

#[test]
fn source_ids_and_context_patches_are_bounded() {
    let scenario = scenario();
    let analysis = analysis();
    let attempt = attempt();

    let mut changed = attempt.clone();
    changed.sources[0].action_index = 3;
    changed.validate_against(&scenario, &analysis).unwrap_err();

    let mut changed = attempt.clone();
    changed.context_patch[0].source_id.offset = 1;
    changed.validate_against(&scenario, &analysis).unwrap_err();

    let mut changed = attempt;
    changed.sources.clear();
    changed.validate_against(&scenario, &analysis).unwrap_err();

    let mut operation = vulnFuzz::model::PatchOperation {
        source_id: vulnFuzz::model::SourceId {
            action_index: 4,
            field: "stdin".to_owned(),
            offset: 0,
            length: 2,
        },
        value_hex: "5a".parse().unwrap(),
    };
    scenario
        .apply_context_patch(&[operation.clone()])
        .unwrap_err();
    operation.source_id.offset = u64::MAX;
    scenario.apply_context_patch(&[operation]).unwrap_err();
}

#[test]
fn invalid_coverage_and_solver_sat_are_not_concrete_success() {
    let mut invalid: Value = serde_json::from_str(example("coverage-invalid")).unwrap();
    invalid["covered_blocks"] = json!([{
        "binary_id": "sha256:3333333333333333333333333333333333333333333333333333333333333333",
        "start_elf_va": "0x0000000000001000"
    }]);
    CoverageSnapshot::from_json(&invalid.to_string()).unwrap_err();

    let invalid = CoverageSnapshot::from_json(example("coverage-invalid")).unwrap();
    assert_eq!(invalid.quality, Quality::Invalid);
    assert!(invalid.novelty_blocks().is_none());
    assert!(!invalid.reached(&analysis().blocks[0].id));

    let mut changed = attempt();
    changed.validation_episode_id = None;
    changed.validate().unwrap_err();
    changed.validation_episode_id = Some("episode-0000000000000002".parse().unwrap());
    changed.solver.result = SolverResult::Unknown;
    changed.solver.model.clear();
    changed.validate().unwrap_err();
}

#[test]
fn finding_levels_cannot_skip_required_evidence() {
    let mut finding = Finding::from_json(example("finding")).unwrap();
    finding.level = FindingLevel::ControlledTrigger;
    finding.minimal_pair = None;
    finding.validate().unwrap_err();

    let mut finding = Finding::from_json(example("finding")).unwrap();
    finding.dse_attempt_id = None;
    finding.validate().unwrap_err();

    let mut finding = Finding::from_json(example("finding")).unwrap();
    finding
        .minimal_pair
        .as_mut()
        .unwrap()
        .baseline_episodes
        .pop();
    finding
        .minimal_pair
        .as_mut()
        .unwrap()
        .baseline_episodes
        .pop();
    finding.validate().unwrap_err();

    let finding = Finding::from_json(example("finding")).unwrap();
    let mut attempt = attempt();
    attempt.reached = false;
    finding.validate_against_dse(&attempt).unwrap_err();
}

#[test]
fn backend_and_outcome_constraints_are_explicit() {
    let scenario = scenario();
    Backend::QemuSystem.validate_scenario(&scenario).unwrap();
    Backend::QemuUser.validate_scenario(&scenario).unwrap_err();

    let mut user_scenario = scenario;
    user_scenario.actions.retain(|action| {
        !matches!(
            action,
            vulnFuzz::model::Action::AdvanceClock { .. }
                | vulnFuzz::model::Action::Checkpoint { .. }
        )
    });
    user_scenario.refresh_scenario_id().unwrap();
    Backend::QemuUser.validate_scenario(&user_scenario).unwrap();

    assert!(StepOutcome::Exited(139).is_target_behavior());
    assert!(StepOutcome::Signaled(11).is_target_behavior());
    for outcome in [
        StepOutcome::NotStarted,
        StepOutcome::SpawnError,
        StepOutcome::AgentError,
        StepOutcome::BackendError,
    ] {
        assert!(!outcome.is_target_behavior());
    }
}
