//! Conservative, side-effect-free rules for class member candidates.
//!
//! This module intentionally consumes already-lowered facts. It does not inspect ASTs,
//! invoke TypeScript, or decide reachability. The optional deep worker may only fill
//! receiver and override gaps represented by [`DeepResolution`]; it never makes an
//! unused judgment.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AnalysisMode {
    Fast,
    Balanced,
    Deep,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemberLanguage {
    JavaScript,
    TypeScript,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemberVisibility {
    JavaScriptPrivate,
    TypeScriptPrivate,
    Protected,
    Public,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemberScope {
    Instance,
    Static,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum MemberKind {
    Method,
    Field,
    Getter,
    Setter,
    Accessor,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct MemberId {
    pub declaring_class: String,
    pub name: String,
    pub scope: MemberScope,
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "these independent flags record distinct runtime member hazards"
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MemberHazards {
    pub decorated: bool,
    pub emitted_decorator_metadata: bool,
    pub unknown_bracket_access: bool,
    pub reflected_or_enumerated: bool,
    pub serialized: bool,
    pub object_spread: bool,
    pub proxied: bool,
    pub passed_to_unknown_code: bool,
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "these independent flags preserve the completeness of inheritance facts"
)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct InheritanceFacts {
    pub participates_in_inheritance: bool,
    pub relationships_complete: bool,
    pub overrides_live_base_member: bool,
    pub has_live_override: bool,
    pub implements_external_contract: bool,
}

/// Facts returned by the optional TypeScript worker.
///
/// `Resolved` is consulted only when the corresponding core fact is incomplete. This
/// preserves the invariant that deep mode can add findings, but cannot invalidate a
/// finding already made by a faster mode from complete facts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum DeepResolution {
    #[default]
    NotRequested,
    Unavailable {
        capability_note: String,
    },
    Resolved {
        receiver_may_reference_member: bool,
        live_override_contract: bool,
    },
}

#[allow(
    clippy::struct_excessive_bools,
    reason = "the candidate aggregates independent facts supplied by earlier analysis stages"
)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberCandidate {
    pub id: MemberId,
    pub language: MemberLanguage,
    pub visibility: MemberVisibility,
    pub kind: MemberKind,
    pub directly_referenced: bool,
    pub framework_root: bool,
    pub class_exported: bool,
    pub class_escaped: bool,
    pub open_world: bool,
    pub receiver_targets_complete: bool,
    pub hazards: MemberHazards,
    pub inheritance: InheritanceFacts,
    pub deep_resolution: DeepResolution,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemberConfidence {
    High,
    Medium,
    Low,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingEvidence {
    NoSemanticReference,
    JavaScriptPrivateIsLexicallyScoped,
    TypeScriptPrivateSurfaceDoesNotEscape,
    ClosedWorldClass,
    ClassDoesNotEscape,
    StaticReceiverIsExplicit,
    ReceiverTargetsComplete,
    OverrideRelationshipsComplete,
    DeepReceiverExcludesMember,
    DeepOverrideRelationshipsComplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RetentionReason {
    DirectReference,
    FrameworkContract,
    OpenWorldPublicSurface,
    EscapedPublicSurface,
    EscapedTypeScriptPrivateSurface,
    DecoratorContract,
    EmittedDecoratorMetadata,
    UnknownBracketAccess,
    ReflectionOrEnumeration,
    Serialization,
    ObjectSpread,
    Proxy,
    UnknownExternalCall,
    ExternalInterfaceContract,
    LiveBaseContract,
    LiveOverride,
    DeepReceiverReference,
    DeepLiveOverrideContract,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeferralReason {
    ModeDoesNotAnalyzeVisibility,
    ReceiverTargetsAmbiguous,
    OverrideRelationshipsIncomplete,
    DeepEvidenceMissing,
    DeepWorkerUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberFinding {
    pub id: MemberId,
    pub kind: MemberKind,
    pub visibility: MemberVisibility,
    pub confidence: MemberConfidence,
    pub evidence: Vec<FindingEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberRetention {
    pub id: MemberId,
    pub reason: RetentionReason,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemberDeferral {
    pub id: MemberId,
    pub reason: DeferralReason,
    pub confidence: MemberConfidence,
    pub capability_note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MemberDecision {
    Finding(MemberFinding),
    Retained(MemberRetention),
    Deferred(MemberDeferral),
}

impl MemberDecision {
    #[must_use]
    pub fn id(&self) -> &MemberId {
        match self {
            Self::Finding(finding) => &finding.id,
            Self::Retained(retention) => &retention.id,
            Self::Deferred(deferral) => &deferral.id,
        }
    }

    #[must_use]
    pub const fn finding_confidence(&self) -> Option<MemberConfidence> {
        match self {
            Self::Finding(finding) => Some(finding.confidence),
            Self::Retained(_) | Self::Deferred(_) => None,
        }
    }

    #[must_use]
    pub const fn confidence(&self) -> Option<MemberConfidence> {
        match self {
            Self::Finding(finding) => Some(finding.confidence),
            Self::Deferred(deferral) => Some(deferral.confidence),
            Self::Retained(_) => None,
        }
    }
}

#[must_use]
pub fn analyze_member(mode: AnalysisMode, candidate: &MemberCandidate) -> MemberDecision {
    if candidate.directly_referenced {
        return retained(candidate, RetentionReason::DirectReference);
    }
    if candidate.framework_root {
        return retained(candidate, RetentionReason::FrameworkContract);
    }
    if candidate.inheritance.implements_external_contract {
        return retained(candidate, RetentionReason::ExternalInterfaceContract);
    }
    if candidate.inheritance.overrides_live_base_member {
        return retained(candidate, RetentionReason::LiveBaseContract);
    }
    if candidate.inheritance.has_live_override {
        return retained(candidate, RetentionReason::LiveOverride);
    }
    if candidate.hazards.decorated {
        return retained(candidate, RetentionReason::DecoratorContract);
    }
    if candidate.hazards.emitted_decorator_metadata {
        return retained(candidate, RetentionReason::EmittedDecoratorMetadata);
    }

    match candidate.visibility {
        MemberVisibility::JavaScriptPrivate => javascript_private_finding(candidate),
        MemberVisibility::TypeScriptPrivate => analyze_typescript_private(mode, candidate),
        MemberVisibility::Protected | MemberVisibility::Public => {
            analyze_visible_member(mode, candidate)
        }
    }
}

#[must_use]
pub fn analyze_members(
    mode: AnalysisMode,
    candidates: impl IntoIterator<Item = MemberCandidate>,
) -> Vec<MemberDecision> {
    let mut decisions = candidates
        .into_iter()
        .map(|candidate| analyze_member(mode, &candidate))
        .collect::<Vec<_>>();
    decisions.sort_by(|left, right| left.id().cmp(right.id()));
    decisions
}

fn analyze_typescript_private(mode: AnalysisMode, candidate: &MemberCandidate) -> MemberDecision {
    if mode == AnalysisMode::Fast {
        return deferred(
            candidate,
            DeferralReason::ModeDoesNotAnalyzeVisibility,
            None,
        );
    }

    if candidate.class_escaped || (candidate.open_world && candidate.class_exported) {
        return retained(candidate, RetentionReason::EscapedTypeScriptPrivateSurface);
    }
    if let Some(reason) = runtime_hazard(candidate.hazards) {
        return retained(candidate, reason);
    }

    finding(
        candidate,
        vec![
            FindingEvidence::NoSemanticReference,
            FindingEvidence::TypeScriptPrivateSurfaceDoesNotEscape,
            FindingEvidence::ClassDoesNotEscape,
        ],
    )
}

fn analyze_visible_member(mode: AnalysisMode, candidate: &MemberCandidate) -> MemberDecision {
    if mode == AnalysisMode::Fast {
        return deferred(
            candidate,
            DeferralReason::ModeDoesNotAnalyzeVisibility,
            None,
        );
    }

    if candidate.open_world && candidate.class_exported {
        return retained(candidate, RetentionReason::OpenWorldPublicSurface);
    }
    if candidate.class_escaped {
        return retained(candidate, RetentionReason::EscapedPublicSurface);
    }
    if let Some(reason) = runtime_hazard(candidate.hazards) {
        return retained(candidate, reason);
    }

    let receiver_incomplete =
        candidate.id.scope == MemberScope::Instance && !candidate.receiver_targets_complete;
    let override_incomplete = candidate.inheritance.participates_in_inheritance
        && !candidate.inheritance.relationships_complete;
    let mut evidence = vec![
        FindingEvidence::NoSemanticReference,
        FindingEvidence::ClosedWorldClass,
        FindingEvidence::ClassDoesNotEscape,
    ];

    if !receiver_incomplete {
        evidence.push(if candidate.id.scope == MemberScope::Static {
            FindingEvidence::StaticReceiverIsExplicit
        } else {
            FindingEvidence::ReceiverTargetsComplete
        });
    }
    if candidate.inheritance.participates_in_inheritance && !override_incomplete {
        evidence.push(FindingEvidence::OverrideRelationshipsComplete);
    }

    if receiver_incomplete || override_incomplete {
        if mode != AnalysisMode::Deep {
            let reason = if receiver_incomplete {
                DeferralReason::ReceiverTargetsAmbiguous
            } else {
                DeferralReason::OverrideRelationshipsIncomplete
            };
            return deferred(candidate, reason, None);
        }

        match &candidate.deep_resolution {
            DeepResolution::NotRequested => {
                return deferred(candidate, DeferralReason::DeepEvidenceMissing, None);
            }
            DeepResolution::Unavailable { capability_note } => {
                return deferred(
                    candidate,
                    DeferralReason::DeepWorkerUnavailable,
                    Some(capability_note.clone()),
                );
            }
            DeepResolution::Resolved {
                receiver_may_reference_member,
                live_override_contract,
            } => {
                if receiver_incomplete && *receiver_may_reference_member {
                    return retained(candidate, RetentionReason::DeepReceiverReference);
                }
                if override_incomplete && *live_override_contract {
                    return retained(candidate, RetentionReason::DeepLiveOverrideContract);
                }
                if receiver_incomplete {
                    evidence.push(FindingEvidence::DeepReceiverExcludesMember);
                }
                if override_incomplete {
                    evidence.push(FindingEvidence::DeepOverrideRelationshipsComplete);
                }
            }
        }
    }

    finding(candidate, evidence)
}

fn javascript_private_finding(candidate: &MemberCandidate) -> MemberDecision {
    finding(
        candidate,
        vec![
            FindingEvidence::NoSemanticReference,
            FindingEvidence::JavaScriptPrivateIsLexicallyScoped,
        ],
    )
}

fn runtime_hazard(hazards: MemberHazards) -> Option<RetentionReason> {
    if hazards.unknown_bracket_access {
        Some(RetentionReason::UnknownBracketAccess)
    } else if hazards.reflected_or_enumerated {
        Some(RetentionReason::ReflectionOrEnumeration)
    } else if hazards.serialized {
        Some(RetentionReason::Serialization)
    } else if hazards.object_spread {
        Some(RetentionReason::ObjectSpread)
    } else if hazards.proxied {
        Some(RetentionReason::Proxy)
    } else if hazards.passed_to_unknown_code {
        Some(RetentionReason::UnknownExternalCall)
    } else {
        None
    }
}

fn finding(candidate: &MemberCandidate, evidence: Vec<FindingEvidence>) -> MemberDecision {
    MemberDecision::Finding(MemberFinding {
        id: candidate.id.clone(),
        kind: candidate.kind,
        visibility: candidate.visibility,
        confidence: MemberConfidence::High,
        evidence,
    })
}

fn retained(candidate: &MemberCandidate, reason: RetentionReason) -> MemberDecision {
    MemberDecision::Retained(MemberRetention {
        id: candidate.id.clone(),
        reason,
    })
}

fn deferred(
    candidate: &MemberCandidate,
    reason: DeferralReason,
    capability_note: Option<String>,
) -> MemberDecision {
    MemberDecision::Deferred(MemberDeferral {
        id: candidate.id.clone(),
        reason,
        confidence: MemberConfidence::Incomplete,
        capability_note,
    })
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::{
        AnalysisMode, DeepResolution, DeferralReason, FindingEvidence, InheritanceFacts,
        MemberCandidate, MemberConfidence, MemberDecision, MemberHazards, MemberId, MemberKind,
        MemberLanguage, MemberScope, MemberVisibility, RetentionReason, analyze_member,
        analyze_members,
    };

    #[test]
    fn javascript_private_members_remain_precise_when_the_class_escapes() {
        let candidate = MemberCandidate {
            class_exported: true,
            class_escaped: true,
            open_world: true,
            hazards: MemberHazards {
                unknown_bracket_access: true,
                reflected_or_enumerated: true,
                serialized: true,
                proxied: true,
                ..MemberHazards::default()
            },
            ..candidate("Widget", "#secret", MemberVisibility::JavaScriptPrivate)
        };

        let decision = analyze_member(AnalysisMode::Fast, &candidate);

        let MemberDecision::Finding(finding) = decision else {
            panic!("JavaScript private member should be a finding");
        };
        assert!(
            finding
                .evidence
                .contains(&FindingEvidence::JavaScriptPrivateIsLexicallyScoped)
        );
        assert_eq!(
            MemberDecision::Finding(finding).confidence(),
            Some(MemberConfidence::High)
        );
    }

    #[test]
    fn decorators_retain_even_javascript_private_members() {
        let candidate = MemberCandidate {
            hazards: MemberHazards {
                decorated: true,
                ..MemberHazards::default()
            },
            ..candidate("Widget", "#hook", MemberVisibility::JavaScriptPrivate)
        };

        assert_retained(
            analyze_member(AnalysisMode::Deep, &candidate),
            RetentionReason::DecoratorContract,
        );
    }

    #[test]
    fn typescript_private_members_require_escape_analysis() {
        let candidate = MemberCandidate {
            class_escaped: true,
            ..candidate("Widget", "secret", MemberVisibility::TypeScriptPrivate)
        };

        assert_deferred(
            analyze_member(AnalysisMode::Fast, &candidate),
            DeferralReason::ModeDoesNotAnalyzeVisibility,
        );
        assert_retained(
            analyze_member(AnalysisMode::Balanced, &candidate),
            RetentionReason::EscapedTypeScriptPrivateSurface,
        );
    }

    #[test]
    fn bracket_reflection_serialization_and_proxy_hazards_retain_members() {
        let hazards = [
            (
                MemberHazards {
                    unknown_bracket_access: true,
                    ..MemberHazards::default()
                },
                RetentionReason::UnknownBracketAccess,
            ),
            (
                MemberHazards {
                    reflected_or_enumerated: true,
                    ..MemberHazards::default()
                },
                RetentionReason::ReflectionOrEnumeration,
            ),
            (
                MemberHazards {
                    serialized: true,
                    ..MemberHazards::default()
                },
                RetentionReason::Serialization,
            ),
            (
                MemberHazards {
                    proxied: true,
                    ..MemberHazards::default()
                },
                RetentionReason::Proxy,
            ),
        ];

        for (hazard, expected) in hazards {
            let candidate = MemberCandidate {
                hazards: hazard,
                ..candidate("Widget", "render", MemberVisibility::Public)
            };
            assert_retained(analyze_member(AnalysisMode::Balanced, &candidate), expected);
        }
    }

    #[test]
    fn exported_public_and_protected_surfaces_are_live_in_open_world() {
        for visibility in [MemberVisibility::Public, MemberVisibility::Protected] {
            let candidate = MemberCandidate {
                class_exported: true,
                open_world: true,
                ..candidate("Widget", "render", visibility)
            };
            assert_retained(
                analyze_member(AnalysisMode::Balanced, &candidate),
                RetentionReason::OpenWorldPublicSurface,
            );
        }
    }

    #[test]
    fn static_members_do_not_need_instance_receiver_resolution() {
        let candidate = MemberCandidate {
            id: MemberId {
                scope: MemberScope::Static,
                ..id("Widget", "create")
            },
            receiver_targets_complete: false,
            ..candidate("Widget", "create", MemberVisibility::Public)
        };

        let MemberDecision::Finding(finding) = analyze_member(AnalysisMode::Balanced, &candidate)
        else {
            panic!("closed-world static member should be a finding");
        };
        assert!(
            finding
                .evidence
                .contains(&FindingEvidence::StaticReceiverIsExplicit)
        );
    }

    #[test]
    fn protected_members_wait_for_complete_override_relationships() {
        let candidate = MemberCandidate {
            inheritance: InheritanceFacts {
                participates_in_inheritance: true,
                relationships_complete: false,
                ..InheritanceFacts::default()
            },
            ..candidate("Widget", "render", MemberVisibility::Protected)
        };

        assert_deferred(
            analyze_member(AnalysisMode::Balanced, &candidate),
            DeferralReason::OverrideRelationshipsIncomplete,
        );
    }

    #[test]
    fn live_base_and_derived_contracts_retain_overrides() {
        let base_contract = MemberCandidate {
            inheritance: InheritanceFacts {
                overrides_live_base_member: true,
                ..InheritanceFacts::default()
            },
            ..candidate("Widget", "render", MemberVisibility::Protected)
        };
        let live_override = MemberCandidate {
            inheritance: InheritanceFacts {
                has_live_override: true,
                ..InheritanceFacts::default()
            },
            ..candidate("Widget", "render", MemberVisibility::Protected)
        };

        assert_retained(
            analyze_member(AnalysisMode::Balanced, &base_contract),
            RetentionReason::LiveBaseContract,
        );
        assert_retained(
            analyze_member(AnalysisMode::Balanced, &live_override),
            RetentionReason::LiveOverride,
        );
    }

    #[test]
    fn deep_facts_can_resolve_ambiguity_without_making_policy() {
        let unused = MemberCandidate {
            receiver_targets_complete: false,
            deep_resolution: DeepResolution::Resolved {
                receiver_may_reference_member: false,
                live_override_contract: false,
            },
            ..candidate("Widget", "render", MemberVisibility::Public)
        };
        let used = MemberCandidate {
            deep_resolution: DeepResolution::Resolved {
                receiver_may_reference_member: true,
                live_override_contract: false,
            },
            ..unused.clone()
        };

        assert!(matches!(
            analyze_member(AnalysisMode::Deep, &unused),
            MemberDecision::Finding(_)
        ));
        assert_retained(
            analyze_member(AnalysisMode::Deep, &used),
            RetentionReason::DeepReceiverReference,
        );
    }

    #[test]
    fn worker_unavailability_is_an_explicit_capability_deferral() {
        let candidate = MemberCandidate {
            receiver_targets_complete: false,
            deep_resolution: DeepResolution::Unavailable {
                capability_note: "workspace TypeScript was not available".to_owned(),
            },
            ..candidate("Widget", "render", MemberVisibility::Public)
        };

        let MemberDecision::Deferred(deferral) = analyze_member(AnalysisMode::Deep, &candidate)
        else {
            panic!("unavailable deep worker should defer");
        };
        assert_eq!(deferral.reason, DeferralReason::DeepWorkerUnavailable);
        assert_eq!(deferral.confidence, MemberConfidence::Incomplete);
        assert_eq!(
            deferral.capability_note.as_deref(),
            Some("workspace TypeScript was not available")
        );
    }

    #[test]
    fn faster_modes_only_return_subsets_of_deep_findings() {
        let candidates = vec![
            candidate("Widget", "#secret", MemberVisibility::JavaScriptPrivate),
            candidate("Widget", "internal", MemberVisibility::TypeScriptPrivate),
            candidate("Widget", "render", MemberVisibility::Public),
            MemberCandidate {
                receiver_targets_complete: false,
                deep_resolution: DeepResolution::Resolved {
                    receiver_may_reference_member: false,
                    live_override_contract: false,
                },
                ..candidate("Widget", "ambiguous", MemberVisibility::Public)
            },
        ];

        let fast = finding_ids(analyze_members(AnalysisMode::Fast, candidates.clone()));
        let balanced = finding_ids(analyze_members(AnalysisMode::Balanced, candidates.clone()));
        let deep = finding_ids(analyze_members(AnalysisMode::Deep, candidates));

        assert!(fast.is_subset(&balanced));
        assert!(balanced.is_subset(&deep));
    }

    #[test]
    fn batch_results_are_sorted_by_stable_member_identity() {
        let decisions = analyze_members(
            AnalysisMode::Balanced,
            [
                candidate("Zed", "b", MemberVisibility::TypeScriptPrivate),
                candidate("Alpha", "z", MemberVisibility::TypeScriptPrivate),
                candidate("Alpha", "a", MemberVisibility::TypeScriptPrivate),
            ],
        );
        let ids = decisions
            .iter()
            .map(|decision| {
                (
                    decision.id().declaring_class.as_str(),
                    decision.id().name.as_str(),
                )
            })
            .collect::<Vec<_>>();

        assert_eq!(ids, vec![("Alpha", "a"), ("Alpha", "z"), ("Zed", "b")]);
    }

    fn candidate(class: &str, name: &str, visibility: MemberVisibility) -> MemberCandidate {
        MemberCandidate {
            id: id(class, name),
            language: if visibility == MemberVisibility::JavaScriptPrivate {
                MemberLanguage::JavaScript
            } else {
                MemberLanguage::TypeScript
            },
            visibility,
            kind: MemberKind::Method,
            directly_referenced: false,
            framework_root: false,
            class_exported: false,
            class_escaped: false,
            open_world: false,
            receiver_targets_complete: true,
            hazards: MemberHazards::default(),
            inheritance: InheritanceFacts::default(),
            deep_resolution: DeepResolution::NotRequested,
        }
    }

    fn id(class: &str, name: &str) -> MemberId {
        MemberId {
            declaring_class: class.to_owned(),
            name: name.to_owned(),
            scope: MemberScope::Instance,
        }
    }

    fn assert_retained(decision: MemberDecision, expected: RetentionReason) {
        let MemberDecision::Retained(retention) = decision else {
            panic!("expected retained decision");
        };
        assert_eq!(retention.reason, expected);
    }

    fn assert_deferred(decision: MemberDecision, expected: DeferralReason) {
        let MemberDecision::Deferred(deferral) = decision else {
            panic!("expected deferred decision");
        };
        assert_eq!(deferral.reason, expected);
    }

    fn finding_ids(decisions: Vec<MemberDecision>) -> BTreeSet<MemberId> {
        decisions
            .into_iter()
            .filter_map(|decision| match decision {
                MemberDecision::Finding(finding) => Some(finding.id),
                MemberDecision::Retained(_) | MemberDecision::Deferred(_) => None,
            })
            .collect()
    }
}
