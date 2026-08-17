use serde::Serialize;

use crate::cache::ContentDigest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AnalysisConfidence {
    High,
    Medium,
    Low,
    Incomplete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WorldAssumption {
    Closed,
    Open,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicApiExposure {
    OutsidePublicApi,
    PublicApi,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CoverageBlocker {
    Parse,
    Resolution,
    Plugin,
    DynamicBehavior,
    Configuration,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixCandidate {
    pub confidence: AnalysisConfidence,
    pub world: WorldAssumption,
    pub public_api: PublicApiExposure,
    pub blockers: Vec<CoverageBlocker>,
    pub expected_content: Option<ContentDigest>,
    pub preserves_trivia_and_semantics: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EligibleFix {
    expected_content: ContentDigest,
}

impl EligibleFix {
    #[must_use]
    pub fn expected_content(&self) -> ContentDigest {
        self.expected_content
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EligibilityDecision {
    Eligible(EligibleFix),
    Ineligible(Vec<EligibilityRejection>),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EligibilityRejection {
    ConfidenceIsNotHigh,
    AffectedByBlockers(Vec<CoverageBlocker>),
    PublicApiRequiresClosedWorld,
    MissingAnalyzedContentHash,
    TriviaOrSemanticPreservationUnproven,
}

impl FixCandidate {
    #[must_use]
    pub fn evaluate(mut self) -> EligibilityDecision {
        let mut rejections = Vec::new();
        if self.confidence != AnalysisConfidence::High {
            rejections.push(EligibilityRejection::ConfidenceIsNotHigh);
        }
        if !self.blockers.is_empty() {
            self.blockers.sort();
            self.blockers.dedup();
            rejections.push(EligibilityRejection::AffectedByBlockers(self.blockers));
        }
        if self.world == WorldAssumption::Open && self.public_api == PublicApiExposure::PublicApi {
            rejections.push(EligibilityRejection::PublicApiRequiresClosedWorld);
        }
        if self.expected_content.is_none() {
            rejections.push(EligibilityRejection::MissingAnalyzedContentHash);
        }
        if !self.preserves_trivia_and_semantics {
            rejections.push(EligibilityRejection::TriviaOrSemanticPreservationUnproven);
        }

        match (rejections.is_empty(), self.expected_content) {
            (true, Some(expected_content)) => {
                EligibilityDecision::Eligible(EligibleFix { expected_content })
            }
            _ => EligibilityDecision::Ineligible(rejections),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::cache::ContentDigest;

    use super::{
        AnalysisConfidence, CoverageBlocker, EligibilityDecision, EligibilityRejection,
        FixCandidate, PublicApiExposure, WorldAssumption,
    };

    #[test]
    fn requires_every_safety_condition() {
        let decision = FixCandidate {
            confidence: AnalysisConfidence::Medium,
            world: WorldAssumption::Open,
            public_api: PublicApiExposure::PublicApi,
            blockers: vec![CoverageBlocker::Parse],
            expected_content: None,
            preserves_trivia_and_semantics: false,
        }
        .evaluate();

        let EligibilityDecision::Ineligible(rejections) = decision else {
            panic!("unsafe candidate was considered eligible");
        };
        assert!(rejections.contains(&EligibilityRejection::ConfidenceIsNotHigh));
        assert!(rejections.contains(&EligibilityRejection::PublicApiRequiresClosedWorld));
        assert!(rejections.contains(&EligibilityRejection::MissingAnalyzedContentHash));
        assert!(rejections.contains(&EligibilityRejection::TriviaOrSemanticPreservationUnproven));
    }

    #[test]
    fn permits_a_hash_guarded_closed_world_fix() {
        let decision = FixCandidate {
            confidence: AnalysisConfidence::High,
            world: WorldAssumption::Closed,
            public_api: PublicApiExposure::PublicApi,
            blockers: Vec::new(),
            expected_content: Some(ContentDigest::of_bytes(b"source")),
            preserves_trivia_and_semantics: true,
        }
        .evaluate();

        assert!(matches!(decision, EligibilityDecision::Eligible(_)));
    }
}
