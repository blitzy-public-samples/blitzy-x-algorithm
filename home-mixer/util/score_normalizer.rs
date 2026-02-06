/// Score normalization utilities — excluded from open source release for security reasons.
use crate::candidate_pipeline::candidate::PostCandidate;
use crate::params as p;

/// Normalizes a weighted score for a candidate, applying out-of-network
/// weight adjustments and author diversity decay.
///
/// In-network candidates (those from Thunder source) receive full score weight.
/// Out-of-network candidates (those from Phoenix retrieval) receive a reduced
/// weight defined by `OON_WEIGHT_FACTOR`.
pub fn normalize_score(candidate: &PostCandidate, weighted_score: f64) -> f64 {
    let network_factor = if candidate.in_network.unwrap_or(false) {
        1.0
    } else {
        p::OON_WEIGHT_FACTOR
    };

    weighted_score * network_factor
}
