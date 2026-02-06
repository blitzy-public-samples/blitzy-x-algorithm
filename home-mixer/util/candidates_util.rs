/// Candidate utility functions for extracting related post IDs.
use crate::candidate_pipeline::candidate::PostCandidate;

/// Returns all post IDs related to a candidate, including the primary tweet ID,
/// any retweeted tweet ID, and any replied-to tweet ID. These are used for
/// deduplication filters to check if a candidate (or its related tweets) has
/// already been seen or served.
pub fn get_related_post_ids(candidate: &PostCandidate) -> Vec<u64> {
    let mut ids = vec![candidate.tweet_id as u64];
    if let Some(retweeted_id) = candidate.retweeted_tweet_id {
        ids.push(retweeted_id);
    }
    if let Some(reply_id) = candidate.in_reply_to_tweet_id {
        ids.push(reply_id);
    }
    ids
}
