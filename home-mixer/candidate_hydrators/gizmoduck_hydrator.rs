use crate::candidate_pipeline::candidate::PostCandidate;
use crate::candidate_pipeline::query::ScoredPostsQuery;
use crate::clients::gizmoduck_client::GizmoduckClient;
use log::warn;
use std::sync::Arc;
use tonic::async_trait;
use xai_candidate_pipeline::hydrator::Hydrator;

pub struct GizmoduckCandidateHydrator {
    pub gizmoduck_client: Arc<dyn GizmoduckClient + Send + Sync>,
}

impl GizmoduckCandidateHydrator {
    pub async fn new(gizmoduck_client: Arc<dyn GizmoduckClient + Send + Sync>) -> Self {
        Self { gizmoduck_client }
    }
}

#[async_trait]
impl Hydrator<ScoredPostsQuery, PostCandidate> for GizmoduckCandidateHydrator {
    #[xai_stats_macro::receive_stats]
    async fn hydrate(
        &self,
        _query: &ScoredPostsQuery,
        candidates: &[PostCandidate],
    ) -> Result<Vec<PostCandidate>, String> {
        let client = &self.gizmoduck_client;

        // [M-2] Security Fix (CWE-681 / OWASP A10:2025): Use checked conversion
        // via i64::try_from() instead of unchecked `as i64` casts. Unsigned-to-signed
        // casts can silently overflow, producing incorrect user ID lookups.
        let author_ids: Vec<i64> = candidates
            .iter()
            .filter_map(|c| {
                i64::try_from(c.author_id).ok().or_else(|| {
                    warn!("Author ID {} overflows i64, skipping lookup", c.author_id);
                    None
                })
            })
            .collect();
        let retweet_user_ids: Vec<i64> = candidates
            .iter()
            .filter_map(|c| c.retweeted_user_id)
            .filter_map(|id| {
                i64::try_from(id).ok().or_else(|| {
                    warn!("Retweet user ID {} overflows i64, skipping lookup", id);
                    None
                })
            })
            .collect();

        let mut user_ids_to_fetch = Vec::with_capacity(author_ids.len() + retweet_user_ids.len());
        user_ids_to_fetch.extend(author_ids);
        user_ids_to_fetch.extend(retweet_user_ids);
        // [L-3] Security Fix (CWE-405 / OWASP A10:2025): Sort before dedup to
        // properly deduplicate ALL entries. Vec::dedup() only removes consecutive
        // duplicates, so non-adjacent duplicates cause redundant external API calls.
        user_ids_to_fetch.sort();
        user_ids_to_fetch.dedup();

        let users = client.get_users(user_ids_to_fetch).await;
        let users = users.map_err(|e| e.to_string())?;

        let mut hydrated_candidates = Vec::with_capacity(candidates.len());

        for candidate in candidates {
            // [M-2] Security Fix (CWE-681): Use checked i64::try_from() for user
            // ID lookups. If conversion fails (overflow), treat as user-not-found.
            let user = i64::try_from(candidate.author_id)
                .ok()
                .and_then(|id| users.get(&id))
                .and_then(|user| user.as_ref());
            let user_counts = user.and_then(|user| user.user.as_ref().map(|u| &u.counts));
            let user_profile = user.and_then(|user| user.user.as_ref().map(|u| &u.profile));

            // [M-2] Security Fix (CWE-681): Use checked i32::try_from() for
            // followers_count. Large follower counts could silently wrap on cast.
            let author_followers_count: Option<i32> = user_counts
                .map(|x| x.followers_count)
                .and_then(|x| i32::try_from(x).ok());
            let author_screen_name: Option<String> = user_profile.map(|x| x.screen_name.clone());

            // [M-2] Security Fix (CWE-681): Use checked i64::try_from() for
            // retweet user ID lookup.
            let retweet_user = candidate
                .retweeted_user_id
                .and_then(|retweeted_user_id| {
                    i64::try_from(retweeted_user_id)
                        .ok()
                        .and_then(|id| users.get(&id))
                })
                .and_then(|user| user.as_ref());
            let retweet_profile =
                retweet_user.and_then(|user| user.user.as_ref().map(|u| &u.profile));
            let retweeted_screen_name: Option<String> =
                retweet_profile.map(|x| x.screen_name.clone());

            let hydrated = PostCandidate {
                author_followers_count,
                author_screen_name,
                retweeted_screen_name,
                ..Default::default()
            };
            hydrated_candidates.push(hydrated);
        }

        Ok(hydrated_candidates)
    }

    fn update(&self, candidate: &mut PostCandidate, hydrated: PostCandidate) {
        candidate.author_followers_count = hydrated.author_followers_count;
        candidate.author_screen_name = hydrated.author_screen_name;
        candidate.retweeted_screen_name = hydrated.retweeted_screen_name;
    }
}
