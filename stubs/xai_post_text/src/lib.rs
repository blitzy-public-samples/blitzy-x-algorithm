// =============================================================================
// xai_post_text — Stub for tweet text tokenization and muted keyword matching.
// =============================================================================

/// A sequence of tokens from tokenized text.
#[derive(Debug, Clone, Default)]
pub struct TokenSequence {
    pub tokens: Vec<String>,
}

/// Tokenizer for tweet text.
pub struct TweetTokenizer;

impl TweetTokenizer {
    pub fn new() -> Self {
        Self
    }

    pub fn tokenize(&self, text: &str) -> TokenSequence {
        TokenSequence {
            tokens: text
                .split_whitespace()
                .map(|s| s.to_lowercase())
                .collect(),
        }
    }
}

/// Represents the set of user muted keyword sequences.
pub struct UserMutes {
    sequences: Vec<TokenSequence>,
}

impl UserMutes {
    pub fn new(sequences: Vec<TokenSequence>) -> Self {
        Self { sequences }
    }
}

/// Matcher that checks if tweet text contains muted keywords.
pub struct MatchTweetGroup {
    user_mutes: UserMutes,
}

impl MatchTweetGroup {
    pub fn new(user_mutes: UserMutes) -> Self {
        Self { user_mutes }
    }

    pub fn matches(&self, tweet_tokens: &TokenSequence) -> bool {
        for muted_seq in &self.user_mutes.sequences {
            if muted_seq.tokens.iter().all(|t| tweet_tokens.tokens.contains(t)) {
                return true;
            }
        }
        false
    }
}
