/// Bloom filter implementation for impression deduplication.
use xai_home_mixer_proto::ImpressionBloomFilterEntry;

/// A simple Bloom filter reconstructed from serialized impression entries.
pub struct BloomFilter {
    bits: Vec<u8>,
    num_hashes: u32,
}

impl BloomFilter {
    /// Constructs a BloomFilter from a serialized ImpressionBloomFilterEntry.
    pub fn from_entry(entry: &ImpressionBloomFilterEntry) -> Self {
        Self {
            bits: entry.filter_data.clone(),
            num_hashes: entry.num_hashes,
        }
    }

    /// Tests whether the filter may contain the given post ID.
    /// False positives are possible; false negatives are not.
    pub fn may_contain(&self, post_id: u64) -> bool {
        if self.bits.is_empty() {
            return false;
        }
        let num_bits = self.bits.len() * 8;
        for i in 0..self.num_hashes {
            let hash = self.hash(post_id, i);
            let bit_index = (hash as usize) % num_bits;
            let byte_index = bit_index / 8;
            let bit_offset = bit_index % 8;
            if self.bits.get(byte_index).map_or(true, |b| b & (1 << bit_offset) == 0) {
                return false;
            }
        }
        true
    }

    /// Simple hash function combining post_id with seed index.
    fn hash(&self, post_id: u64, seed: u32) -> u64 {
        let mut h = post_id;
        h = h.wrapping_mul(0x9E3779B97F4A7C15);
        h = h.wrapping_add(seed as u64);
        h ^= h >> 33;
        h = h.wrapping_mul(0xFF51AFD7ED558CCD);
        h ^= h >> 33;
        h
    }
}
