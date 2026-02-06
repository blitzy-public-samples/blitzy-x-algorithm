/// Extracts the short type name from a fully-qualified Rust type path.
///
/// Given a full type path like `"my_crate::module::submodule::MyType"`,
/// returns just `"MyType"`. This is used by all pipeline trait implementations
/// (`Filter`, `Source`, `Hydrator`, `Scorer`, `Selector`, `SideEffect`,
/// `QueryHydrator`) to produce concise, human-readable names for logging
/// and metrics output.
///
/// # Arguments
/// * `full` - A fully-qualified type name, typically obtained from
///   `std::any::type_name_of_val`. Must have `'static` lifetime since
///   `type_name_of_val` returns `&'static str` and the trait `name()`
///   methods return `&'static str`.
///
/// # Returns
/// The substring after the last `"::"` separator, or the original string
/// if no separator is found.
///
/// # Examples
/// ```
/// use xai_candidate_pipeline::util::short_type_name;
/// assert_eq!(short_type_name("my_crate::module::MyFilter"), "MyFilter");
/// assert_eq!(short_type_name("SimpleType"), "SimpleType");
/// assert_eq!(short_type_name("a::b::c::DeepType"), "DeepType");
/// ```
pub fn short_type_name(full: &'static str) -> &'static str {
    // rsplit("::") yields substrings in reverse order of "::" splits.
    // .next() gets the last segment (the short name).
    // Since `full` is &'static str, the returned slice is also &'static str.
    full.rsplit("::").next().unwrap_or(full)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_short_type_name_with_module_path() {
        let full: &'static str = "my_crate::module::MyType";
        assert_eq!(short_type_name(full), "MyType");
    }

    #[test]
    fn test_short_type_name_no_separators() {
        let full: &'static str = "SimpleType";
        assert_eq!(short_type_name(full), "SimpleType");
    }

    #[test]
    fn test_short_type_name_deep_nesting() {
        let full: &'static str = "a::b::c::d::DeepType";
        assert_eq!(short_type_name(full), "DeepType");
    }

    #[test]
    fn test_short_type_name_single_segment_with_colons() {
        let full: &'static str = "crate::TopLevel";
        assert_eq!(short_type_name(full), "TopLevel");
    }

    #[test]
    fn test_short_type_name_empty_string() {
        let full: &'static str = "";
        assert_eq!(short_type_name(full), "");
    }
}
