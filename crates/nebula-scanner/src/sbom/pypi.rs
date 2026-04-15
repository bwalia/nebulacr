//! pypi parser — stub (task #6).

use super::Package;

#[allow(unused_variables)]
pub fn parse(layer_digest: &str, path: &str, contents: &[u8], out: &mut Vec<Package>) {
    // TODO(task 6): real parser with fixture-based tests.
    let _ = (layer_digest, contents, out);
}
