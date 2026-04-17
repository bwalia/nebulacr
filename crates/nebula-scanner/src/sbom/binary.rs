//! Go static-binary SBOM parser.
//!
//! Go 1.18+ embeds build-info metadata directly in the executable under a
//! section prefixed by `\xff Go buildinf:`. We locate the magic in the
//! binary, parse the inline varint-prefixed version + module-info strings,
//! and emit one `Package` per `path` / `dep` line. That covers the
//! overwhelming majority of vendored-Go binaries shipped in container
//! images where no `go.sum` is around.
//!
//! Non-Go binaries fall through as no-op. Future binary types (Rust musl,
//! Java fat JARs) can be added alongside without restructuring this module.

use super::Package;

const GO_BUILDINFO_MAGIC: &[u8] = b"\xff Go buildinf:";
const ELF_MAGIC: &[u8] = b"\x7fELF";

pub fn looks_like_binary(contents: &[u8]) -> bool {
    contents.len() >= 4 && &contents[..4] == ELF_MAGIC
}

pub fn parse(layer_digest: &str, contents: &[u8], out: &mut Vec<Package>) {
    if !looks_like_binary(contents) {
        return;
    }
    let Some(off) = find_subslice(contents, GO_BUILDINFO_MAGIC) else {
        return;
    };
    let after_magic = &contents[off + GO_BUILDINFO_MAGIC.len()..];
    if after_magic.len() < 2 {
        return;
    }
    // 1 byte ptrSize, 1 byte flags. Inline format has flags & 2 == 2.
    let flags = after_magic[1];
    if flags & 2 == 0 {
        // Pointer format (older Go); we don't decode it — ELF-section math
        // is involved and the inline format covers Go 1.18+ which is now
        // almost everything in the wild.
        return;
    }
    let body = &after_magic[2..];
    let Some((_version, rest)) = read_uvarint_string(body) else {
        return;
    };
    let Some((modinfo, _)) = read_uvarint_string(rest) else {
        return;
    };
    parse_modinfo(modinfo, layer_digest, out);
}

/// Parse the TSV-shaped modinfo blob that follows the Go build-info version.
/// Line prefixes we handle:
///   `path\t<module>` — the main module
///   `mod\t<name>\t<version>` — legacy main module line (rare)
///   `dep\t<name>\t<version>` — a transitive dependency
fn parse_modinfo(blob: &str, layer_digest: &str, out: &mut Vec<Package>) {
    // The blob is framed on many binaries by opaque marker bytes — we just
    // iterate UTF-8 lines and ignore lines we don't understand.
    let mut seen = std::collections::HashSet::new();
    for line in blob.split('\n') {
        let fields: Vec<&str> = line.split('\t').collect();
        if fields.len() < 2 {
            continue;
        }
        let (name, version) = match fields[0] {
            "path" if fields.len() >= 2 => (fields[1].trim(), "main"),
            "mod" if fields.len() >= 3 => (fields[1].trim(), fields[2].trim()),
            "dep" if fields.len() >= 3 => (fields[1].trim(), fields[2].trim()),
            _ => continue,
        };
        if name.is_empty() || name.contains(char::is_whitespace) {
            continue;
        }
        if !seen.insert((name.to_string(), version.to_string())) {
            continue;
        }
        out.push(Package {
            name: name.to_string(),
            version: version.to_string(),
            ecosystem: "go".into(),
            purl: format!("pkg:golang/{}@{}", name, version),
            layer_digest: Some(layer_digest.to_string()),
        });
    }
}

/// Decode a LEB128 unsigned varint. Returns `(value, bytes_consumed)`.
fn read_uvarint(b: &[u8]) -> Option<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    for (i, &byte) in b.iter().enumerate() {
        result |= ((byte & 0x7f) as u64) << shift;
        if byte & 0x80 == 0 {
            return Some((result, i + 1));
        }
        shift += 7;
        if shift > 63 {
            return None;
        }
    }
    None
}

/// Read a `<uvarint len><bytes>` pair from `b`, returning the string slice
/// plus the remainder. Returns `None` if the length overruns the buffer.
fn read_uvarint_string(b: &[u8]) -> Option<(&str, &[u8])> {
    let (len, n) = read_uvarint(b)?;
    let len = len as usize;
    if b.len() < n + len {
        return None;
    }
    let s = std::str::from_utf8(&b[n..n + len]).ok()?;
    Some((s, &b[n + len..]))
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn encode_uvarint(n: u64) -> Vec<u8> {
        let mut out = Vec::new();
        let mut v = n;
        loop {
            let byte = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(byte);
                return out;
            }
            out.push(byte | 0x80);
        }
    }

    fn synth_go_binary(version: &str, modinfo: &str) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(ELF_MAGIC); // rough ELF header stand-in
        out.extend_from_slice(&[0u8; 60]); // filler so the magic isn't at offset 0
        out.extend_from_slice(GO_BUILDINFO_MAGIC);
        out.push(8); // ptrSize
        out.push(2); // flags: inline format
        out.extend_from_slice(&encode_uvarint(version.len() as u64));
        out.extend_from_slice(version.as_bytes());
        out.extend_from_slice(&encode_uvarint(modinfo.len() as u64));
        out.extend_from_slice(modinfo.as_bytes());
        out
    }

    #[test]
    fn extracts_main_module_and_deps() {
        let modinfo = "path\tgithub.com/acme/app\nmod\tgithub.com/acme/app\t(devel)\n\
                       dep\tgolang.org/x/sync\tv0.5.0\tsum\n\
                       dep\tgithub.com/foo/bar\tv1.2.3\tsum";
        let bin = synth_go_binary("go1.21.0", modinfo);
        let mut pkgs = Vec::new();
        parse("layer", &bin, &mut pkgs);
        let names: Vec<&str> = pkgs.iter().map(|p| p.name.as_str()).collect();
        assert!(names.contains(&"github.com/acme/app"));
        assert!(names.contains(&"golang.org/x/sync"));
        assert!(names.contains(&"github.com/foo/bar"));
        let bar = pkgs.iter().find(|p| p.name == "github.com/foo/bar").unwrap();
        assert_eq!(bar.version, "v1.2.3");
        assert_eq!(bar.ecosystem, "go");
        assert_eq!(bar.purl, "pkg:golang/github.com/foo/bar@v1.2.3");
    }

    #[test]
    fn non_elf_input_is_ignored() {
        let mut pkgs = Vec::new();
        parse("layer", b"not an elf", &mut pkgs);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn elf_without_buildinfo_is_ignored() {
        let mut data = Vec::new();
        data.extend_from_slice(ELF_MAGIC);
        data.extend_from_slice(&[0u8; 1024]);
        let mut pkgs = Vec::new();
        parse("layer", &data, &mut pkgs);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn deduplicates_repeated_entries() {
        let modinfo =
            "dep\tgolang.org/x/net\tv0.1.0\nnsum\ndep\tgolang.org/x/net\tv0.1.0\nnsum";
        let bin = synth_go_binary("go1.21", modinfo);
        let mut pkgs = Vec::new();
        parse("layer", &bin, &mut pkgs);
        let count = pkgs.iter().filter(|p| p.name == "golang.org/x/net").count();
        assert_eq!(count, 1);
    }
}
