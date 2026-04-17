//! RPM SBOM parser.
//!
//! RPM package databases live at `/var/lib/rpm/Packages` (Berkeley DB, older
//! RHEL/CentOS) or `/var/lib/rpm/rpmdb.sqlite` (dnf/newer Fedora/RHEL 9).
//! The two containers are very different binary formats, but both hold the
//! same RPM *header blob* format for each installed package — and the
//! header blob has a hard-to-mistake 8-byte magic `8E AD E8 01 00 00 00 00`
//! that appears nowhere else in either container.
//!
//! So we side-step container parsing entirely: scan the input bytes for the
//! header magic and parse each header we find. Works on BDB and sqlite
//! alike, tolerates unknown-format DBs gracefully (zero matches → zero
//! packages), and avoids pulling in a Berkeley DB or SQLite dependency
//! just for SBOM extraction.
//!
//! Trade-off: we rely on the header magic's uniqueness. If a false positive
//! slips in, `parse_header` rejects it in the bounds-check step because
//! the index-entry offsets must address bytes inside the declared data blob.

use super::Package;

const HEADER_MAGIC: [u8; 8] = [0x8E, 0xAD, 0xE8, 0x01, 0x00, 0x00, 0x00, 0x00];

const TAG_NAME: u32 = 1000;
const TAG_VERSION: u32 = 1001;
const TAG_RELEASE: u32 = 1002;
const TAG_EPOCH: u32 = 1003;
const TAG_ARCH: u32 = 1022;

const TYPE_INT32: u32 = 4;
const TYPE_STRING: u32 = 6;
const TYPE_I18NSTRING: u32 = 9;

pub fn parse(layer_digest: &str, contents: &[u8], out: &mut Vec<Package>) {
    let mut seen = std::collections::HashSet::new();
    let mut i = 0usize;
    while let Some(offset) = find_subslice(&contents[i..], &HEADER_MAGIC) {
        let header_start = i + offset;
        match parse_header(&contents[header_start..]) {
            Some((header_len, pkg)) => {
                // Dedup on (name, version) — some DBs hold duplicate entries
                // when a package was reinstalled / updated in place.
                let key = (pkg.name.clone(), pkg.version.clone());
                if seen.insert(key) {
                    out.push(Package {
                        name: pkg.name,
                        version: pkg.version,
                        ecosystem: "rpm".into(),
                        purl: format!("pkg:rpm/{}@{}", pkg.package_name, pkg.full_version),
                        layer_digest: Some(layer_digest.to_string()),
                    });
                }
                i = header_start + header_len;
            }
            None => {
                // False-positive magic. Step past the first magic byte and
                // keep scanning.
                i = header_start + 1;
            }
        }
    }
}

struct ParsedHeader {
    name: String,
    package_name: String,
    version: String,
    full_version: String,
}

/// Parse one RPM header blob starting at `bytes[0]` (which must begin with
/// `HEADER_MAGIC`). Returns `(bytes_consumed, package)` on success.
fn parse_header(bytes: &[u8]) -> Option<(usize, ParsedHeader)> {
    if bytes.len() < 16 || bytes[..8] != HEADER_MAGIC {
        return None;
    }
    let entry_count = read_be_u32(&bytes[8..12])? as usize;
    let data_len = read_be_u32(&bytes[12..16])? as usize;
    // 16 byte preamble + 16 bytes per index entry + data blob
    let entries_end = 16usize.checked_add(entry_count.checked_mul(16)?)?;
    let total = entries_end.checked_add(data_len)?;
    if bytes.len() < total || entry_count == 0 || entry_count > 10_000 {
        return None;
    }

    let entries = &bytes[16..entries_end];
    let data = &bytes[entries_end..total];

    let mut name = None;
    let mut version = None;
    let mut release = None;
    let mut epoch: Option<u32> = None;
    let mut arch = None;

    for chunk in entries.chunks_exact(16) {
        let tag = read_be_u32(&chunk[0..4])?;
        let ty = read_be_u32(&chunk[4..8])?;
        let off = read_be_u32(&chunk[8..12])? as usize;
        let count = read_be_u32(&chunk[12..16])? as usize;
        if off >= data.len() {
            return None;
        }
        match (tag, ty) {
            (TAG_NAME, TYPE_STRING) => name = read_cstring(&data[off..]),
            (TAG_VERSION, TYPE_STRING) => version = read_cstring(&data[off..]),
            (TAG_RELEASE, TYPE_STRING) => release = read_cstring(&data[off..]),
            (TAG_ARCH, TYPE_STRING) => arch = read_cstring(&data[off..]),
            (TAG_EPOCH, TYPE_INT32) if count >= 1 && off + 4 <= data.len() => {
                epoch = Some(read_be_u32(&data[off..off + 4])?);
            }
            // Summary / description are i18n string arrays — we don't need them.
            (_, TYPE_I18NSTRING) => {}
            _ => {}
        }
    }

    let n = name?;
    let v = version?;
    let r = release?;
    let full_version = match (epoch, arch.as_deref()) {
        (Some(e), Some(a)) if e > 0 => format!("{e}:{v}-{r}.{a}"),
        (Some(e), None) if e > 0 => format!("{e}:{v}-{r}"),
        (_, Some(a)) => format!("{v}-{r}.{a}"),
        _ => format!("{v}-{r}"),
    };

    Some((
        total,
        ParsedHeader {
            name: n.clone(),
            package_name: n,
            version: format!("{v}-{r}"),
            full_version,
        },
    ))
}

fn read_be_u32(b: &[u8]) -> Option<u32> {
    if b.len() < 4 {
        return None;
    }
    Some(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

fn read_cstring(b: &[u8]) -> Option<String> {
    let end = b.iter().position(|&c| c == 0)?;
    std::str::from_utf8(&b[..end]).ok().map(str::to_string)
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

    /// Assembles a minimal synthetic RPM header with the given tags/strings.
    fn make_header(entries: &[(u32, u32, &[u8])]) -> Vec<u8> {
        // Layout the data blob and index entries pointing into it.
        let mut data = Vec::new();
        let mut index_entries = Vec::new();
        for (tag, ty, payload) in entries {
            let offset = data.len() as u32;
            let count = if *ty == TYPE_INT32 { 1u32 } else { 1u32 };
            data.extend_from_slice(payload);
            if *ty == TYPE_STRING {
                // strings are null-terminated
                if !payload.ends_with(&[0]) {
                    data.push(0);
                }
            }
            index_entries.extend_from_slice(&tag.to_be_bytes());
            index_entries.extend_from_slice(&ty.to_be_bytes());
            index_entries.extend_from_slice(&offset.to_be_bytes());
            index_entries.extend_from_slice(&count.to_be_bytes());
        }
        let mut out = Vec::new();
        out.extend_from_slice(&HEADER_MAGIC);
        out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
        out.extend_from_slice(&(data.len() as u32).to_be_bytes());
        out.extend_from_slice(&index_entries);
        out.extend_from_slice(&data);
        out
    }

    #[test]
    fn parses_single_header() {
        let mut hdr = make_header(&[
            (TAG_NAME, TYPE_STRING, b"openssl\0"),
            (TAG_VERSION, TYPE_STRING, b"1.1.1k\0"),
            (TAG_RELEASE, TYPE_STRING, b"7.el8_4\0"),
            (TAG_ARCH, TYPE_STRING, b"x86_64\0"),
        ]);
        // Put some noise before the header — simulates a BDB page prefix.
        let mut buf = vec![0u8; 64];
        buf.append(&mut hdr);
        let mut pkgs = Vec::new();
        parse("sha256:layerX", &buf, &mut pkgs);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].name, "openssl");
        assert_eq!(pkgs[0].ecosystem, "rpm");
        assert_eq!(pkgs[0].version, "1.1.1k-7.el8_4");
        assert_eq!(pkgs[0].purl, "pkg:rpm/openssl@1.1.1k-7.el8_4.x86_64");
        assert_eq!(pkgs[0].layer_digest.as_deref(), Some("sha256:layerX"));
    }

    #[test]
    fn includes_epoch_when_nonzero() {
        let mut epoch_bytes = vec![0u8; 4];
        epoch_bytes[3] = 2; // big-endian 2
        let hdr = make_header(&[
            (TAG_NAME, TYPE_STRING, b"mysql\0"),
            (TAG_VERSION, TYPE_STRING, b"8.0.28\0"),
            (TAG_RELEASE, TYPE_STRING, b"1.el9\0"),
            (TAG_EPOCH, TYPE_INT32, &epoch_bytes),
        ]);
        let mut pkgs = Vec::new();
        parse("layer", &hdr, &mut pkgs);
        assert_eq!(pkgs.len(), 1);
        assert_eq!(pkgs[0].purl, "pkg:rpm/mysql@2:8.0.28-1.el9");
    }

    #[test]
    fn dedupes_repeated_headers() {
        let h = make_header(&[
            (TAG_NAME, TYPE_STRING, b"curl\0"),
            (TAG_VERSION, TYPE_STRING, b"7.80\0"),
            (TAG_RELEASE, TYPE_STRING, b"1\0"),
        ]);
        let mut buf = Vec::new();
        buf.extend_from_slice(&h);
        buf.extend_from_slice(&h);
        let mut pkgs = Vec::new();
        parse("layer", &buf, &mut pkgs);
        assert_eq!(pkgs.len(), 1);
    }

    #[test]
    fn empty_input_yields_nothing() {
        let mut pkgs = Vec::new();
        parse("layer", &[], &mut pkgs);
        assert!(pkgs.is_empty());
    }

    #[test]
    fn false_positive_magic_is_skipped() {
        // Magic followed by garbage (not a valid header prelude).
        let mut buf = Vec::new();
        buf.extend_from_slice(&HEADER_MAGIC);
        buf.extend_from_slice(&[0xff; 4]); // entry_count huge → rejected
        buf.extend_from_slice(&[0xff; 4]);
        let mut pkgs = Vec::new();
        parse("layer", &buf, &mut pkgs);
        assert!(pkgs.is_empty());
    }
}
