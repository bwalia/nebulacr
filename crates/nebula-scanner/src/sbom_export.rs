//! SBOM emission in CycloneDX 1.5 and SPDX 2.3 JSON formats.
//!
//! We emit from `ScanResult` since it already holds both the package list
//! and the vulnerability findings — no re-extraction needed. Both formats
//! are hand-assembled as `serde_json::Value` rather than via generated
//! bindings: this keeps the dependency surface flat and the output
//! inspectable.

use chrono::Utc;
use serde_json::{Value, json};

use crate::model::ScanResult;

pub fn cyclonedx_1_5(result: &ScanResult) -> Value {
    let components: Vec<Value> = result
        .packages
        .iter()
        .map(|p| {
            let mut props = vec![];
            if let Some(layer) = &p.layer_digest {
                props.push(json!({"name":"nebulacr:layer", "value": layer}));
            }
            let mut c = json!({
                "type": "library",
                "name": p.name,
                "version": p.version,
                "purl": p.purl,
            });
            if !props.is_empty() {
                c["properties"] = Value::Array(props);
            }
            c
        })
        .collect();

    let vulnerabilities: Vec<Value> = result
        .vulnerabilities
        .iter()
        .filter(|v| !v.suppressed)
        .map(|v| {
            let source = if v.id.starts_with("CVE-") {
                "NVD"
            } else if v.id.starts_with("GHSA-") {
                "GitHub Advisory"
            } else {
                "OSV"
            };
            let mut rating = json!({
                "severity": format!("{:?}", v.severity).to_lowercase(),
                "source": {"name": source},
            });
            if let Some(score) = v.cvss_score {
                rating["score"] = json!(score);
                rating["method"] = json!("CVSSv3");
            }
            json!({
                "id": v.id,
                "source": {"name": source},
                "ratings": [rating],
                "affects": [{"ref": format!("pkg:{}", v.package)}],
                "description": v.summary.clone().unwrap_or_default(),
            })
        })
        .collect();

    json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "serialNumber": format!("urn:uuid:{}", result.id),
        "metadata": {
            "timestamp": Utc::now().to_rfc3339(),
            "tools": [{"vendor":"NebulaCR","name":"nebula-scanner"}],
            "component": {
                "type":"container",
                "name": format!("{}/{}/{}", result.tenant, result.project, result.repository),
                "version": result.reference,
                "purl": format!("pkg:oci/{}@{}", result.repository, result.digest),
            }
        },
        "components": components,
        "vulnerabilities": vulnerabilities,
    })
}

pub fn spdx_2_3(result: &ScanResult) -> Value {
    let packages: Vec<Value> = result
        .packages
        .iter()
        .enumerate()
        .map(|(i, p)| {
            json!({
                "SPDXID": format!("SPDXRef-Package-{i}"),
                "name": p.name,
                "versionInfo": p.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": false,
                "externalRefs": [{
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": p.purl,
                }],
            })
        })
        .collect();

    json!({
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": format!("{}/{}/{}:{}", result.tenant, result.project, result.repository, result.reference),
        "documentNamespace": format!(
            "https://nebulacr/{tenant}/{project}/{repo}/{id}",
            tenant = result.tenant,
            project = result.project,
            repo = result.repository,
            id = result.id,
        ),
        "creationInfo": {
            "created": Utc::now().to_rfc3339(),
            "creators": ["Tool: nebula-scanner"],
        },
        "packages": packages,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::*;
    use crate::sbom::Package;
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_result() -> ScanResult {
        ScanResult {
            id: Uuid::nil(),
            digest: "sha256:xx".into(),
            tenant: "t".into(),
            project: "p".into(),
            repository: "r".into(),
            reference: "1.0".into(),
            status: ScanStatus::Completed,
            error: None,
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            summary: ScanSummary::default(),
            vulnerabilities: vec![Vulnerability {
                id: "CVE-1".into(),
                aliases: vec![],
                package: "openssl".into(),
                ecosystem: "deb".into(),
                installed_version: "1.1.1".into(),
                fixed_version: Some("1.1.1k".into()),
                severity: Severity::High,
                cvss_score: Some(7.5),
                summary: Some("flaw".into()),
                description: None,
                layer_digest: Some("sha256:layer".into()),
                references: vec![],
                suppressed: false,
            }],
            policy_evaluation: None,
            packages: vec![Package {
                name: "openssl".into(),
                version: "1.1.1".into(),
                ecosystem: "deb".into(),
                purl: "pkg:deb/openssl@1.1.1".into(),
                layer_digest: Some("sha256:layer".into()),
            }],
        }
    }

    #[test]
    fn cyclonedx_emits_component_and_vuln() {
        let v = cyclonedx_1_5(&sample_result());
        assert_eq!(v["bomFormat"], "CycloneDX");
        assert_eq!(v["specVersion"], "1.5");
        let components = v["components"].as_array().unwrap();
        assert_eq!(components.len(), 1);
        assert_eq!(components[0]["purl"], "pkg:deb/openssl@1.1.1");
        let vulns = v["vulnerabilities"].as_array().unwrap();
        assert_eq!(vulns[0]["id"], "CVE-1");
        assert_eq!(vulns[0]["ratings"][0]["score"], 7.5);
    }

    #[test]
    fn spdx_document_has_packages_and_namespace() {
        let v = spdx_2_3(&sample_result());
        assert_eq!(v["spdxVersion"], "SPDX-2.3");
        assert_eq!(v["dataLicense"], "CC0-1.0");
        let packages = v["packages"].as_array().unwrap();
        assert_eq!(packages[0]["name"], "openssl");
        assert_eq!(packages[0]["versionInfo"], "1.1.1");
    }

    #[test]
    fn cyclonedx_excludes_suppressed() {
        let mut r = sample_result();
        r.vulnerabilities[0].suppressed = true;
        let v = cyclonedx_1_5(&r);
        assert!(v["vulnerabilities"].as_array().unwrap().is_empty());
    }
}
