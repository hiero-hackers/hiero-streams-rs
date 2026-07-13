//! `attest` — the CLI's only networked command. Fetch this file's
//! `.rcd_sig` from every node's bucket directory plus the current
//! address book, and verify network attestation (≥ ⅓ of nodes signed
//! these exact bytes). Gated behind the `fetch` feature; the library
//! itself never does I/O. GCS is requester-pays: pass
//! `--project <gcp-project>`; auth from `$GCS_OAUTH_TOKEN` or `gcloud`.

use hiero_streams::{verify_record_file, AddressBook, NodeSignature};
use serde_json::json;
use std::process::ExitCode;

const BUCKET: &str = "https://storage.googleapis.com/storage/v1/b/hedera-mainnet-streams/o";

fn percent_encode(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

fn token() -> Result<String, Box<dyn std::error::Error>> {
    if let Ok(t) = std::env::var("GCS_OAUTH_TOKEN") {
        return Ok(t);
    }
    let out = std::process::Command::new("gcloud")
        .args(["auth", "print-access-token"])
        .output()?;
    if !out.status.success() {
        return Err("gcloud auth print-access-token failed (set GCS_OAUTH_TOKEN?)".into());
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn address_book(mirror: &str) -> Result<AddressBook, Box<dyn std::error::Error>> {
    let mut book = AddressBook::new();
    let mut path = "/api/v1/network/nodes?limit=25".to_string();
    loop {
        let body: serde_json::Value = serde_json::from_str(
            &ureq::get(&format!("{mirror}{path}"))
                .call()?
                .into_string()?,
        )?;
        for node in body["nodes"].as_array().into_iter().flatten() {
            if let (Some(account), Some(key)) = (
                node["node_account_id"].as_str(),
                node["public_key"].as_str(),
            ) {
                book.insert(
                    account.to_string(),
                    key.trim_start_matches("0x").to_string(),
                );
            }
        }
        match body["links"]["next"].as_str() {
            Some(next) => path = next.to_string(),
            None => return Ok(book),
        }
    }
}

fn fetch_sig(name: &str, node: &str, project: &str, tok: &str) -> Option<Vec<u8>> {
    let object = percent_encode(&format!("recordstreams/record{node}/{name}"));
    let url = format!("{BUCKET}/{object}?alt=media&userProject={project}");
    let response = ureq::get(&url)
        .set("Authorization", &format!("Bearer {tok}"))
        .call()
        .ok()?;
    let mut bytes = Vec::new();
    std::io::Read::read_to_end(&mut response.into_reader(), &mut bytes).ok()?;
    Some(bytes)
}

pub fn run(args: &[String]) -> Result<ExitCode, Box<dyn std::error::Error>> {
    let Some(rcd_path) = args.first() else {
        eprintln!(
            "usage: hiero-streams attest <file.rcd.gz> --project <gcp-project> [--mirror <url>]"
        );
        return Ok(ExitCode::from(2));
    };
    let project = super::flag(args, "--project")
        .or_else(|| std::env::var("GCS_USER_PROJECT").ok())
        .ok_or("GCS is requester-pays: pass --project or set GCS_USER_PROJECT")?;
    let mirror = super::flag(args, "--mirror")
        .unwrap_or_else(|| "https://mainnet.mirrornode.hedera.com".to_string());

    let file_name = std::path::Path::new(rcd_path)
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or("bad file path")?;
    let sig_name = file_name
        .trim_end_matches(".gz")
        .trim_end_matches(".rcd")
        .to_string()
        + ".rcd_sig";

    let record_bytes = std::fs::read(rcd_path)?;
    let book = address_book(&mirror)?;
    let tok = token()?;
    eprintln!(
        "address book: {} nodes; fetching {sig_name} from each node's directory…",
        book.len()
    );

    let mut signatures = Vec::new();
    let mut missing = Vec::new();
    for node in book.keys() {
        match fetch_sig(&sig_name, node, &project, &tok) {
            Some(bytes) => signatures.push(NodeSignature {
                node: node.clone(),
                bytes,
            }),
            None => missing.push(node.clone()),
        }
    }

    let result = verify_record_file(&record_bytes, &signatures, &book)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "file": file_name,
            "fileHash": hex::encode(result.hash),
            "nodesInAddressBook": result.node_count,
            "signaturesFetched": signatures.len(),
            "signatureMissing": missing,
            "valid": result.valid,
            "invalid": result.invalid,
            "attested": result.attested,
            "meaning": if result.attested {
                "nodes holding >= 1/3 of the address book signed exactly these bytes"
            } else {
                "NOT attested — insufficient valid signatures"
            },
        }))?
    );
    Ok(if result.attested {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}
