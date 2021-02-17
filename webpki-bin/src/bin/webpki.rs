// Copyright 2021 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR
// ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
// ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
// OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

use clap::Clap;
use std::convert::TryFrom;
use std::env;
use std::fs;
use std::path::Path;
use std::path::PathBuf;
use std::process;
use std::time::SystemTime;

static ALL_SIGALGS: &[&webpki::SignatureAlgorithm] = &[
    &webpki::ECDSA_P256_SHA256,
    &webpki::ECDSA_P256_SHA384,
    &webpki::ECDSA_P384_SHA256,
    &webpki::ECDSA_P384_SHA384,
    &webpki::ED25519,
    &webpki::RSA_PKCS1_2048_8192_SHA256,
    &webpki::RSA_PKCS1_2048_8192_SHA384,
    &webpki::RSA_PKCS1_2048_8192_SHA512,
    &webpki::RSA_PKCS1_3072_8192_SHA384,
];

#[derive(Clap)]
#[clap(about = "Parse and print a certificate")]
struct PrintCert {
    filename: PathBuf,
}

#[derive(Clap)]
#[clap(about = "Verify server certificate")]
struct VerifyServerCert {
    #[clap(long)]
    trusted_root: PathBuf,
    #[clap(long)]
    intermediates: Vec<PathBuf>,
    #[clap(long)]
    server_cert: PathBuf,
    #[clap(long, about = "Seconds since epoch")]
    time: Option<u64>,
}

#[derive(Clap)]
enum Command {
    PrintCert(PrintCert),
    VerifyServerCert(VerifyServerCert),
}

#[derive(Clap)]
#[clap(about = "Utility to debug webpki. Does not have a stable API.")]
struct Opts {
    #[clap(subcommand)]
    command: Command,
}

fn print_error_and_exit(s: String) -> ! {
    let arg0 = env::args().next();
    let arg0 = arg0.as_ref().map(|s| s.as_str()).unwrap_or("webpki");
    eprintln!("{}: {}", arg0, s);
    process::exit(1)
}

fn read_file(path: &Path) -> Vec<u8> {
    match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) => print_error_and_exit(format!("could not read file {}: {}", path.display(), e)),
    }
}

fn parse_end_entity_cert<'a>(der: &'a [u8], path: &Path) -> webpki::EndEntityCert<'a> {
    match webpki::EndEntityCert::try_from(der) {
        Ok(cert) => cert,
        Err(e) => {
            print_error_and_exit(format!("failed to parse a cert {}: {}", &path.display(), e))
        }
    }
}

fn print_cert(args: PrintCert) {
    let der = read_file(&args.filename);

    let _cert = parse_end_entity_cert(&der, &args.filename);

    eprintln!("cert {} parsed successfully", &args.filename.display());
    // TODO: actually print something about the certificate
}

fn verify_server_cert(args: VerifyServerCert) {
    let server_cert = read_file(&args.server_cert);
    let server_cert = parse_end_entity_cert(&server_cert, &args.server_cert);

    let trusted_root = read_file(&args.trusted_root);

    let trust_anchor = match webpki::TrustAnchor::from_cert_der(&trusted_root) {
        Ok(trust_anchor) => trust_anchor,
        Err(e) => print_error_and_exit(format!(
            "failed to parse trust anchor from {}: {}",
            args.trusted_root.display(),
            e
        )),
    };

    let intermediates: Vec<Vec<u8>> = args
        .intermediates
        .iter()
        .map(|intermediate| read_file(intermediate))
        .collect();
    let intermediates: Vec<&[u8]> = intermediates
        .iter()
        .map(|intermediate| intermediate.as_slice())
        .collect();

    let time = args.time.unwrap_or_else(|| {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    });
    let time = webpki::Time::from_seconds_since_unix_epoch(time);

    match server_cert.verify_is_valid_tls_server_cert(
        ALL_SIGALGS,
        &webpki::TLSServerTrustAnchors(&[trust_anchor]),
        &intermediates,
        time,
    ) {
        Ok(()) => {}
        Err(e) => print_error_and_exit(format!("verify server certificate failed: {}", e)),
    }

    eprintln!("server certificate {} is valid", args.server_cert.display());
}

fn main() {
    let opts: Opts = Opts::parse();
    match opts.command {
        Command::PrintCert(args) => print_cert(args),
        Command::VerifyServerCert(args) => verify_server_cert(args),
    }
}
