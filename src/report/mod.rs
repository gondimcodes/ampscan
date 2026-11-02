//! PDF Report Generation
//!
//! This module generates formatted PDF reports using the `printpdf` crate based
//! on the `ScanReport` data containing network scan results.

pub mod config;
pub mod procedures;
pub mod text;
pub mod writer;

pub use config::{AppConfig, CompanyConfig};

use crate::scanner::result::{PortStatus, ScanReport};
use anyhow::Result;
#[allow(unused)]
use printpdf::*;
use procedures::get_manual_command;
use std::fs::File;
use text::{wrap_command, wrap_text};
use writer::*;

/// Generate a PDF report from scan results.
pub fn generate_pdf(
    report: &ScanReport,
    output_path: &str,
    client_name: Option<&str>,
    recipient: Option<&str>,
    config: &AppConfig,
) -> Result<()> {
    let mut w = PdfWriter::new()?;

    // ── Logo and Company Header ────────────────────────────────────
    let mut logo_rendered = false;
    if let Some(ref company) = config.company {
        if let Some(ref logo_path) = company.logo_path {
            if std::path::Path::new(logo_path).exists() {
                let load_res = (|| -> Result<RawImage> {
                    let file = File::open(logo_path)?;
                    let reader = std::io::BufReader::new(file);
                    let img_reader = ::image::ImageReader::new(reader).with_guessed_format()?;
                    let format = img_reader
                        .format()
                        .ok_or_else(|| anyhow::anyhow!("Undetected image format"))?;

                    match format {
                        ::image::ImageFormat::Png => {
                            let dynamic_img = ::image::open(logo_path)?;
                            let (width, height) =
                                <::image::DynamicImage as ::image::GenericImageView>::dimensions(
                                    &dynamic_img,
                                );
                            let mut white_bg = ::image::ImageBuffer::from_pixel(
                                width,
                                height,
                                ::image::Rgba([255u8, 255u8, 255u8, 255u8]),
                            );
                            ::image::imageops::overlay(
                                &mut white_bg,
                                &dynamic_img.to_rgba8(),
                                0,
                                0,
                            );

                            let rgb_img = ::image::DynamicImage::ImageRgba8(white_bg).into_rgb8();

                            let mut buffer = std::io::Cursor::new(Vec::new());
                            rgb_img.write_to(&mut buffer, ::image::ImageFormat::Png)?;
                            let bytes = buffer.into_inner();
                            let mut warnings = Vec::new();
                            RawImage::decode_from_bytes(&bytes, &mut warnings)
                                .map_err(|e| anyhow::anyhow!("PNG error: {:?}", e))
                        }
                        ::image::ImageFormat::Jpeg => {
                            let bytes = std::fs::read(logo_path)?;
                            let mut warnings = Vec::new();
                            RawImage::decode_from_bytes(&bytes, &mut warnings)
                                .map_err(|e| anyhow::anyhow!("JPEG error: {:?}", e))
                        }
                        _ => anyhow::bail!("Unsupported image format: {:?}", format),
                    }
                })();

                match load_res {
                    Ok(raw_image) => {
                        let scale = company.logo_scale.unwrap_or(0.15);
                        let logo_height = scale * 30.0; // Dynamic spacing calculation
                        w.ensure_space(logo_height + 5.0);

                        let image_id = w.doc.add_image(&raw_image);
                        let page = &mut w.doc.pages[w.page_index];
                        page.ops.push(Op::UseXobject {
                            id: image_id,
                            transform: XObjectTransform {
                                translate_x: Some(Mm(MARGIN).into()),
                                translate_y: Some(Mm(w.y - logo_height).into()),
                                scale_x: Some(scale),
                                scale_y: Some(scale),
                                ..Default::default()
                            },
                        });
                        w.skip(logo_height + 5.0);
                        logo_rendered = true;
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to load logo '{}': {}", logo_path, e);
                    }
                }
            }
        }
    }

    if !logo_rendered {
        w.skip(10.0);
    }

    // Company metadata at the top
    if let Some(ref company) = config.company {
        if let Some(ref name) = company.name {
            w.text(name, HEADING_SIZE, HEADING_LH, true);
        }
        if let Some(ref cnpj) = company.cnpj {
            w.text(&format!("CNPJ: {}", cnpj), SMALL_SIZE, SMALL_LH, false);
        }
        if let Some(ref addr) = company.address {
            w.text(addr, SMALL_SIZE, SMALL_LH, false);
        }
        if let Some(rec) = recipient {
            w.skip(2.0);
            w.text(
                &format!("Recipient: {}", rec),
                SUBHEADING_SIZE,
                SUBHEADING_LH,
                true,
            );
        }
        w.skip(5.0);
        w.hline();
    }

    // ── Cover Page Title ───────────────────────────────────────────
    w.skip(20.0);
    w.text("AmpScan", TITLE_SIZE, TITLE_LH, true);
    w.skip(4.0);
    w.text(
        "DDoS Amplification Ports Report",
        HEADING_SIZE,
        HEADING_LH,
        false,
    );
    w.skip(15.0);

    // Client metadata
    if let Some(client) = client_name {
        w.text(
            &format!("Client: {}", client),
            SUBHEADING_SIZE,
            SUBHEADING_LH,
            true,
        );
        w.skip(5.0);
    }

    // Scan Details
    w.text(
        &format!("Scan ID: {}", report.scan_id),
        BODY_SIZE,
        BODY_LH,
        false,
    );

    // Emission Date and Time in UTC
    let emission_time = chrono::Utc::now();
    let emission_str = emission_time.format("%d/%m/%Y %H:%M:%S UTC").to_string();
    w.text(
        &format!("Emission Date: {}", emission_str),
        BODY_SIZE,
        BODY_LH,
        false,
    );

    w.text(
        &format!(
            "Scan Start Date: {}",
            report.started_at.format("%d/%m/%Y %H:%M:%S UTC")
        ),
        BODY_SIZE,
        BODY_LH,
        false,
    );
    if let Some(ref finished) = report.finished_at {
        let duration = *finished - report.started_at;
        w.text(
            &format!("Duration: {}s", duration.num_seconds()),
            BODY_SIZE,
            BODY_LH,
            false,
        );
    }
    let prefixes_text = format!("Scanned prefixes: {}", report.prefixes_scanned.join(", "));
    for line in wrap_text(&prefixes_text, 90) {
        w.text(&line, BODY_SIZE, BODY_LH, false);
    }
    w.text(
        &format!("Total tested IPs: {}", report.total_ips),
        BODY_SIZE,
        BODY_LH,
        false,
    );
    w.text(
        &format!("Total executed probes: {}", report.total_probes),
        BODY_SIZE,
        BODY_LH,
        false,
    );
    if report.check_php {
        w.text(
            "Audit Profile: Full Amplification + PHP2Shell (CVE-2026-109618 / CVE-2026-109619)",
            BODY_SIZE,
            BODY_LH,
            true,
        );
    }

    // ── Executive Summary ──────────────────────────────────────────
    w.skip(15.0);
    w.text("Executive Summary", HEADING_SIZE, HEADING_LH, true);
    w.hline();

    let vuln_count = report.vulnerable_results().len();
    let vuln_ips = report.vulnerable_ips();

    w.text(
        &format!("Vulnerable ports found: {}", vuln_count),
        SUBHEADING_SIZE,
        SUBHEADING_LH,
        true,
    );
    w.text(
        &format!("IPs with at least one vulnerable port: {}", vuln_ips.len()),
        SUBHEADING_SIZE,
        SUBHEADING_LH,
        true,
    );

    if vuln_count == 0 {
        w.skip(10.0);
        w.text(
            "No vulnerable amplification ports were found in the tested prefixes.",
            BODY_SIZE,
            BODY_LH,
            false,
        );
        w.save(output_path)?;
        return Ok(());
    }

    // ── Breakdown by Service ───────────────────────────────────────
    w.skip(10.0);
    w.text(
        "Distribution by Service",
        SUBHEADING_SIZE,
        SUBHEADING_LH,
        true,
    );
    w.skip(3.0);

    let by_service = report.vulnerable_by_service();

    // Table header
    w.ensure_space(BODY_LH * 2.0);
    w.text_at("Service", BODY_SIZE, MARGIN, true);
    w.text_at("Occurrences", BODY_SIZE, MARGIN + 60.0, true);
    w.skip(BODY_LH);
    w.hline();

    for (service, count) in &by_service {
        w.ensure_space(BODY_LH + 2.0);
        w.text_at(service, BODY_SIZE, MARGIN, false);
        w.text_at(&count.to_string(), BODY_SIZE, MARGIN + 60.0, false);
        w.skip(BODY_LH);
    }

    // ── Detailed Results ───────────────────────────────────────────
    w.new_page();
    w.text(
        "Detailed Results - Vulnerable Ports",
        HEADING_SIZE,
        HEADING_LH,
        true,
    );
    w.hline();
    w.skip(2.0);

    // Table header
    let hdr_x = MARGIN;
    w.text_at("IP", SMALL_SIZE, hdr_x + COL_IP, true);
    w.text_at("Port", SMALL_SIZE, hdr_x + COL_PORT, true);
    w.text_at("Proto", SMALL_SIZE, hdr_x + COL_PROTO, true);
    w.text_at("Service", SMALL_SIZE, hdr_x + COL_SVC, true);
    w.text_at("Risk Description", SMALL_SIZE, hdr_x + COL_DESC, true);
    w.skip(SMALL_LH);
    w.hline();

    for result in report.vulnerable_results() {
        let desc_lines = wrap_text(&result.description, DESC_MAX_CHARS);
        let row_height = SMALL_LH * desc_lines.len() as f32 + 1.0;
        w.ensure_space(row_height + 2.0);

        w.text_at(&result.ip.to_string(), SMALL_SIZE, hdr_x + COL_IP, false);
        w.text_at(
            &result.port.to_string(),
            SMALL_SIZE,
            hdr_x + COL_PORT,
            false,
        );
        w.text_at(
            &result.protocol.to_uppercase(),
            SMALL_SIZE,
            hdr_x + COL_PROTO,
            false,
        );
        w.text_at(&result.service_name, SMALL_SIZE, hdr_x + COL_SVC, false);

        // First line of description on same row
        if let Some(first) = desc_lines.first() {
            w.text_at(first, SMALL_SIZE, hdr_x + COL_DESC, false);
        }
        w.skip(SMALL_LH);

        // Remaining description lines
        for line in desc_lines.iter().skip(1) {
            w.text_at(line, SMALL_SIZE, hdr_x + COL_DESC, false);
            w.skip(SMALL_LH);
        }
        w.skip(1.0); // Row spacing
    }

    // ── Per-IP Detail Section ──────────────────────────────────────
    w.new_page();
    w.text("Vulnerable IP Details", HEADING_SIZE, HEADING_LH, true);
    w.hline();

    for vuln_ip in &vuln_ips {
        w.ensure_space(SUBHEADING_LH + BODY_LH * 3.0);
        w.skip(4.0);
        w.text(
            &format!("IP: {}", vuln_ip),
            SUBHEADING_SIZE,
            SUBHEADING_LH,
            true,
        );

        let ip_results: Vec<_> = report
            .results
            .iter()
            .filter(|r| r.ip == *vuln_ip && r.status == PortStatus::Open)
            .collect();

        for r in &ip_results {
            let prefix = format!(
                "  * {}/{} ({}) - ",
                r.port,
                r.protocol.to_uppercase(),
                r.service_name
            );
            // Wrap description dynamically to fit the page width (~115 chars max for SMALL_SIZE)
            let desc_width = 115usize.saturating_sub(prefix.len()).max(40);
            let desc_lines = wrap_text(&r.description, desc_width);

            if let Some(first) = desc_lines.first() {
                w.text(&format!("{}{}", prefix, first), SMALL_SIZE, SMALL_LH, false);
            }

            let indent = " ".repeat(prefix.len());
            for line in desc_lines.iter().skip(1) {
                w.text(&format!("{}{}", indent, line), SMALL_SIZE, SMALL_LH, false);
            }
        }
    }

    // ── Manual Validation Procedures ───────────────────────────────
    let open_services: std::collections::BTreeSet<(String, u16, String)> = report
        .results
        .iter()
        .filter(|r| r.status == PortStatus::Open)
        .map(|r| (r.service_name.clone(), r.port, r.protocol.clone()))
        .collect();

    if !open_services.is_empty() {
        w.new_page();
        w.text(
            "Manual Validation Procedures",
            HEADING_SIZE,
            HEADING_LH,
            true,
        );
        w.hline();
        w.text(
            "To manually verify the identified amplification ports, you can execute the following commands from a terminal:",
            BODY_SIZE,
            BODY_LH,
            false,
        );
        w.skip(4.0);

        for (service, port, protocol) in &open_services {
            w.ensure_space(BODY_LH * 5.0 + 4.0);
            w.text(
                &format!("* Service: {}", service),
                SUBHEADING_SIZE,
                SUBHEADING_LH,
                true,
            );

            let command = get_manual_command(service, *port, protocol);

            // Wrap the command — two-level strategy:
            // (1) word wrap at spaces, (2) char-level break for long tokens
            // without spaces (e.g., hex payloads like SLP's \x02\x01...).
            // CMD_MAX_CHARS is calibrated for SMALL_SIZE (8pt) Helvetica at 170mm usable width.
            const CMD_MAX_CHARS: usize = 100;
            let cmd_lines = wrap_command(&format!("  {}", command), CMD_MAX_CHARS);
            let cmd_block_height = SMALL_LH * (cmd_lines.len() as f32) + SUBHEADING_LH + 6.0;
            w.ensure_space(cmd_block_height);

            w.text("  Command:", SMALL_SIZE, SMALL_LH, true);
            for line in &cmd_lines {
                w.text(line, SMALL_SIZE, SMALL_LH, false);
            }
            w.skip(3.0);
        }
    }

    // ── PHP2Shell Advisory & Mitigation Section (if --check-php was used) ──
    if report.check_php || report.has_php_findings() {
        w.new_page();
        w.text(
            "PHP2Shell Security Advisory (CVE-2026-109618 / CVE-2026-109619)",
            HEADING_SIZE,
            HEADING_LH,
            true,
        );
        w.hline();
        w.skip(2.0);

        let advisory_p1 = "Critical vulnerabilities disclosed in October 2026 (CVSS 9.2) affect the core PHP interpreter from version 5.4 up to 8.5.11 (CVE-2026-109618 memory corruption on Out-Of-Memory and CVE-2026-109619 Use-After-Free in worker processes). AmpScan audits these ports using non-intrusive HTTP HEAD banner grabbing without sending exploit payloads.";
        for line in wrap_text(advisory_p1, 95) {
            w.text(&line, BODY_SIZE, BODY_LH, false);
        }
        w.skip(4.0);

        w.text(
            "Official Upstream Patched Versions (PHP Foundation):",
            SUBHEADING_SIZE,
            SUBHEADING_LH,
            true,
        );
        w.text("  * Branch 8.5: PHP >= 8.5.12", BODY_SIZE, BODY_LH, false);
        w.text("  * Branch 8.4: PHP >= 8.4.27", BODY_SIZE, BODY_LH, false);
        w.text("  * Branch 8.3: PHP >= 8.3.36", BODY_SIZE, BODY_LH, false);
        w.text("  * Branch 8.2: PHP >= 8.2.35", BODY_SIZE, BODY_LH, false);
        w.text(
            "  * Versions 8.1, 7.x, 5.x: EOL (No upstream patch - upgrade immediately)",
            BODY_SIZE,
            BODY_LH,
            false,
        );
        w.skip(4.0);

        w.text(
            "Mitigation & Hardening Guidelines for Clients:",
            SUBHEADING_SIZE,
            SUBHEADING_LH,
            true,
        );
        w.text(
            "  1. Definitive OS Update: Run 'apt update && apt upgrade' (Debian/Ubuntu) or equivalent.",
            BODY_SIZE,
            BODY_LH,
            false,
        );
        let backport_note = "     Important Note on Linux Backports: Linux distributions (Debian, Ubuntu, RHEL) frequently backport security fixes while preserving package version strings. Advise clients to verify system package changelogs if the reported banner indicates a vulnerable upstream version.";
        for line in wrap_text(backport_note, 95) {
            w.text(&line, SMALL_SIZE, SMALL_LH, false);
        }
        w.text(
            "  2. PHP-FPM Pool Mitigation: Set 'pm.max_requests = 1' in www.conf to force worker recycling.",
            BODY_SIZE,
            BODY_LH,
            false,
        );
        w.text(
            "  3. Information Disclosure: Set 'expose_php = Off' in php.ini to prevent version discovery.",
            BODY_SIZE,
            BODY_LH,
            false,
        );
        w.skip(5.0);
    }

    // ── Disclaimer ─────────────────────────────────────────────────
    w.skip(20.0);
    w.ensure_space(20.0);
    w.text("Disclaimer", BODY_SIZE, BODY_LH, true);
    w.text(
        "This report was generated by the AmpScan tool for security audit purposes.",
        SMALL_SIZE,
        SMALL_LH,
        false,
    );
    w.text(
        "The use of this tool must be authorized by the network owner.",
        SMALL_SIZE,
        SMALL_LH,
        false,
    );
    w.text(
        "The authors are not responsible for any misuse.",
        SMALL_SIZE,
        SMALL_LH,
        false,
    );

    w.save(output_path)?;
    Ok(())
}
