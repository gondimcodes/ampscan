//! PDF Report Generation
//!
//! This module generates formatted PDF reports using the `printpdf` crate based
//! on the `ScanReport` data containing network scan results.
use crate::scanner::result::{PortStatus, ScanReport};
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

#[allow(unused)]
use printpdf::*;
use std::fs::File;
use std::io::BufWriter;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompanyConfig {
    pub name: Option<String>,
    pub cnpj: Option<String>,
    pub address: Option<String>,
    pub logo_path: Option<String>,
    pub logo_scale: Option<f32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    pub company: Option<CompanyConfig>,
}

impl AppConfig {
    pub fn load() -> Self {
        match std::fs::read_to_string("config.toml") {
            Ok(content) => toml::from_str(&content).unwrap_or_else(|_| Self::default()),
            Err(_) => Self::default(),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Constants — A4 page layout
// ═══════════════════════════════════════════════════════════════════════════

const PAGE_W: f32 = 210.0;
const PAGE_H: f32 = 297.0;
const MARGIN: f32 = 20.0;
const _USABLE_W: f32 = PAGE_W - 2.0 * MARGIN;

// Font sizes (points)
const TITLE_SIZE: f32 = 28.0;
const HEADING_SIZE: f32 = 16.0;
const SUBHEADING_SIZE: f32 = 12.0;
const BODY_SIZE: f32 = 10.0;
const SMALL_SIZE: f32 = 8.0;

// Line heights (mm) — approximate for each font size
const TITLE_LH: f32 = 12.0;
const HEADING_LH: f32 = 7.0;
const SUBHEADING_LH: f32 = 5.5;
const BODY_LH: f32 = 4.5;
const SMALL_LH: f32 = 3.5;

// Table column positions (X offset from left margin) for the results table
const COL_IP: f32 = 0.0;
const COL_PORT: f32 = 38.0;
const COL_PROTO: f32 = 55.0;
const COL_SVC: f32 = 72.0;
const COL_DESC: f32 = 105.0;
const DESC_MAX_CHARS: usize = 55;

// ═══════════════════════════════════════════════════════════════════════════
// PDF Writer helper
// ═══════════════════════════════════════════════════════════════════════════

struct PdfWriter {
    doc: PdfDocumentReference,
    font: IndirectFontRef,
    font_bold: IndirectFontRef,
    current_layer: PdfLayerReference,
    /// Current Y position from the BOTTOM of the page (decreases as we add content)
    y: f32,
}

impl PdfWriter {
    fn new() -> Result<Self> {
        let (doc, page, layer) = PdfDocument::new(
            "AmpScan - DDoS Amplification Report",
            Mm(PAGE_W),
            Mm(PAGE_H),
            "Content",
        );
        let font = doc
            .add_builtin_font(BuiltinFont::Helvetica)
            .context("Failed to add Helvetica font")?;
        let font_bold = doc
            .add_builtin_font(BuiltinFont::HelveticaBold)
            .context("Failed to add Helvetica Bold font")?;
        let current_layer = doc.get_page(page).get_layer(layer);

        Ok(Self {
            doc,
            font,
            font_bold,
            current_layer,
            y: PAGE_H - MARGIN,
        })
    }

    /// Create a new page and reset Y to the top.
    fn new_page(&mut self) {
        let (page, layer) = self.doc.add_page(Mm(PAGE_W), Mm(PAGE_H), "Content");
        self.current_layer = self.doc.get_page(page).get_layer(layer);
        self.y = PAGE_H - MARGIN;
    }

    /// Ensure there's enough space; if not, start a new page.
    fn ensure_space(&mut self, needed_mm: f32) {
        if self.y - needed_mm < MARGIN {
            self.new_page();
        }
    }

    /// Write text at the current Y position, left-aligned at MARGIN.
    fn text(&mut self, text: &str, size: f32, line_h: f32, bold: bool) {
        self.ensure_space(line_h);
        let font = if bold { &self.font_bold } else { &self.font };
        self.current_layer
            .use_text(sanitize(text), size, Mm(MARGIN), Mm(self.y), font);
        self.y -= line_h;
    }

    /// Write text at a specific X position (relative to page left), at current Y.
    fn text_at(&self, text: &str, size: f32, x: f32, bold: bool) {
        let font = if bold { &self.font_bold } else { &self.font };
        self.current_layer
            .use_text(sanitize(text), size, Mm(x), Mm(self.y), font);
    }

    /// Skip vertical space.
    fn skip(&mut self, mm: f32) {
        self.y -= mm;
    }

    /// Draw a horizontal line at the current Y position.
    fn hline(&mut self) {
        let points = vec![
            (Point::new(Mm(MARGIN), Mm(self.y)), false),
            (Point::new(Mm(PAGE_W - MARGIN), Mm(self.y)), false),
        ];
        let line = Line {
            points,
            is_closed: false,
        };
        self.current_layer.add_line(line);
        self.skip(5.0);
    }

    /// Save the document to a file.
    fn save(self, path: &str) -> Result<()> {
        let file = File::create(path)
            .with_context(|| format!("Failed to create PDF file: {}", path))?;
        self.doc
            .save(&mut BufWriter::new(file))
            .context("Failed to write PDF content")?;
        Ok(())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Text utilities
// ═══════════════════════════════════════════════════════════════════════════

/// Sanitize text for PDF built-in fonts (WinAnsiEncoding).
/// Transliterates Portuguese accented characters to ASCII equivalents.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            'á' | 'à' | 'â' | 'ã' => 'a',
            'é' | 'è' | 'ê' => 'e',
            'í' | 'ì' | 'î' => 'i',
            'ó' | 'ò' | 'ô' | 'õ' => 'o',
            'ú' | 'ù' | 'û' => 'u',
            'ç' => 'c',
            'Á' | 'À' | 'Â' | 'Ã' => 'A',
            'É' | 'È' | 'Ê' => 'E',
            'Í' | 'Ì' | 'Î' => 'I',
            'Ó' | 'Ò' | 'Ô' | 'Õ' => 'O',
            'Ú' | 'Ù' | 'Û' => 'U',
            'Ç' => 'C',
            _ => c,
        })
        .collect()
}

/// Simple word wrapping.
fn wrap_text(text: &str, max_chars: usize) -> Vec<String> {
    let mut lines = Vec::new();
    let mut current = String::new();
    for word in text.split_whitespace() {
        if !current.is_empty() && current.len() + 1 + word.len() > max_chars {
            lines.push(current);
            current = String::new();
        }
        if !current.is_empty() {
            current.push(' ');
        }
        current.push_str(word);
    }
    if !current.is_empty() {
        lines.push(current);
    }
    if lines.is_empty() {
        lines.push(String::new());
    }
    lines
}

/// Truncate a string for display.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let truncated: String = s.chars().take(max.saturating_sub(3)).collect();
        format!("{}...", truncated)
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Public API
// ═══════════════════════════════════════════════════════════════════════════

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
                // Try to load the image (PNG or JPEG)
                let load_res = (|| -> Result<Image> {
                    let file = File::open(logo_path)?;
                    let reader = std::io::BufReader::new(file);
                    let img_reader = ::image::io::Reader::new(reader).with_guessed_format()?;
                    let format = img_reader.format().ok_or_else(|| anyhow::anyhow!("Undetected image format"))?;

                    match format {
                        ::image::ImageFormat::Png => {
                            let dynamic_img = ::image::open(logo_path)?;
                            let (width, height) = <::image::DynamicImage as ::image::GenericImageView>::dimensions(&dynamic_img);
                            let mut white_bg = ::image::ImageBuffer::from_pixel(width, height, ::image::Rgba([255u8, 255u8, 255u8, 255u8]));
                            ::image::imageops::overlay(&mut white_bg, &dynamic_img.to_rgba8(), 0, 0);

                            let rgb_img = ::image::DynamicImage::ImageRgba8(white_bg).into_rgb8();

                            let mut buffer = std::io::Cursor::new(Vec::new());
                            rgb_img.write_to(&mut buffer, ::image::ImageFormat::Png)?;
                            buffer.set_position(0);

                            let decoder = ::image::codecs::png::PngDecoder::new(buffer)?;
                            Image::try_from(decoder).map_err(|e| anyhow::anyhow!("PNG error: {:?}", e))
                        }
                        ::image::ImageFormat::Jpeg => {
                            let mut file = File::open(logo_path)?;
                            let decoder = ::image::codecs::jpeg::JpegDecoder::new(&mut file)?;
                            Image::try_from(decoder).map_err(|e| anyhow::anyhow!("JPEG error: {:?}", e))
                        }
                        _ => anyhow::bail!("Unsupported image format: {:?}", format),
                    }
                })();

                match load_res {
                    Ok(image) => {
                        let scale = company.logo_scale.unwrap_or(0.15);
                        let logo_height = scale * 30.0; // Dynamic spacing calculation
                        w.ensure_space(logo_height + 5.0);
                        
                        image.add_to_layer(
                            w.current_layer.clone(),
                            ImageTransform {
                                translate_x: Some(Mm(MARGIN)),
                                translate_y: Some(Mm(w.y - logo_height)),
                                scale_x: Some(scale),
                                scale_y: Some(scale),
                                ..Default::default()
                            },
                        );
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
            w.text(&format!("Recipient: {}", rec), SUBHEADING_SIZE, SUBHEADING_LH, true);
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
        w.text(&format!("Client: {}", client), SUBHEADING_SIZE, SUBHEADING_LH, true);
        w.skip(5.0);
    }

    // Scan Details
    w.text(
        &format!("Scan ID: {}", report.scan_id),
        BODY_SIZE,
        BODY_LH,
        false,
    );

    // Emission Date and Time with timezone (Local)
    let emission_time = chrono::Local::now();
    let emission_str = emission_time.format("%d/%m/%Y %H:%M:%S %Z (UTC%z)").to_string();
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
        &format!(
            "IPs with at least one vulnerable port: {}",
            vuln_ips.len()
        ),
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
    w.text("Distribution by Service", SUBHEADING_SIZE, SUBHEADING_LH, true);
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
    w.text(
        "Vulnerable IP Details",
        HEADING_SIZE,
        HEADING_LH,
        true,
    );
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
            let line = format!(
                "  * {}/{} ({}) - {}",
                r.port,
                r.protocol.to_uppercase(),
                r.service_name,
                truncate(&r.description, 80)
            );
            w.text(&line, SMALL_SIZE, SMALL_LH, false);
        }
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
