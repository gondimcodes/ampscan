//! PDF low-level document writer and layout primitives
use super::text::sanitize;
use anyhow::{Context, Result};
#[allow(unused)]
use printpdf::*;

// ═══════════════════════════════════════════════════════════════════════════
// Constants — A4 page layout
// ═══════════════════════════════════════════════════════════════════════════

pub const PAGE_W: f32 = 210.0;
pub const PAGE_H: f32 = 297.0;
pub const MARGIN: f32 = 20.0;
pub const _USABLE_W: f32 = PAGE_W - 2.0 * MARGIN;

// Font sizes (points)
pub const TITLE_SIZE: f32 = 28.0;
pub const HEADING_SIZE: f32 = 16.0;
pub const SUBHEADING_SIZE: f32 = 12.0;
pub const BODY_SIZE: f32 = 10.0;
pub const SMALL_SIZE: f32 = 8.0;

// Line heights (mm) — approximate for each font size
pub const TITLE_LH: f32 = 12.0;
pub const HEADING_LH: f32 = 7.0;
pub const SUBHEADING_LH: f32 = 5.5;
pub const BODY_LH: f32 = 4.5;
pub const SMALL_LH: f32 = 3.5;

// Table column positions (X offset from left margin) for the results table
pub const COL_IP: f32 = 0.0;
pub const COL_PORT: f32 = 38.0;
pub const COL_PROTO: f32 = 55.0;
pub const COL_SVC: f32 = 72.0;
pub const COL_DESC: f32 = 105.0;
pub const DESC_MAX_CHARS: usize = 55;

// ═══════════════════════════════════════════════════════════════════════════
// PDF Writer helper
// ═══════════════════════════════════════════════════════════════════════════

pub struct PdfWriter {
    pub doc: PdfDocument,
    pub page_index: usize,
    /// Current Y position from the BOTTOM of the page (decreases as we add content)
    pub y: f32,
}

impl PdfWriter {
    pub fn new() -> Result<Self> {
        let mut doc = PdfDocument::new("AmpScan - DDoS Amplification Report");
        doc.pages.push(PdfPage::new(Mm(PAGE_W), Mm(PAGE_H), vec![]));

        Ok(Self {
            doc,
            page_index: 0,
            y: PAGE_H - MARGIN,
        })
    }

    /// Create a new page and reset Y to the top.
    pub fn new_page(&mut self) {
        self.doc
            .pages
            .push(PdfPage::new(Mm(PAGE_W), Mm(PAGE_H), vec![]));
        self.page_index = self.doc.pages.len() - 1;
        self.y = PAGE_H - MARGIN;
    }

    /// Ensure there's enough space; if not, start a new page.
    pub fn ensure_space(&mut self, needed_mm: f32) {
        if self.y - needed_mm < MARGIN {
            self.new_page();
        }
    }

    /// Write text at the current Y position, left-aligned at MARGIN.
    pub fn text(&mut self, text: &str, size: f32, line_h: f32, bold: bool) {
        self.ensure_space(line_h);
        let font = if bold {
            PdfFontHandle::Builtin(BuiltinFont::HelveticaBold)
        } else {
            PdfFontHandle::Builtin(BuiltinFont::Helvetica)
        };
        let page = &mut self.doc.pages[self.page_index];
        page.ops.push(Op::StartTextSection);
        page.ops.push(Op::SetTextCursor {
            pos: Point::new(Mm(MARGIN), Mm(self.y)),
        });
        page.ops.push(Op::SetFont {
            font,
            size: Pt(size),
        });
        page.ops.push(Op::ShowText {
            items: vec![TextItem::Text(sanitize(text))],
        });
        page.ops.push(Op::EndTextSection);
        self.y -= line_h;
    }

    /// Write text at a specific X position (relative to page left), at current Y.
    pub fn text_at(&mut self, text: &str, size: f32, x: f32, bold: bool) {
        let font = if bold {
            PdfFontHandle::Builtin(BuiltinFont::HelveticaBold)
        } else {
            PdfFontHandle::Builtin(BuiltinFont::Helvetica)
        };
        let page = &mut self.doc.pages[self.page_index];
        page.ops.push(Op::StartTextSection);
        page.ops.push(Op::SetTextCursor {
            pos: Point::new(Mm(x), Mm(self.y)),
        });
        page.ops.push(Op::SetFont {
            font,
            size: Pt(size),
        });
        page.ops.push(Op::ShowText {
            items: vec![TextItem::Text(sanitize(text))],
        });
        page.ops.push(Op::EndTextSection);
    }

    /// Skip vertical space.
    pub fn skip(&mut self, mm: f32) {
        self.y -= mm;
    }

    /// Draw a horizontal line at the current Y position.
    pub fn hline(&mut self) {
        let page = &mut self.doc.pages[self.page_index];
        let line = Line {
            points: vec![
                LinePoint {
                    p: Point::new(Mm(MARGIN), Mm(self.y)),
                    bezier: false,
                },
                LinePoint {
                    p: Point::new(Mm(PAGE_W - MARGIN), Mm(self.y)),
                    bezier: false,
                },
            ],
            is_closed: false,
        };
        page.ops.push(Op::DrawLine { line });
        self.skip(5.0);
    }

    /// Save the document to a file.
    pub fn save(self, path: &str) -> Result<()> {
        let mut warnings = Vec::new();
        let bytes = self.doc.save(&PdfSaveOptions::default(), &mut warnings);
        std::fs::write(path, bytes)
            .with_context(|| format!("Failed to create PDF file: {}", path))?;
        Ok(())
    }
}
