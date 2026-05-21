from __future__ import annotations

from pathlib import Path

from PyQt6.QtCore import QMarginsF
from PyQt6.QtGui import QFont, QFontDatabase, QPageLayout, QPageSize, QTextDocument
from PyQt6.QtPrintSupport import QPrinter
from PyQt6.QtWidgets import QApplication


CYRILLIC_FONT_CANDIDATES = (
    "Segoe UI",
    "Arial",
    "Noto Sans",
    "DejaVu Sans",
    "Liberation Sans",
)


def _available_font_families() -> set[str]:
    try:
        return set(QFontDatabase.families())
    except Exception:
        return set()


def _select_report_font() -> QFont:
    families = _available_font_families()
    for family in CYRILLIC_FONT_CANDIDATES:
        if family in families:
            return QFont(family, 10)

    app = QApplication.instance()
    if app is not None:
        return QFont(app.font().family(), 10)
    return QFont("Sans Serif", 10)


def write_pdf_report(html: str, output_path: Path) -> None:
    report_path = Path(output_path)
    report_path.parent.mkdir(parents=True, exist_ok=True)

    printer = QPrinter(QPrinter.PrinterMode.HighResolution)
    printer.setOutputFormat(QPrinter.OutputFormat.PdfFormat)
    printer.setOutputFileName(str(report_path))
    printer.setPageSize(QPageSize(QPageSize.PageSizeId.A4))
    printer.setPageMargins(QMarginsF(14, 14, 14, 14), QPageLayout.Unit.Millimeter)

    document = QTextDocument()
    document.setDefaultFont(_select_report_font())
    document.setHtml(html)
    document.setPageSize(printer.pageRect(QPrinter.Unit.Point).size())
    document.print(printer)
