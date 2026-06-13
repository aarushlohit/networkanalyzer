from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import Optional

from vulnsync.core.scanner import ScanResult
from vulnsync.report.html import generate_html
from vulnsync.utils.log import get_logger

logger = get_logger("report.pdf")


def generate_pdf(result: ScanResult, output_path: str) -> Optional[str]:
    html_content = generate_html(result)

    try:
        import weasyprint
        pdf_bytes = weasyprint.HTML(string=html_content).write_pdf()
        Path(output_path).write_bytes(pdf_bytes)
        logger.info("PDF report saved to %s", output_path)
        return output_path
    except ImportError:
        logger.warning("weasyprint not installed — generating HTML instead of PDF")
        html_path = output_path.replace(".pdf", ".html")
        Path(html_path).write_text(html_content)
        logger.info("HTML fallback saved to %s", html_path)
        return html_path
    except Exception as e:
        logger.error("PDF generation failed: %s", e)
        html_path = output_path.replace(".pdf", ".html")
        Path(html_path).write_text(html_content)
        return html_path
