# Cloud DLP Gateway

A backend security tool that scans uploaded files — text, images, or PDFs — for sensitive data and automatically redacts it before the content goes anywhere further.

## Why this exists

Most real-world data leaks come from human error — an employee uploads the wrong file, or a screenshot containing an email ends up somewhere it shouldn't. This project is a scaled-down version of the same detection concept used by real DLP tools like Microsoft Purview, built to understand how that detection actually works under the hood.

## What it detects

- Email addresses
- Phone numbers (including international formats)
- Credit card numbers
- US Social Security Numbers
- Leaked API secret keys (e.g. Stripe-style `sk_live_...` tokens)
- Custom internal asset/key IDs (e.g. `CORP-ID-12345`)
- Internal account/reference IDs (e.g. `ACC-NUM-4029-8812`)

## How it works

1. A file is uploaded (`.txt`, `.png`, `.jpg`, or `.pdf`)
2. Text is extracted — directly for plain text, via OCR (Tesseract) for images, via `pdfplumber` for PDFs
3. The extracted text is scanned using Microsoft Presidio (NLP-based entity recognition) plus custom regex-based recognizers
4. Matches are redacted and the cleaned text is returned as JSON, alongside a summary of what was found

## Architecture

- `main.py` — FastAPI app, file upload handling, routing by file type
- `scanner.py` — Presidio analyzer/anonymizer setup and custom recognizers
- `extractors.py` — OCR and PDF text extraction
- `static/index.html` — front-end scan console

## Tech stack

FastAPI, Microsoft Presidio, spaCy, Tesseract OCR, pdfplumber

## Live demo

[link once deployed]

## Known limitations

- No authentication yet — anyone with the link can use it
- Custom ID patterns are structural guesses, not validated against real internal formats
- PDF text extraction covers the document's text layer only — images embedded inside a PDF page are not separately OCR'd (only standalone image uploads go through OCR)
- Free-tier hosting may take 30–50 seconds to wake up after inactivity
