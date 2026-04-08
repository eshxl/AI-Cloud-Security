import os
from docx import Document
import PyPDF2

# ---------- TXT READER ----------
def read_txt(file_path):
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        return f.read()


# ---------- DOCX READER ----------
def read_docx(file_path):
    doc = Document(file_path)
    text = []
    for para in doc.paragraphs:
        text.append(para.text)
    return "\n".join(text)


# ---------- PDF READER ----------
def read_pdf(file_path):
    text = ""
    with open(file_path, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        for page in reader.pages:
            text += page.extract_text() or ""
    return text


# ---------- MAIN FUNCTION ----------
def extract_text(file_path):
    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".txt":
        return read_txt(file_path)

    elif ext == ".docx":
        return read_docx(file_path)

    elif ext == ".pdf":
        return read_pdf(file_path)

    else:
        return "Unsupported file format"
