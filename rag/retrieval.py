
import re
from pathlib import Path

DOCUMENTS_DIR = Path(__file__).resolve().parent.parent / "docs"


def tokenize(text: str) -> set[str]:
    """Extract simple lowercase word tokens."""
    return set(re.findall(r"\b[a-z0-9]+\b", text.lower()))


def load_chunks() -> list[dict[str, str]]:
    """Load local text documents and split them into paragraphs."""
    chunks = []

    for path in sorted(DOCUMENTS_DIR.glob("*.txt")):
        content = path.read_text(encoding="utf-8")

        for paragraph in content.split("\n\n"):
            paragraph = paragraph.strip()

            if paragraph:
                chunks.append({
                    "source": path.name,
                    "text": paragraph,
                })

    return chunks


def retrieve(query: str, top_k: int = 3) -> list[dict]:
    """Return the most relevant document paragraphs using word overlap."""
    query_tokens = tokenize(query)

    if not query_tokens:
        return []

    results = []

    for chunk in load_chunks():
        chunk_tokens = tokenize(chunk["text"])
        overlap = query_tokens & chunk_tokens

        if overlap:
            results.append({
                **chunk,
                "score": len(overlap) / len(query_tokens),
            })

    results.sort(
        key=lambda item: item["score"],
        reverse=True,
    )

    return results[:max(1, top_k)]
