
from rag.retrieval import retrieve
from rag.generator import generate_answer
from taint_registry import find_tainted_sources, register_untrusted

def answer_question(question: str) -> dict:
    """Retrieve passages, track their provenance, and generate an answer."""

    passages = retrieve(question, top_k=3)

    if not passages:
        return {
            "answer": (
                "I couldn't find relevant information "
                "in the local knowledge base."
            ),
            "sources": [],
        }

    for item in passages:
        register_untrusted(item["text"], item["source"])

    context = "\n\n".join(
        f"Source: {item['source']}\n{item['text']}"
        for item in passages
    )

    answer = generate_answer(question, context)
    # Preserve provenance from retrieved passages in generated output.
    source_records = find_tainted_sources(context)
    for record in source_records:
        register_untrusted(answer, record.source)
    return {
        "answer": answer,
        "sources": sorted({
            item["source"] for item in passages
        }),
    }
