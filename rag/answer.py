
from rag.retrieval import retrieve
from rag.generator import generate_answer
from taint_registry import register_untrusted


def answer_question(question: str, registry=None) -> dict:
    """Retrieve passages, track provenance, and generate an answer.

    When a registry is supplied, all provenance is stored in that
    registry. Otherwise, the legacy global registry is used.
    """
    passages = retrieve(question, top_k=3)

    if not passages:
        return {
            "answer": "I couldn't find relevant information in the local knowledge base.",
            "sources": [],
        }

    register = (
        registry.register_untrusted
        if registry is not None
        else register_untrusted
    )

    # Register retrieved passages as untrusted.
    for item in passages:
        register(item["text"], item["source"])

    context = "\n\n".join(
        f"Source: {item['source']}\n{item['text']}"
        for item in passages
    )

    answer = generate_answer(question, context)

    current_sources = sorted({
        item["source"] for item in passages
    })

    # Preserve provenance only from documents retrieved for this query.
    for source in current_sources:
        register(answer, source)

    return {
        "answer": answer,
        "sources": current_sources,
    }
