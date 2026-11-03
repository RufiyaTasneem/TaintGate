from rag.retrieval import retrieve
from rag.generator import generate_answer
from taint_registry import register_untrusted


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

    # Register each retrieved passage as untrusted.
    for item in passages:
        register_untrusted(item["text"], item["source"])

    # Build context for the local language model.
    context = "\n\n".join(
        f"Source: {item['source']}\n{item['text']}"
        for item in passages
    )

    # Generate an answer using the retrieved context.
    answer = generate_answer(question, context)

    # Attach provenance only from documents retrieved for this query.
    current_sources = sorted({
        item["source"] for item in passages
    })

    for source in current_sources:
        register_untrusted(answer, source)

    return {
        "answer": answer,
        "sources": current_sources,
    }