
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

    for item in passages:
        register_untrusted(item["text"], item["source"])

    context = "\n\n".join(
        f"Source: {item['source']}\n{item['text']}"
        for item in passages
    )

    answer = generate_answer(question, context)

    return {
        "answer": answer,
        "sources": sorted({
            item["source"] for item in passages
        }),
    }
