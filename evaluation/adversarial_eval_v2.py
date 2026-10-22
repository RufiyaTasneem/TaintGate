
import json
import math
import sys
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from gateway.taint import (
    TAINTED_VALUES,
    find_tainted_sources,
    register_untrusted,
)

DATASET_PATH = PROJECT_ROOT / "evaluation" / "adversarial_cases_v2.json"
REPORT_PATH = PROJECT_ROOT / "evaluation" / "adversarial_report_v2.json"

OLLAMA_URL = "http://127.0.0.1:11434/api/embed"
MODEL = "nomic-embed-text"
THRESHOLD = 0.72


def embed(texts):
    payload = json.dumps({
        "model": MODEL,
        "input": texts,
    }).encode("utf-8")

    request = urllib.request.Request(
        OLLAMA_URL,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    with urllib.request.urlopen(request, timeout=120) as response:
        result = json.loads(response.read().decode("utf-8"))

    vectors = result.get("embeddings")

    if not isinstance(vectors, list) or len(vectors) != len(texts):
        raise ValueError("Ollama returned an unexpected embedding response.")

    return vectors


def cosine_similarity(a, b):
    if len(a) != len(b):
        raise ValueError("Embedding dimensions do not match.")

    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))

    if norm_a == 0 or norm_b == 0:
        return 0.0

    return dot / (norm_a * norm_b)


def confusion_metrics(cases, prediction_key):
    tp = sum(
        c["expected"] == "attack" and c[prediction_key]
        for c in cases
    )
    fn = sum(
        c["expected"] == "attack" and not c[prediction_key]
        for c in cases
    )
    fp = sum(
        c["expected"] == "benign" and c[prediction_key]
        for c in cases
    )
    tn = sum(
        c["expected"] == "benign" and not c[prediction_key]
        for c in cases
    )

    attack_total = tp + fn
    benign_total = fp + tn

    return {
        "true_positives": tp,
        "false_negatives": fn,
        "false_positives": fp,
        "true_negatives": tn,
        "attack_detection_rate_percent": (
            round(tp / attack_total * 100, 2)
            if attack_total else None
        ),
        "false_negative_rate_percent": (
            round(fn / attack_total * 100, 2)
            if attack_total else None
        ),
        "false_positive_rate_percent": (
            round(fp / benign_total * 100, 2)
            if benign_total else None
        ),
    }


def category_metrics(cases, prediction_key):
    grouped = defaultdict(list)

    for case in cases:
        grouped[case["category"]].append(case)

    results = {}

    for category, group in sorted(grouped.items()):
        attack_count = sum(c["expected"] == "attack" for c in group)
        benign_count = sum(c["expected"] == "benign" for c in group)
        flagged = sum(bool(c[prediction_key]) for c in group)

        result = {
            "cases": len(group),
            "attacks": attack_count,
            "benign": benign_count,
            "flagged": flagged,
        }

        if attack_count:
            detected = sum(
                c["expected"] == "attack" and c[prediction_key]
                for c in group
            )
            result["attacks_detected"] = detected
            result["attack_detection_rate_percent"] = round(
                detected / attack_count * 100, 2
            )

        if benign_count:
            false_positives = sum(
                c["expected"] == "benign" and c[prediction_key]
                for c in group
            )
            result["false_positives"] = false_positives
            result["false_positive_rate_percent"] = round(
                false_positives / benign_count * 100, 2
            )

        results[category] = result

    return results


def main():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(
            f"Dataset not found: {DATASET_PATH}"
        )

    dataset = json.loads(DATASET_PATH.read_text(encoding="utf-8"))
    cases = dataset.get("cases", [])
    source = dataset.get("source_text", "")

    if not cases or not source:
        raise ValueError("Dataset must contain cases and source_text.")

    ids = [case.get("id") for case in cases]

    if len(ids) != len(set(ids)) or any(not case_id for case_id in ids):
        raise ValueError("Dataset case IDs must be present and unique.")

    if any(
        case.get("expected") not in ("attack", "benign")
        or not case.get("text")
        or not case.get("category")
        for case in cases
    ):
        raise ValueError("A case has a missing or invalid required field.")

    # Reset provenance so repeated runs are deterministic.
    TAINTED_VALUES.clear()
    register_untrusted(source, "adversarial_cases_v2.json")

    # Embed the reference attack and every case in one batch.
    vectors = embed([source] + [case["text"] for case in cases])
    source_vector = vectors[0]

    for case, vector in zip(cases, vectors[1:]):
        similarity = cosine_similarity(source_vector, vector)
        lexical_match = bool(find_tainted_sources(case["text"]))

        case["similarity"] = round(similarity, 4)
        case["lexical_flag"] = lexical_match
        case["semantic_flag"] = similarity >= THRESHOLD

    attacks = sum(c["expected"] == "attack" for c in cases)
    benign = sum(c["expected"] == "benign" for c in cases)

    report = {
        "project": "TaintGate",
        "evaluation_type": "adversarial_evaluation_v2",
        "generated_at_utc": datetime.now(timezone.utc).isoformat(),
        "dataset_version": dataset.get("dataset_version"),
        "dataset_description": dataset.get("description"),
        "model": MODEL,
        "semantic_threshold": THRESHOLD,
        "threshold_is_experimental": True,
        "dataset_summary": {
            "total_cases": len(cases),
            "attack_cases": attacks,
            "benign_cases": benign,
            "category_count": len(set(c["category"] for c in cases)),
        },
        "lexical_overall": confusion_metrics(cases, "lexical_flag"),
        "semantic_overall": confusion_metrics(cases, "semantic_flag"),
        "lexical_by_category": category_metrics(cases, "lexical_flag"),
        "semantic_by_category": category_metrics(cases, "semantic_flag"),
        "cases": cases,
        "limitations": [
            "Small, manually authored dataset; not a standardized benchmark.",
            "Expected labels are scenario-based and may not cover all contexts.",
            "Semantic similarity to one reference attack does not establish intent.",
            "Threshold results are exploratory and not independently validated.",
            "This script does not modify or authorize live gateway tool calls.",
        ],
    }

    REPORT_PATH.write_text(
        json.dumps(report, indent=2),
        encoding="utf-8",
    )

    print("TAINTGATE ADVERSARIAL EVALUATION V2")
    print("=" * 44)
    print(f"Dataset cases: {len(cases)}")
    print(f"Attacks: {attacks} | Benign: {benign}")
    print(f"Embedding model: {MODEL}")
    print(f"Experimental threshold: {THRESHOLD}")

    for name, key in (
        ("LEXICAL", "lexical_flag"),
        ("SEMANTIC", "semantic_flag"),
    ):
        metrics = confusion_metrics(cases, key)
        print(f"\n{name} RESULTS")
        print(
            f"Attack detection: "
            f"{metrics['true_positives']}/{attacks} "
            f"({metrics['attack_detection_rate_percent']}%)"
        )
        print(
            f"False negatives: {metrics['false_negatives']}/{attacks}"
        )
        print(
            f"Benign false positives: "
            f"{metrics['false_positives']}/{benign} "
            f"({metrics['false_positive_rate_percent']}%)"
        )

    print("\nRESULTS BY CATEGORY")
    for category in sorted(set(c["category"] for c in cases)):
        lexical = report["lexical_by_category"][category]
        semantic = report["semantic_by_category"][category]
        print(
            f"{category}: "
            f"lexical flagged {lexical['flagged']}/{lexical['cases']}, "
            f"semantic flagged {semantic['flagged']}/{semantic['cases']}"
        )

    print(f"\nDetailed report saved to: {REPORT_PATH}")


if __name__ == "__main__":
    main()
