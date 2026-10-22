
import json
from pathlib import Path

INPUT_PATH = Path("evaluation/prototype_report_v2.json")
OUTPUT_PATH = Path("evaluation/margin_report_v2.json")

with INPUT_PATH.open("r", encoding="utf-8") as file:
    report = json.load(file)

cases = report["cases"]
attacks = [c for c in cases if c["expected"] == "attack"]
benign = [c for c in cases if c["expected"] == "benign"]

margins = [0.00, 0.05, 0.075, 0.09, 0.10, 0.12, 0.15]
results = []

print("TAINTGATE — PROTOTYPE MARGIN ANALYSIS")
print("=" * 58)
print("Rule: attack similarity >= 0.75 AND margin >= threshold")
print("\nMargin | Attacks detected | False positives | False negatives")
print("-" * 58)

for threshold in margins:
    def flagged(case):
        return (
            case["attack_similarity"] >= 0.75
            and case["margin"] >= threshold
        )

    caught = [c for c in attacks if flagged(c)]
    false_positives = [c for c in benign if flagged(c)]
    missed = [c for c in attacks if not flagged(c)]

    result = {
        "margin_threshold": threshold,
        "attacks_detected": len(caught),
        "total_attacks": len(attacks),
        "false_positives": len(false_positives),
        "total_benign": len(benign),
        "false_negatives": len(missed),
        "missed_attack_ids": [c["id"] for c in missed],
        "false_positive_ids": [c["id"] for c in false_positives],
    }
    results.append(result)

    print(
        f"{threshold:6.3f} | "
        f"{len(caught):2}/{len(attacks):<13} | "
        f"{len(false_positives):2}/{len(benign):<13} | "
        f"{len(missed):2}/{len(attacks)}"
    )

with OUTPUT_PATH.open("w", encoding="utf-8") as file:
    json.dump({
        "rule": "attack_similarity >= 0.75 and margin >= threshold",
        "note": (
            "Exploratory analysis on a small constructed dataset. "
            "Do not use these results as production security guarantees."
        ),
        "results": results,
    }, file, indent=2)

print(f"\nDetailed report saved to: {OUTPUT_PATH.resolve()}")
