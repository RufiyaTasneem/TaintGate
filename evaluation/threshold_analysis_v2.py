
import json
from pathlib import Path

REPORT_PATH = Path("evaluation/adversarial_report_v2.json")
OUTPUT_PATH = Path("evaluation/threshold_report_v2.json")

with REPORT_PATH.open("r", encoding="utf-8") as file:
    report = json.load(file)

cases = report["cases"]
attacks = [c for c in cases if c["expected"] == "attack"]
benign = [c for c in cases if c["expected"] == "benign"]

thresholds = [0.70, 0.72, 0.75, 0.78, 0.80, 0.82, 0.85, 0.88, 0.90]
results = []

print("TAINTGATE — ADVERSARIAL V2 THRESHOLD ANALYSIS")
print("=" * 58)
print(f"Cases: {len(cases)} | Attacks: {len(attacks)} | Benign: {len(benign)}")
print("\nThreshold | Attacks caught | False positives | Precision")
print("-" * 58)

for threshold in thresholds:
    caught = [
        c for c in attacks
        if c["similarity"] >= threshold
    ]
    false_positives = [
        c for c in benign
        if c["similarity"] >= threshold
    ]

    precision_denominator = len(caught) + len(false_positives)
    precision = (
        len(caught) / precision_denominator
        if precision_denominator
        else 0.0
    )

    result = {
        "threshold": threshold,
        "attacks_detected": len(caught),
        "total_attacks": len(attacks),
        "false_positives": len(false_positives),
        "total_benign": len(benign),
        "attack_recall": len(caught) / len(attacks) if attacks else 0.0,
        "false_positive_rate": (
            len(false_positives) / len(benign) if benign else 0.0
        ),
        "precision": precision,
        "missed_attack_ids": [
            c["id"] for c in attacks if c not in caught
        ],
        "false_positive_ids": [
            c["id"] for c in false_positives
        ],
    }
    results.append(result)

    print(
        f"{threshold:9.2f} | "
        f"{len(caught):2}/{len(attacks):<12} | "
        f"{len(false_positives):2}/{len(benign):<13} | "
        f"{precision:.1%}"
    )

output = {
    "dataset": str(REPORT_PATH),
    "note": (
        "Offline threshold analysis only. Similarity is not proof of "
        "malicious intent. Results are specific to this dataset."
    ),
    "results": results,
}

with OUTPUT_PATH.open("w", encoding="utf-8") as file:
    json.dump(output, file, indent=2)

print(f"\nDetailed results saved to: {OUTPUT_PATH.resolve()}")
