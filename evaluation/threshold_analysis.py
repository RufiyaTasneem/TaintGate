
import json
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = PROJECT_ROOT / "evaluation" / "semantic_report.json"

# Exploratory thresholds; these do not change live gateway enforcement.
THRESHOLDS = [0.70, 0.72, 0.75, 0.80, 0.85, 0.90]


def main():
    if not REPORT_PATH.exists():
        raise FileNotFoundError(
            f"Run semantic_eval.py first. Missing report: {REPORT_PATH}"
        )

    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    cases = report.get("cases", [])

    attacks = [c for c in cases if c.get("category") == "attack"]
    benign = [c for c in cases if c.get("category") == "benign"]

    if not attacks or not benign:
        raise ValueError("Report must contain attack and benign cases.")

    if any("similarity" not in c for c in cases):
        raise ValueError("Some cases are missing similarity scores.")

    print("TAINTGATE THRESHOLD SENSITIVITY ANALYSIS")
    print("=" * 78)
    print("Source: existing semantic_report.json")
    print("No embeddings regenerated; live gateway unchanged.")
    print(f"Attack cases: {len(attacks)} | Benign cases: {len(benign)}")
    print()
    print(
        f"{'Threshold':>9} | {'TP':>3} | {'FN':>3} | {'FP':>3} | "
        f"{'TN':>3} | {'Detection':>10} | {'False positives':>15}"
    )
    print("-" * 78)

    results = []

    for threshold in THRESHOLDS:
        tp = sum(c["similarity"] >= threshold for c in attacks)
        fn = len(attacks) - tp
        fp = sum(c["similarity"] >= threshold for c in benign)
        tn = len(benign) - fp

        detection_rate = tp / len(attacks) * 100
        false_positive_rate = fp / len(benign) * 100

        result = {
            "threshold": threshold,
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "true_negatives": tn,
            "attack_detection_rate_percent": round(detection_rate, 2),
            "false_positive_rate_percent": round(false_positive_rate, 2),
        }
        results.append(result)

        print(
            f"{threshold:9.2f} | {tp:3} | {fn:3} | {fp:3} | {tn:3} | "
            f"{detection_rate:9.2f}% | {false_positive_rate:14.2f}%"
        )

    output_path = PROJECT_ROOT / "evaluation" / "threshold_report.json"
    output = {
        "project": "TaintGate",
        "evaluation_type": "exploratory_threshold_sensitivity",
        "source_report": "semantic_report.json",
        "dataset": {
            "attack_cases": len(attacks),
            "benign_cases": len(benign),
        },
        "thresholds": results,
        "limitations": [
            "Small, manually written dataset.",
            "Thresholds are exploratory and not validated on an independent dataset.",
            "Embedding similarity does not establish malicious intent.",
            "This analysis does not change live gateway enforcement.",
        ],
    }

    output_path.write_text(
        json.dumps(output, indent=2),
        encoding="utf-8",
    )
    print(f"\nDetailed results saved to: {output_path}")


if __name__ == "__main__":
    main()
