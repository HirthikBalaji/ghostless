"""
subjects/simulator.py
Simulates subject population and vigilance audits.
Measures empirical detection probability:
P(detect) = 1 - (1 - q)^m
Validates that empirical detection is within +/-3% of theoretical probability across 1000+ Monte Carlo trials.
"""

import random
from typing import Dict, Any, List

def run_population_experiment(
    total_subjects: int = 500,
    falsified_counts: List[int] = [10, 30, 50, 100, 200],
    vigilance_rates: List[float] = [0.01, 0.02, 0.05],
    trials_per_cell: int = 1500
) -> Dict[str, Any]:
    print("=" * 60)
    print("RUNNING S10: POPULATION AUDIT & VIGILANCE EXPERIMENT")
    print(f"Subjects: {total_subjects}, Trials per cell: {trials_per_cell}")
    print("=" * 60)

    results = {}

    for q in vigilance_rates:
        q_key = f"q_{int(q*100)}pct"
        results[q_key] = {}
        for m in falsified_counts:
            # Theoretical formula: 1 - (1 - q)^m
            theory_p = 1.0 - ((1.0 - q) ** m)

            detected_trials = 0
            for _ in range(trials_per_cell):
                # Simulate m falsified decisions distributed across subjects
                # Each falsified decision is checked by its recipient with probability q
                detected = False
                for _ in range(m):
                    if random.random() < q:
                        detected = True
                        break
                if detected:
                    detected_trials += 1

            empirical_p = detected_trials / trials_per_cell
            diff_pct = abs(empirical_p - theory_p) * 100

            passed = diff_pct <= 3.0 # Within +/-3% requirement (AC4)
            print(f"q = {q*100:4.1f}% | m = {m:3d} | Theory: {theory_p*100:5.2f}% | Empirical: {empirical_p*100:5.2f}% | Delta: {diff_pct:4.2f}% | Pass: {passed}")

            results[q_key][f"m_{m}"] = {
                "vigilance_q": q,
                "falsified_records_m": m,
                "theory_detection_prob": round(theory_p, 4),
                "empirical_detection_prob": round(empirical_p, 4),
                "delta_percentage": round(diff_pct, 2),
                "within_3pct_margin": passed,
                "trials": trials_per_cell
            }

    return results

if __name__ == "__main__":
    run_population_experiment()
