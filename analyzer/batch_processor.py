"""Batch processing module for CSV files.

Processes multiple passwords from CSV files and generates reports.
"""

import csv
from pathlib import Path
from typing import list, dict

from analyzer.scorer import PasswordScorer
from analyzer.breach_checker import BreachChecker


class BatchProcessor:
    """Processes multiple passwords from CSV files."""

    def __init__(self, use_breach_check: bool = True):
        """Initialize batch processor.

        Args:
            use_breach_check: Whether to check HIBP API (default: True)
        """
        self.scorer = PasswordScorer()
        self.breach_checker = BreachChecker(use_api=use_breach_check)

    def process_csv(self, input_file: str, output_file: str = None) -> list:
        """Process passwords from CSV file.

        Expected CSV format:
        password_id,password
        user1,MyPassword123!
        user2,WeakPass

        Args:
            input_file: Path to input CSV file
            output_file: Path to output CSV file (optional)

        Returns:
            List of processed password analyses
        """
        results = []

        try:
            # Read input CSV
            input_path = Path(input_file)
            if not input_path.exists():
                raise FileNotFoundError(f"Input file not found: {input_file}")

            with open(input_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                if not reader.fieldnames or "password" not in reader.fieldnames:
                    raise ValueError("CSV must contain 'password' column")

                for row_num, row in enumerate(reader, start=2):
                    password = row.get("password", "")
                    password_id = row.get("password_id", f"row_{row_num}")

                    # Score password
                    analysis = self.scorer.score(password)

                    # Check breach database
                    is_breached, breach_count = self.breach_checker.check_breach(
                        password
                    )

                    # Compile result
                    result = {
                        "password_id": password_id,
                        "score": analysis["score"],
                        "rating": analysis["rating"],
                        "is_breached": is_breached,
                        "breach_count": breach_count,
                        "vulnerabilities": ";".join(analysis["vulnerabilities"]),
                        "recommendations": ";".join(analysis["recommendations"]),
                    }
                    results.append(result)

            # Write output CSV if specified
            if output_file:
                self._write_results_csv(results, output_file)

            return results

        except Exception as e:
            print(f"Error processing CSV: {e}")
            return []

    def _write_results_csv(self, results: list, output_file: str) -> bool:
        """Write analysis results to CSV file.

        Args:
            results: List of analysis results
            output_file: Path to output file

        Returns:
            True if successful
        """
        try:
            output_path = Path(output_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            if not results:
                return False

            fieldnames = results[0].keys()

            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(results)

            print(f"Results written to: {output_file}")
            return True

        except Exception as e:
            print(f"Error writing results CSV: {e}")
            return False

    def generate_summary_report(self, results: list) -> dict:
        """Generate summary statistics from batch results.

        Args:
            results: List of analysis results

        Returns:
            Summary report dictionary
        """
        if not results:
            return {}

        total = len(results)
        breached = sum(1 for r in results if r.get("is_breached", False))
        very_weak = sum(1 for r in results if r.get("rating") == "Very Weak")
        weak = sum(1 for r in results if r.get("rating") == "Weak")
        moderate = sum(1 for r in results if r.get("rating") == "Moderate")
        strong = sum(1 for r in results if r.get("rating") == "Strong")
        very_strong = sum(1 for r in results if r.get("rating") == "Very Strong")

        avg_score = sum(r.get("score", 0) for r in results) / total if total > 0 else 0

        return {
            "total_passwords": total,
            "breached_passwords": breached,
            "breached_percentage": round((breached / total * 100) if total > 0 else 0, 2),
            "average_score": round(avg_score, 2),
            "rating_distribution": {
                "Very Weak": very_weak,
                "Weak": weak,
                "Moderate": moderate,
                "Strong": strong,
                "Very Strong": very_strong,
            },
        }
