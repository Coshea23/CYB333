#!/usr/bin/env python3
"""Password Strength Analyzer - Main entry point.

Command-line tool for evaluating password strength, detecting common patterns,
and checking against data breach databases.

Usage:
    python password_analyzer.py "MyPassword123!"
    python password_analyzer.py --batch passwords.csv --output results.csv
    python password_analyzer.py "password" --config admin_settings.json
"""

import argparse
import sys
from pathlib import Path

from analyzer.scorer import PasswordScorer
from analyzer.breach_checker import BreachChecker
from analyzer.config_manager import ConfigManager
from analyzer.batch_processor import BatchProcessor


def print_header():
    """Print application header."""
    print("\n" + "=" * 50)
    print("Password Strength Analyzer v1.0")
    print("CYB333 Final Project")
    print("=" * 50 + "\n")


def analyze_single_password(
    password: str, config_manager: ConfigManager = None, check_breach: bool = True
) -> None:
    """Analyze a single password and print results.

    Args:
        password: The password to analyze
        config_manager: Configuration manager instance
        check_breach: Whether to check HIBP API
    """
    scorer = PasswordScorer()
    breach_checker = BreachChecker(use_api=check_breach)

    # Score the password
    analysis = scorer.score(password)

    # Check breach database
    is_breached, breach_count = breach_checker.check_breach(password)

    # Print results
    print(f"\nPassword Analysis Results")
    print("-" * 50)
    print(f"Score:              {analysis['score']}/100")
    print(f"Rating:             {analysis['rating']}")
    print(f"\nScore Breakdown:")
    print(f"  Length Score:     {analysis['length_score']}/30")
    print(f"  Composition Score: {analysis['composition_score']}/40")
    print(f"  Entropy Score:    {analysis['entropy_score']}/20")

    if analysis["penalties"]:
        print(f"\nPenalties:")
        for penalty_type, penalty_value in analysis["penalties"].items():
            print(f"  {penalty_type}: -{penalty_value} points")

    print(f"\nBreach Database Check:")
    if is_breached:
        print(f"  Status: FOUND IN {breach_count} BREACHES!")
        print(f"  Action: DO NOT USE THIS PASSWORD")
    else:
        print(f"  Status: Not found in known breaches")

    print(f"\nVulnerabilities:")
    for i, vuln in enumerate(analysis["vulnerabilities"], 1):
        print(f"  {i}. {vuln}")

    print(f"\nRecommendations:")
    for i, rec in enumerate(analysis["recommendations"], 1):
        print(f"  {i}. {rec}")

    # Config validation if provided
    if config_manager:
        is_valid, violations = config_manager.validate_password(password)
        print(f"\nConfiguration Policy Check:")
        if is_valid:
            print("  ✓ Meets all policy requirements")
        else:
            print("  ✗ Policy violations:")
            for violation in violations:
                print(f"    - {violation}")

    print("\n" + "=" * 50 + "\n")


def batch_analyze(
    input_file: str, output_file: str = None, check_breach: bool = True
) -> None:
    """Process and analyze passwords from a CSV file.

    Args:
        input_file: Path to input CSV file
        output_file: Path to output CSV file (optional)
        check_breach: Whether to check HIBP API
    """
    print(f"\nProcessing batch file: {input_file}")
    print("-" * 50)

    processor = BatchProcessor(use_breach_check=check_breach)
    results = processor.process_csv(input_file, output_file)

    if not results:
        print("No results to display.")
        return

    # Print summary
    summary = processor.generate_summary_report(results)
    print(f"\nBatch Processing Summary:")
    print(f"  Total Passwords:    {summary['total_passwords']}")
    print(f"  Breached:           {summary['breached_passwords']} "
          f"({summary['breached_percentage']}%)")
    print(f"  Average Score:      {summary['average_score']}/100")

    print(f"\nRating Distribution:")
    for rating, count in summary["rating_distribution"].items():
        percentage = (count / summary["total_passwords"] * 100) if summary["total_passwords"] > 0 else 0
        print(f"  {rating:12}: {count:3} ({percentage:5.1f}%)")

    if output_file:
        print(f"\nDetailed results saved to: {output_file}")

    print("\n" + "=" * 50 + "\n")


def main():
    """Main entry point for the application."""
    parser = argparse.ArgumentParser(
        description="Password Strength Analyzer - Evaluate and improve password security",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
        "  python password_analyzer.py 'MyPassword123!'\n"
        "  python password_analyzer.py --batch passwords.csv --output results.csv\n"
        "  python password_analyzer.py 'password' --config admin_settings.json",
    )

    parser.add_argument(
        "password",
        nargs="?",
        help="Password to analyze (omit if using --batch)",
    )
    parser.add_argument(
        "--batch",
        help="Process passwords from CSV file",
    )
    parser.add_argument(
        "--output",
        help="Output file for batch results",
    )
    parser.add_argument(
        "--config",
        help="Configuration file (JSON) with policy settings",
    )
    parser.add_argument(
        "--no-breach-check",
        action="store_true",
        help="Skip Have I Been Pwned breach checking",
    )
    parser.add_argument(
        "--version",
        action="version",
        version="Password Strength Analyzer v1.0",
    )

    args = parser.parse_args()

    # Print header
    print_header()

    # Load configuration if provided
    config_manager = None
    if args.config:
        config_manager = ConfigManager(args.config)

    # Check whether to use breach checking
    check_breach = not args.no_breach_check

    # Handle batch processing
    if args.batch:
        batch_analyze(args.batch, args.output, check_breach)
        return

    # Handle single password analysis
    if args.password:
        analyze_single_password(args.password, config_manager, check_breach)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
