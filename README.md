# Password Strength Analyzer

A Python command-line tool that evaluates password strength, detects common weaknesses, and provides actionable recommendations for improvement.

## Project Overview

The Password Strength Analyzer automates password security validation by scoring passwords on multiple factors and checking against known breaches. This addresses a critical security gap: weak passwords remain a leading cause of account compromise, yet manual validation doesn't scale beyond a handful of accounts.

### Key Features

- **Comprehensive Scoring System**
  - Length assessment
  - Character composition (uppercase, lowercase, numbers, symbols)
  - Entropy calculation (mathematical predictability estimate)
  
- **Security Database Integration**
  - Checks against common weak password lists
  - Integrates with Have I Been Pwned (HIBP) API using k-anonymity
  - Detects dictionary words and keyboard patterns (e.g., "qwerty")
  - Identifies common substitutions (e.g., "p@ssw0rd")
  
- **Batch Processing**
  - Process multiple passwords from CSV files
  - Apply consistent validation rules across all passwords
  
- **Configuration Management**
  - Customizable admin settings
  - Define minimum password requirements
  - Enforce organization-specific rules
  
- **Detailed Reporting**
  - Strength rating with score breakdown
  - Specific, actionable recommendations
  - Vulnerability explanations

## Security Rationale

Weak passwords are consistently among the top vectors for account compromise. Automating password strength validation ensures:
- **Consistency**: The same rules apply every time
- **Scale**: Rules enforce across all accounts automatically
- **Early Detection**: Compromised passwords are caught before exploitation
- **Privacy**: K-anonymity ensures full passwords are never transmitted to external services

This approach mirrors the password validation built into modern login systems.

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package manager)

### Setup

1. Clone the repository:
```bash
git clone https://github.com/Coshea23/CYB333.git
cd CYB333
```

2. Create a virtual environment (recommended):
```bash
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Command-Line Mode

Analyze a single password:

```bash
python password_analyzer.py "your_password_here"
```

Example output:
```
Password Strength Analysis
==========================
Password Score: 72/100
Strength Rating: STRONG

Vulnerability Analysis:
✓ Length: 12 characters (Good)
✓ Uppercase: Present (A-Z)
✓ Lowercase: Present (a-z)
✓ Numbers: Present (0-9)
✓ Symbols: Present (!@#$%...)
✓ Not in breach database
✓ No dictionary words detected

Recommendations:
- Consider adding more symbols for maximum entropy
- Avoid sequential keyboard patterns
```

### Batch Mode

Process multiple passwords from a CSV file:

```bash
python password_analyzer.py --batch passwords.csv --output report.csv
```

Input CSV format (passwords.csv):
```
password_id,password
user1,MyP@ssw0rd123
user2,password123
user3,Tr0pic@lThunder!2024
```

Output includes scores, ratings, and recommendations for each password.

### Using Configuration Files

Apply organization-specific rules:

```bash
python password_analyzer.py "password" --config admin_settings.json
```

Example admin_settings.json:
```json
{
  "min_length": 12,
  "require_uppercase": true,
  "require_lowercase": true,
  "require_numbers": true,
  "require_symbols": true,
  "check_breach_database": true,
  "entropy_threshold": 50
}
```

## Configuration

### Admin Settings (admin_settings.json)

Define minimum password requirements for your organization:

```json
{
  "min_length": 12,
  "max_length": 128,
  "require_uppercase": true,
  "require_lowercase": true,
  "require_numbers": true,
  "require_symbols": true,
  "check_breach_database": true,
  "check_dictionary_words": true,
  "check_patterns": true,
  "entropy_threshold": 50,
  "common_patterns": ["qwerty", "password", "admin", "123456"],
  "custom_weak_passwords": []
}
```

## Architecture

### Core Components

- **password_analyzer.py**: Main entry point with CLI argument parsing
- **analyzer/scorer.py**: Password strength scoring logic
- **analyzer/breach_checker.py**: Have I Been Pwned API integration (k-anonymity)
- **analyzer/pattern_detector.py**: Dictionary words and keyboard pattern detection
- **analyzer/config_manager.py**: Configuration file handling
- **analyzer/batch_processor.py**: CSV batch processing
- **tests/test_scorer.py**: Unit tests for scoring logic
- **requirements.txt**: Python dependencies

### Scoring Methodology

**Final Score = Base Score + Character Bonus - Penalty Points**

1. **Base Score** (0-30 points)
   - Length: 0-30 points (1 point per character, max 30)

2. **Character Bonus** (0-40 points)
   - Uppercase letters: 0-10 points
   - Lowercase letters: 0-10 points
   - Numbers: 0-10 points
   - Symbols: 0-10 points

3. **Entropy Bonus** (0-20 points)
   - Based on Shannon entropy calculation
   - Measures predictability

4. **Penalties** (-5 to -30 points)
   - Dictionary words: -10 points
   - Keyboard patterns: -10 points
   - Common substitutions: -5 points
   - Found in breach database: -30 points

**Rating Scale:**
- 80-100: Very Strong
- 60-79: Strong
- 40-59: Moderate
- 20-39: Weak
- 0-19: Very Weak

## Dependencies

- `requests`: HTTP library for HIBP API calls
- `python-dotenv`: Environment variable management
- `pytest`: Testing framework
- See `requirements.txt` for complete list

## Privacy & Security Notes

### Have I Been Pwned Integration

The tool uses **k-anonymity** when checking the HIBP API:
- Only the first 5 characters of the SHA-1 hash are sent
- The API returns all password hashes matching those 5 characters
- Local comparison identifies exact matches without revealing the full password
- No plain-text passwords leave your system

### Best Practices

- Never commit actual passwords to the repository
- Use environment variables for sensitive API keys
- Restrict config files with strong passwords to authorized personnel
- Regularly update the breach database list

## Testing

Run the test suite to verify scoring logic:

```bash
pytest tests/ -v
```

Tests cover:
- Scoring accuracy for various password compositions
- Entropy calculations
- Pattern detection (dictionary words, keyboard patterns)
- Configuration loading and validation
- Batch processing

## Project Scope

This project implements a realistic subset of password validation:
- Entropy scoring
- Breach database integration (HIBP)
- Pattern detection
- Batch mode processing
- Configuration management
- Unit tests
- Comprehensive documentation

## Limitations & Future Enhancements

- Currently CLI-only (GUI/web interface possible future enhancement)
- Rate limiting on HIBP API (1 request/sec when not authenticated)
- Dictionary database is finite (can be extended)
- No multi-language pattern support (extensible)

## Contributing

This is an individual academic project. For suggestions or issues, please open a GitHub issue.

## License

This project is created for educational purposes in CYB333.

## Author

Created for CYB333 Course Project - June 2026

## References

- [Have I Been Pwned API](https://haveibeenpwned.com/API/v3)
- [OWASP Password Guidelines](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [Shannon Entropy in Security](https://en.wikipedia.org/wiki/Entropy_(information_theory))
- [Keyboard Pattern Recognition](https://en.wikipedia.org/wiki/Keyboard_pattern)
