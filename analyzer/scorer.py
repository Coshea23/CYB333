"""Password strength scoring module.

Calculates password strength based on:
- Length
- Character composition (uppercase, lowercase, numbers, symbols)
- Entropy (Shannon entropy)
- Penalties for patterns and weaknesses
"""

import math
import re


class PasswordScorer:
    """Scores password strength on a 0-100 scale."""

    # Scoring constants
    MAX_LENGTH_POINTS = 30
    MAX_COMPOSITION_POINTS = 40
    MAX_ENTROPY_POINTS = 20
    MAX_TOTAL_POINTS = 100

    # Penalty constants
    DICTIONARY_WORD_PENALTY = 10
    KEYBOARD_PATTERN_PENALTY = 10
    COMMON_SUBSTITUTION_PENALTY = 5
    BREACH_PENALTY = 30

    # Rating thresholds
    RATINGS = {
        (80, 100): "Very Strong",
        (60, 79): "Strong",
        (40, 59): "Moderate",
        (20, 39): "Weak",
        (0, 19): "Very Weak",
    }

    def __init__(self):
        """Initialize the password scorer."""
        self.common_substitutions = {
            "@": "a",
            "0": "o",
            "1": "i",
            "3": "e",
            "4": "a",
            "5": "s",
            "7": "t",
            "$": "s",
        }

    def score(self, password: str) -> dict:
        """Calculate comprehensive password strength score.

        Args:
            password: The password to score

        Returns:
            Dictionary containing score breakdown and recommendations
        """
        if not password:
            return self._create_result(
                score=0,
                rating="Very Weak",
                vulnerabilities=["Password cannot be empty"],
                recommendations=["Enter a password"],
            )

        # Calculate component scores
        length_score = self._score_length(password)
        composition_score = self._score_composition(password)
        entropy_score = self._score_entropy(password)

        # Calculate penalties
        penalties = self._calculate_penalties(password)

        # Calculate final score
        total_score = length_score + composition_score + entropy_score - sum(
            penalties.values()
        )
        final_score = max(0, min(100, total_score))  # Clamp between 0-100

        # Determine rating
        rating = self._get_rating(final_score)

        # Get vulnerabilities and recommendations
        vulnerabilities = self._get_vulnerabilities(
            password, penalties, composition_score, entropy_score
        )
        recommendations = self._get_recommendations(
            password, vulnerabilities, penalties
        )

        return self._create_result(
            score=final_score,
            rating=rating,
            length_score=length_score,
            composition_score=composition_score,
            entropy_score=entropy_score,
            penalties=penalties,
            vulnerabilities=vulnerabilities,
            recommendations=recommendations,
        )

    def _score_length(self, password: str) -> int:
        """Score based on password length.

        1 point per character, max 30 points.

        Args:
            password: The password to evaluate

        Returns:
            Length score (0-30)
        """
        length = len(password)
        return min(length, self.MAX_LENGTH_POINTS)

    def _score_composition(self, password: str) -> int:
        """Score based on character composition.

        Up to 10 points each for:
        - Uppercase letters
        - Lowercase letters
        - Numbers
        - Symbols

        Args:
            password: The password to evaluate

        Returns:
            Composition score (0-40)
        """
        score = 0
        has_uppercase = bool(re.search(r"[A-Z]", password))
        has_lowercase = bool(re.search(r"[a-z]", password))
        has_numbers = bool(re.search(r"[0-9]", password))
        has_symbols = bool(re.search(r"[!@#$%^&*()_+\-=\[\]{};:'\",.<>?/\\|`~]", password))

        if has_uppercase:
            score += 10
        if has_lowercase:
            score += 10
        if has_numbers:
            score += 10
        if has_symbols:
            score += 10

        return score

    def _score_entropy(self, password: str) -> int:
        """Calculate Shannon entropy and convert to score.

        Entropy = -sum(p_i * log2(p_i)) for each character frequency.
        Max entropy score: 20 points.

        Args:
            password: The password to evaluate

        Returns:
            Entropy score (0-20)
        """
        if not password:
            return 0

        # Calculate character frequencies
        char_counts = {}
        for char in password:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Calculate entropy
        entropy = 0
        length = len(password)
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        # Convert entropy to 0-20 point scale
        # Max entropy for 100-character ASCII is ~6.6 bits
        max_entropy = 6.6
        entropy_score = min(20, (entropy / max_entropy) * 20)

        return int(entropy_score)

    def _calculate_penalties(self, password: str) -> dict:
        """Calculate penalties for common weaknesses.

        Args:
            password: The password to evaluate

        Returns:
            Dictionary of penalties by type
        """
        penalties = {}

        # Check for dictionary words (simplified - lowercase words)
        if self._contains_common_words(password):
            penalties["dictionary_words"] = self.DICTIONARY_WORD_PENALTY

        # Check for keyboard patterns
        if self._contains_keyboard_pattern(password):
            penalties["keyboard_patterns"] = self.KEYBOARD_PATTERN_PENALTY

        # Check for common substitutions
        if self._contains_substitution_pattern(password):
            penalties["substitutions"] = self.COMMON_SUBSTITUTION_PENALTY

        return penalties

    def _contains_common_words(self, password: str) -> bool:
        """Check if password contains common dictionary words.

        Args:
            password: The password to check

        Returns:
            True if common words detected
        """
        common_words = [
            "password",
            "admin",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
            "master",
            "sunshine",
            "princess",
            "qwerty",
        ]
        password_lower = password.lower()
        return any(word in password_lower for word in common_words)

    def _contains_keyboard_pattern(self, password: str) -> bool:
        """Detect keyboard walk patterns.

        Common patterns: qwerty, asdfgh, zxcvbn, etc.

        Args:
            password: The password to check

        Returns:
            True if keyboard pattern detected
        """
        keyboard_patterns = [
            "qwerty",
            "asdfgh",
            "zxcvbn",
            "123456",
            "qwertz",
            "azerty",
        ]
        password_lower = password.lower()
        return any(pattern in password_lower for pattern in keyboard_patterns)

    def _contains_substitution_pattern(self, password: str) -> bool:
        """Detect common character substitutions.

        Examples: p@ssw0rd, p@ssword, passw0rd, etc.

        Args:
            password: The password to check

        Returns:
            True if substitution patterns detected
        """
        # Create substituted versions of common words
        common_bases = ["password", "pass", "admin", "welcome", "letmein"]

        for base in common_bases:
            # Check if password contains base with substitutions
            pattern = self._create_substitution_variants(base)
            for variant in pattern:
                if variant in password.lower():
                    return True
        return False

    def _create_substitution_variants(self, text: str) -> list:
        """Generate common substitution variants of text.

        Args:
            text: Base text to generate variants from

        Returns:
            List of common substitution patterns
        """
        variants = [text]  # Include original
        # Common substitutions
        variants.append(text.replace("a", "@"))
        variants.append(text.replace("o", "0"))
        variants.append(text.replace("i", "1"))
        variants.append(text.replace("e", "3"))
        variants.append(text.replace("s", "5"))
        variants.append(text.replace("s", "$"))
        return variants

    def _get_vulnerabilities(
        self, password: str, penalties: dict, composition_score: int, entropy_score: int
    ) -> list:
        """Identify specific password vulnerabilities.

        Args:
            password: The password to analyze
            penalties: Dictionary of detected penalties
            composition_score: Character composition score
            entropy_score: Entropy score

        Returns:
            List of vulnerability descriptions
        """
        vulnerabilities = []

        # Length check
        if len(password) < 8:
            vulnerabilities.append("Length: Too short (less than 8 characters)")
        elif len(password) < 12:
            vulnerabilities.append("Length: Could be longer (less than 12 characters)")

        # Composition checks
        if not re.search(r"[A-Z]", password):
            vulnerabilities.append("Uppercase: No uppercase letters found")
        if not re.search(r"[a-z]", password):
            vulnerabilities.append("Lowercase: No lowercase letters found")
        if not re.search(r"[0-9]", password):
            vulnerabilities.append("Numbers: No numbers found")
        if not re.search(
            r"[!@#$%^&*()_+\-=\[\]{};:'\",.<>?/\\|`~]", password
        ):
            vulnerabilities.append("Symbols: No special symbols found")

        # Pattern violations
        if "dictionary_words" in penalties:
            vulnerabilities.append(
                "Pattern: Contains common dictionary words or names"
            )
        if "keyboard_patterns" in penalties:
            vulnerabilities.append("Pattern: Contains keyboard walk sequences")
        if "substitutions" in penalties:
            vulnerabilities.append(
                "Pattern: Contains common character substitutions (p@ssw0rd)"
            )

        # Entropy check
        if entropy_score < 10:
            vulnerabilities.append("Entropy: Low predictability resistance")

        return vulnerabilities if vulnerabilities else ["No vulnerabilities detected"]

    def _get_recommendations(
        self, password: str, vulnerabilities: list, penalties: dict
    ) -> list:
        """Generate specific improvement recommendations.

        Args:
            password: The password to analyze
            vulnerabilities: List of detected vulnerabilities
            penalties: Dictionary of detected penalties

        Returns:
            List of actionable recommendations
        """
        recommendations = []

        if len(password) < 12:
            recommendations.append("Increase length to at least 12 characters")

        if not re.search(r"[A-Z]", password):
            recommendations.append("Add uppercase letters (A-Z)")

        if not re.search(r"[a-z]", password):
            recommendations.append("Add lowercase letters (a-z)")

        if not re.search(r"[0-9]", password):
            recommendations.append("Add numbers (0-9)")

        if not re.search(
            r"[!@#$%^&*()_+\-=\[\]{};:'\",.<>?/\\|`~]", password
        ):
            recommendations.append("Add special symbols (!@#$%^&*)")

        if "dictionary_words" in penalties:
            recommendations.append(
                "Avoid common words, names, or dictionary terms"
            )

        if "keyboard_patterns" in penalties:
            recommendations.append("Avoid keyboard patterns like QWERTY or 123456")

        if "substitutions" in penalties:
            recommendations.append(
                "Avoid obvious character substitutions like @ for A or 0 for O"
            )

        if len(password) < 16:
            recommendations.append(
                "Consider making password longer (16+ characters) for better security"
            )

        if not recommendations:
            recommendations.append(
                "Password is strong! Maintain this level of security."
            )

        return recommendations

    def _get_rating(self, score: int) -> str:
        """Get rating description based on score.

        Args:
            score: Numeric score (0-100)

        Returns:
            Rating string
        """
        for (min_score, max_score), rating in self.RATINGS.items():
            if min_score <= score <= max_score:
                return rating
        return "Unknown"

    def _create_result(self, **kwargs) -> dict:
        """Create standardized result dictionary.

        Args:
            **kwargs: Result fields

        Returns:
            Standardized result dictionary
        """
        return {
            "score": kwargs.get("score", 0),
            "rating": kwargs.get("rating", "Unknown"),
            "length_score": kwargs.get("length_score", 0),
            "composition_score": kwargs.get("composition_score", 0),
            "entropy_score": kwargs.get("entropy_score", 0),
            "penalties": kwargs.get("penalties", {}),
            "vulnerabilities": kwargs.get("vulnerabilities", []),
            "recommendations": kwargs.get("recommendations", []),
        }
