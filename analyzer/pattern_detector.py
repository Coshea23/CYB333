"""Pattern detection module for identifying common password weaknesses.

Detects:
- Dictionary words
- Keyboard patterns (qwerty, asdfgh, etc.)
- Sequential patterns (abc, 123, etc.)
- Repeated characters
- Common substitutions
"""

import re


class PatternDetector:
    """Detects common patterns in passwords."""

    def __init__(self):
        """Initialize pattern detector with common patterns."""
        self.keyboard_layouts = {
            "qwerty": "qwertyuiopasdfghjklzxcvbnm",
            "dvorak": "',.pyfgcrlaoeuidhtns;qjkxbmwvz",
            "azerty": "azertyuiopqsdfghjklmwxcvbn",
        }

        self.common_words = [
            "password",
            "pass",
            "admin",
            "letmein",
            "welcome",
            "monkey",
            "dragon",
            "master",
            "sunshine",
            "princess",
            "flower",
            "shadow",
            "michael",
            "ashley",
            "bailey",
        ]

        self.sequential_patterns = [
            "abc",
            "xyz",
            "123",
            "456",
            "789",
            "012",
            "qwerty",
            "asdfgh",
            "zxcvbn",
        ]

    def detect_all_patterns(self, password: str) -> dict:
        """Detect all patterns in password.

        Args:
            password: The password to analyze

        Returns:
            Dictionary of detected patterns
        """
        return {
            "dictionary_words": self.detect_dictionary_words(password),
            "keyboard_patterns": self.detect_keyboard_patterns(password),
            "sequential_patterns": self.detect_sequential_patterns(password),
            "repeated_characters": self.detect_repeated_characters(password),
            "substitutions": self.detect_substitutions(password),
        }

    def detect_dictionary_words(self, password: str) -> list:
        """Detect common dictionary words in password.

        Args:
            password: The password to check

        Returns:
            List of detected dictionary words
        """
        detected = []
        password_lower = password.lower()

        for word in self.common_words:
            if word in password_lower:
                detected.append(word)

        return detected

    def detect_keyboard_patterns(self, password: str) -> dict:
        """Detect keyboard walk patterns.

        Args:
            password: The password to check

        Returns:
            Dictionary with detected keyboard patterns
        """
        detected = {"layouts": {}, "raw_patterns": []}
        password_lower = password.lower()

        # Check each keyboard layout
        for layout_name, layout_chars in self.keyboard_layouts.items():
            found_patterns = self._find_sequential_in_string(
                password_lower, layout_chars, min_length=3
            )
            if found_patterns:
                detected["layouts"][layout_name] = found_patterns

        # Check for simple keyboard patterns
        simple_patterns = ["qwerty", "asdfgh", "zxcvbn", "qwertz", "azerty"]
        for pattern in simple_patterns:
            if pattern in password_lower:
                detected["raw_patterns"].append(pattern)

        return detected

    def detect_sequential_patterns(self, password: str) -> list:
        """Detect sequential character patterns (abc, 123, etc.).

        Args:
            password: The password to check

        Returns:
            List of detected sequential patterns
        """
        detected = []
        password_lower = password.lower()

        for pattern in self.sequential_patterns:
            if pattern in password_lower:
                detected.append(pattern)

        # Detect other sequential patterns (3+ characters)
        found = self._find_sequential_patterns(password_lower, min_length=3)
        detected.extend(found)

        return list(set(detected))  # Remove duplicates

    def detect_repeated_characters(self, password: str) -> dict:
        """Detect repeated character patterns.

        Args:
            password: The password to check

        Returns:
            Dictionary with repeated character information
        """
        detected = {"patterns": [], "severity": "low"}

        # Find repeated characters
        for i in range(len(password) - 1):
            if password[i] == password[i + 1]:
                # Found repeated character
                char = password[i]
                count = 1
                j = i + 1
                while j < len(password) and password[j] == char:
                    count += 1
                    j += 1

                detected["patterns"].append({"character": char, "count": count})

                # Assess severity
                if count >= 4:
                    detected["severity"] = "high"
                elif count >= 3:
                    detected["severity"] = "medium"

        return detected

    def detect_substitutions(self, password: str) -> list:
        """Detect common character substitutions.

        Args:
            password: The password to check

        Returns:
            List of detected substitution types
        """
        detected = []

        substitution_patterns = {
            "leetspeak_basic": {"@": "a", "0": "o", "1": "i", "3": "e", "5": "s", "$": "s"},
            "numbers": {"0": "o", "1": "i", "2": "z", "3": "e", "4": "a", "5": "s", "7": "t"},
            "symbols": {"@": "a", "!": "i", "$": "s", "*": "x"},
        }

        for sub_type, mappings in substitution_patterns.items():
            for char, replacement in mappings.items():
                if char in password:
                    # Check if the character appears to be a substitution
                    # by looking for words with that substitution
                    unsubstituted = password.lower()
                    for search_char, replace_char in mappings.items():
                        unsubstituted = unsubstituted.replace(
                            search_char.lower(), replace_char
                        )

                    # Check if unsubstituted version contains common words
                    for word in self.common_words:
                        if word in unsubstituted:
                            detected.append(
                                f"{sub_type}: {word} with substitutions"
                            )
                            break

        return list(set(detected))

    def _find_sequential_in_string(self, text: str, sequence: str, min_length: int = 3) -> list:
        """Find sequential occurrences from sequence in text.

        Args:
            text: Text to search
            sequence: Character sequence to search for
            min_length: Minimum length of sequence to find

        Returns:
            List of found sequences
        """
        found = []
        for i in range(len(text) - min_length + 1):
            for j in range(i + min_length, len(text) + 1):
                substring = text[i:j]
                if self._is_sequential_in_sequence(substring, sequence):
                    if len(substring) >= min_length:
                        found.append(substring)
        return list(set(found))

    def _is_sequential_in_sequence(self, text: str, sequence: str) -> bool:
        """Check if text is sequential within a sequence.

        Args:
            text: Text to check
            sequence: Character sequence reference

        Returns:
            True if text is sequential in the sequence
        """
        if len(text) < 3:
            return False

        try:
            start_index = sequence.index(text[0])
            for i, char in enumerate(text):
                if sequence[(start_index + i) % len(sequence)] != char:
                    return False
            return True
        except ValueError:
            return False

    def _find_sequential_patterns(self, text: str, min_length: int = 3) -> list:
        """Find character sequences (a-z, 0-9) in text.

        Args:
            text: Text to search
            min_length: Minimum sequence length

        Returns:
            List of found sequential patterns
        """
        found = []
        i = 0
        while i < len(text) - min_length + 1:
            # Check alphabetic sequences
            if text[i].isalpha():
                j = i
                while j < len(text) - 1 and ord(text[j + 1]) == ord(text[j]) + 1:
                    j += 1
                if j - i + 1 >= min_length:
                    found.append(text[i : j + 1])
                    i = j + 1
                    continue

            # Check numeric sequences
            if text[i].isdigit():
                j = i
                while j < len(text) - 1 and ord(text[j + 1]) == ord(text[j]) + 1:
                    j += 1
                if j - i + 1 >= min_length:
                    found.append(text[i : j + 1])
                    i = j + 1
                    continue

            i += 1

        return found
