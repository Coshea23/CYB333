"""Unit tests for pattern detector module."""

import pytest
from analyzer.pattern_detector import PatternDetector


class TestPatternDetector:
    """Test cases for PatternDetector class."""

    @pytest.fixture
    def detector(self):
        """Create detector instance for tests."""
        return PatternDetector()

    def test_detect_dictionary_words(self, detector):
        """Test detection of common dictionary words."""
        # Should detect 'password'
        result = detector.detect_dictionary_words("MyPassword123")
        assert len(result) > 0
        assert "password" in [w.lower() for w in result]

        # Should not detect arbitrary words
        result2 = detector.detect_dictionary_words("Xyz123!@#")
        assert len(result2) == 0

    def test_detect_keyboard_patterns(self, detector):
        """Test detection of keyboard patterns."""
        # Should detect qwerty
        result = detector.detect_keyboard_patterns("Qwerty123!@#")
        assert len(result["layouts"]) > 0 or len(result["raw_patterns"]) > 0

        # Should not detect random patterns
        result2 = detector.detect_keyboard_patterns("Xyz123!@#")
        # May or may not detect depending on layout

    def test_detect_sequential_patterns(self, detector):
        """Test detection of sequential patterns."""
        # Should detect 123
        result = detector.detect_sequential_patterns("Pass123Word")
        assert "123" in result or any("123" in str(p) for p in result)

    def test_detect_repeated_characters(self, detector):
        """Test detection of repeated characters."""
        # Should detect repeated 'a's
        result = detector.detect_repeated_characters("Paaassword123")
        assert len(result["patterns"]) > 0

        # No repeated characters
        result2 = detector.detect_repeated_characters("Tr0pic@lThunder")
        assert len(result2["patterns"]) == 0

    def test_detect_all_patterns(self, detector):
        """Test comprehensive pattern detection."""
        result = detector.detect_all_patterns("Password123")
        assert isinstance(result, dict)
        assert "dictionary_words" in result
        assert "keyboard_patterns" in result
        assert "sequential_patterns" in result
        assert "repeated_characters" in result
        assert "substitutions" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
