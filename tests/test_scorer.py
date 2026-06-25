"""Unit tests for password scorer module."""

import pytest
from analyzer.scorer import PasswordScorer


class TestPasswordScorer:
    """Test cases for PasswordScorer class."""

    @pytest.fixture
    def scorer(self):
        """Create scorer instance for tests."""
        return PasswordScorer()

    def test_empty_password(self, scorer):
        """Test scoring of empty password."""
        result = scorer.score("")
        assert result["score"] == 0
        assert result["rating"] == "Very Weak"

    def test_very_short_password(self, scorer):
        """Test scoring of very short password."""
        result = scorer.score("abc")
        assert result["score"] < 20
        assert result["rating"] == "Very Weak"

    def test_length_scoring(self, scorer):
        """Test length scoring component."""
        # 8 characters = 8 points
        result1 = scorer.score("abcdefgh")
        assert result1["length_score"] == 8

        # 30+ characters = 30 points max
        result2 = scorer.score("a" * 50)
        assert result2["length_score"] == 30

    def test_composition_scoring(self, scorer):
        """Test character composition scoring."""
        # Only lowercase: 10 points
        result = scorer.score("abcdefghijkl")
        assert result["composition_score"] == 10

        # Lowercase + uppercase: 20 points
        result = scorer.score("AbcDefGhIjKl")
        assert result["composition_score"] == 20

        # Lowercase + uppercase + numbers: 30 points
        result = scorer.score("AbcDefGhIjKl123")
        assert result["composition_score"] == 30

        # All types: 40 points
        result = scorer.score("AbcDefGhIjKl123!@#")
        assert result["composition_score"] == 40

    def test_entropy_scoring(self, scorer):
        """Test entropy scoring."""
        # Repeated characters have lower entropy
        result1 = scorer.score("aaaaaaaaaa")
        entropy1 = result1["entropy_score"]

        # Varied characters have higher entropy
        result2 = scorer.score("aBcDeFgHiJ")
        entropy2 = result2["entropy_score"]

        assert entropy2 > entropy1

    def test_dictionary_word_penalty(self, scorer):
        """Test penalty for dictionary words."""
        # Password without dictionary words
        result1 = scorer.score("Xyz123!@#")

        # Password with dictionary word
        result2 = scorer.score("Password123!@#")

        # Should have penalty in penalties dict
        assert "dictionary_words" in result2["penalties"]
        assert result2["penalties"]["dictionary_words"] > 0

    def test_keyboard_pattern_penalty(self, scorer):
        """Test penalty for keyboard patterns."""
        result = scorer.score("Qwerty123!@#")
        assert "keyboard_patterns" in result["penalties"]

    def test_strong_password(self, scorer):
        """Test scoring of strong password."""
        result = scorer.score("Tr0pic@lThunder!2024")
        assert result["score"] >= 60
        assert result["rating"] in ["Strong", "Very Strong"]

    def test_weak_password(self, scorer):
        """Test scoring of weak password."""
        result = scorer.score("password123")
        assert result["score"] < 60
        # Should contain recommendations
        assert len(result["recommendations"]) > 0

    def test_recommendations_generated(self, scorer):
        """Test that recommendations are generated."""
        result = scorer.score("abc")
        assert len(result["recommendations"]) > 0
        assert isinstance(result["recommendations"], list)

    def test_vulnerabilities_identified(self, scorer):
        """Test that vulnerabilities are identified."""
        result = scorer.score("abc")
        assert len(result["vulnerabilities"]) > 0
        assert isinstance(result["vulnerabilities"], list)

    def test_score_clamped_to_100(self, scorer):
        """Test that score is clamped to max 100."""
        # Create an exceptionally good password (should still be capped)
        result = scorer.score(
            "Tr0pic@lThunder!2024XyZ#$%^&*()_+-=[]{}|;:',.<>?/~`"
        )
        assert result["score"] <= 100

    def test_score_clamped_to_0(self, scorer):
        """Test that score doesn't go below 0."""
        result = scorer.score("")
        assert result["score"] >= 0

    def test_rating_assignment(self, scorer):
        """Test rating assignment for different score ranges."""
        # Very Weak (0-19)
        result1 = scorer.score("a")
        assert result1["rating"] == "Very Weak"

        # Weak (20-39) - harder to achieve, might need more content
        result2 = scorer.score("abcdef")
        assert result2["rating"] in ["Very Weak", "Weak"]

        # Strong or Very Strong
        result3 = scorer.score("Str0ng!P@ssw0rd123")
        assert result3["rating"] in ["Strong", "Very Strong"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
