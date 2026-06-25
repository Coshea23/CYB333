"""Unit tests for config manager module."""

import pytest
import json
from pathlib import Path
from analyzer.config_manager import ConfigManager


class TestConfigManager:
    """Test cases for ConfigManager class."""

    @pytest.fixture
    def config_manager(self):
        """Create config manager instance for tests."""
        return ConfigManager()

    @pytest.fixture
    def temp_config_file(self, tmp_path):
        """Create a temporary config file for testing."""
        config = {
            "min_length": 14,
            "require_uppercase": True,
            "require_lowercase": True,
            "require_numbers": True,
            "require_symbols": True,
        }
        config_file = tmp_path / "test_config.json"
        with open(config_file, "w") as f:
            json.dump(config, f)
        return str(config_file)

    def test_default_config(self, config_manager):
        """Test that default config is loaded."""
        assert config_manager.get("min_length") == 12
        assert config_manager.get("require_uppercase") is True

    def test_load_config_file(self, config_manager, temp_config_file):
        """Test loading config from file."""
        result = config_manager.load_config(temp_config_file)
        assert result is True
        assert config_manager.get("min_length") == 14

    def test_load_nonexistent_file(self, config_manager):
        """Test loading nonexistent config file."""
        result = config_manager.load_config("/nonexistent/path/config.json")
        assert result is False

    def test_save_config(self, config_manager, tmp_path):
        """Test saving config to file."""
        config_file = tmp_path / "saved_config.json"
        config_manager.set("min_length", 16)
        result = config_manager.save_config(str(config_file))
        assert result is True
        assert config_file.exists()

    def test_validate_password_length(self, config_manager):
        """Test password validation for length."""
        config_manager.set("min_length", 12)
        is_valid, violations = config_manager.validate_password("Short1!")
        assert is_valid is False
        assert len(violations) > 0

    def test_validate_password_uppercase(self, config_manager):
        """Test password validation for uppercase."""
        config_manager.set("require_uppercase", True)
        is_valid, violations = config_manager.validate_password(
            "alllowercase123!"
        )
        assert is_valid is False
        assert any("uppercase" in v.lower() for v in violations)

    def test_validate_strong_password(self, config_manager):
        """Test validation of strong password."""
        is_valid, violations = config_manager.validate_password(
            "Str0ng!P@ssw0rd123"
        )
        assert is_valid is True
        assert len(violations) == 0

    def test_get_and_set(self, config_manager):
        """Test getting and setting config values."""
        config_manager.set("test_key", "test_value")
        value = config_manager.get("test_key")
        assert value == "test_value"

    def test_get_with_default(self, config_manager):
        """Test getting config with default value."""
        value = config_manager.get("nonexistent_key", "default_value")
        assert value == "default_value"

    def test_reset_to_defaults(self, config_manager):
        """Test resetting config to defaults."""
        config_manager.set("min_length", 999)
        config_manager.reset_to_defaults()
        assert config_manager.get("min_length") == 12


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
