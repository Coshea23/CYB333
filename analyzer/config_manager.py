"""Configuration management module.

Handles loading and validation of admin settings from JSON files.
"""

import json
from pathlib import Path
from typing import Dict, Any


class ConfigManager:
    """Manages configuration files for password policy."""

    # Default configuration
    DEFAULT_CONFIG = {
        "min_length": 12,
        "max_length": 128,
        "require_uppercase": True,
        "require_lowercase": True,
        "require_numbers": True,
        "require_symbols": True,
        "check_breach_database": True,
        "check_dictionary_words": True,
        "check_patterns": True,
        "entropy_threshold": 50,
        "common_patterns": [
            "qwerty",
            "asdfgh",
            "zxcvbn",
            "123456",
            "password",
            "admin",
        ],
        "custom_weak_passwords": [],
    }

    def __init__(self, config_file: str = None):
        """Initialize configuration manager.

        Args:
            config_file: Path to configuration JSON file (optional)
        """
        self.config = self.DEFAULT_CONFIG.copy()
        if config_file:
            self.load_config(config_file)

    def load_config(self, config_file: str) -> bool:
        """Load configuration from JSON file.

        Args:
            config_file: Path to configuration file

        Returns:
            True if successful, False otherwise
        """
        try:
            config_path = Path(config_file)
            if not config_path.exists():
                print(f"Config file not found: {config_file}")
                return False

            with open(config_path, "r") as f:
                loaded_config = json.load(f)

            # Merge with defaults, keeping any custom settings
            self.config.update(loaded_config)
            return True

        except json.JSONDecodeError as e:
            print(f"Invalid JSON in config file: {e}")
            return False
        except Exception as e:
            print(f"Error loading config file: {e}")
            return False

    def save_config(self, config_file: str) -> bool:
        """Save current configuration to JSON file.

        Args:
            config_file: Path to save configuration to

        Returns:
            True if successful, False otherwise
        """
        try:
            config_path = Path(config_file)
            # Create parent directories if needed
            config_path.parent.mkdir(parents=True, exist_ok=True)

            with open(config_path, "w") as f:
                json.dump(self.config, f, indent=2)
            return True

        except Exception as e:
            print(f"Error saving config file: {e}")
            return False

    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value.

        Args:
            key: Configuration key
            default: Default value if key not found

        Returns:
            Configuration value or default
        """
        return self.config.get(key, default)

    def set(self, key: str, value: Any) -> None:
        """Set configuration value.

        Args:
            key: Configuration key
            value: Value to set
        """
        self.config[key] = value

    def validate_password(self, password: str) -> tuple:
        """Validate password against configuration requirements.

        Args:
            password: Password to validate

        Returns:
            Tuple of (is_valid, violations)
        """
        violations = []

        # Length check
        if len(password) < self.config["min_length"]:
            violations.append(
                f"Password must be at least {self.config['min_length']} characters"
            )
        if len(password) > self.config["max_length"]:
            violations.append(
                f"Password must not exceed {self.config['max_length']} characters"
            )

        # Composition checks
        if self.config["require_uppercase"]:
            if not any(c.isupper() for c in password):
                violations.append("Password must contain uppercase letters")

        if self.config["require_lowercase"]:
            if not any(c.islower() for c in password):
                violations.append("Password must contain lowercase letters")

        if self.config["require_numbers"]:
            if not any(c.isdigit() for c in password):
                violations.append("Password must contain numbers")

        if self.config["require_symbols"]:
            if not any(
                c in "!@#$%^&*()_+-=[]{}';:\",.<>?/\\|`~" for c in password
            ):
                violations.append("Password must contain special symbols")

        return len(violations) == 0, violations

    def get_all_config(self) -> dict:
        """Get entire configuration dictionary.

        Returns:
            Complete configuration
        """
        return self.config.copy()

    def reset_to_defaults(self) -> None:
        """Reset configuration to defaults."""
        self.config = self.DEFAULT_CONFIG.copy()
