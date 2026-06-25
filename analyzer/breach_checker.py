"""Have I Been Pwned API integration module.

Implements k-anonymity approach to check if passwords have appeared in data breaches.
Only the first 5 characters of SHA-1 hash are sent to HIBP API.
"""

import hashlib
import requests
from typing import Tuple


class BreachChecker:
    """Checks passwords against Have I Been Pwned database using k-anonymity."""

    HIBP_API_URL = "https://api.pwnedpasswords.com/range/"
    REQUEST_TIMEOUT = 5
    USER_AGENT = {
        "User-Agent": "PasswordStrengthAnalyzer/1.0 (CYB333_Project)"
    }

    def __init__(self, use_api: bool = True):
        """Initialize breach checker.

        Args:
            use_api: Whether to use actual HIBP API (default: True)
        """
        self.use_api = use_api
        self.cache = {}

    def check_breach(self, password: str) -> Tuple[bool, int]:
        """Check if password has been found in data breaches.

        Uses k-anonymity: only SHA-1 prefix (first 5 chars) is sent to HIBP.
        Full password hash is never transmitted or revealed.

        Args:
            password: The password to check

        Returns:
            Tuple of (is_breached, occurrence_count)
            - is_breached: True if password found in breach database
            - occurrence_count: Number of times password appears in breaches (0 if not found)
        """
        if not self.use_api:
            return False, 0

        try:
            # Calculate SHA-1 hash
            password_hash = hashlib.sha1(password.encode()).hexdigest().upper()

            # Get hash prefix (first 5 characters)
            hash_prefix = password_hash[:5]
            hash_suffix = password_hash[5:]

            # Check cache first
            if hash_prefix in self.cache:
                return self._check_suffix_in_response(
                    hash_suffix, self.cache[hash_prefix]
                )

            # Query HIBP API with prefix
            response = self._query_hibp_api(hash_prefix)
            if response is None:
                return False, 0

            # Cache the response
            self.cache[hash_prefix] = response

            # Check if our suffix is in the response
            return self._check_suffix_in_response(hash_suffix, response)

        except Exception as e:
            print(f"Error checking breach database: {e}")
            return False, 0

    def _query_hibp_api(self, hash_prefix: str) -> str:
        """Query HIBP API with hash prefix.

        Args:
            hash_prefix: First 5 characters of SHA-1 hash

        Returns:
            Response text containing hash suffixes and counts, or None on error
        """
        try:
            url = f"{self.HIBP_API_URL}{hash_prefix}"
            response = requests.get(
                url, headers=self.USER_AGENT, timeout=self.REQUEST_TIMEOUT
            )
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            print(f"HIBP API request failed: {e}")
            return None

    def _check_suffix_in_response(self, hash_suffix: str, response_text: str) -> Tuple[bool, int]:
        """Check if hash suffix appears in HIBP response.

        Response format:
        SUFFIX:COUNT
        SUFFIX:COUNT
        ...

        Args:
            hash_suffix: Remaining hash characters (after first 5)
            response_text: Response from HIBP API

        Returns:
            Tuple of (is_found, occurrence_count)
        """
        lines = response_text.split("\r\n")
        for line in lines:
            if ":" in line:
                suffix, count = line.split(":")
                if suffix == hash_suffix:
                    return True, int(count)
        return False, 0

    def get_cache_status(self) -> dict:
        """Get status of cached API responses.

        Returns:
            Dictionary with cache statistics
        """
        return {"cached_prefixes": len(self.cache),
                "cache_entries": sum(len(v.split("\r\n")) for v in self.cache.values())}
