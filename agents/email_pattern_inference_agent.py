"""
Email Pattern Inference Agent for targeted email enumeration.

This agent generates likely email address combinations based on usernames,
names, and domain patterns. It validates domains using DNS/MX lookups and
produces structured output for security testing scenarios.

OFFENSIVE SECURITY USE CASES:
    - Phishing campaign target identification
    - Credential stuffing attack preparation
    - Social engineering reconnaissance
    - Password spraying target list generation
    - Spear-phishing email discovery

LEGAL NOTICE: This tool is for authorized security testing only.
Unauthorized use against systems you don't own is illegal.
"""

import asyncio
import dns.resolver
import dns.exception
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import re


@dataclass
class EmailPattern:
    """
    Represents a generated email pattern.

    Attributes:
        email: Generated email address
        pattern: Pattern used (e.g., "firstname.lastname@domain")
        confidence: Confidence score (0.0-1.0)
        source: Source of the pattern (inferred, common, etc.)
        notes: Additional information
    """

    email: str
    pattern: str
    confidence: float
    source: str
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class DomainValidation:
    """
    Domain validation results.

    Attributes:
        domain: Domain name
        is_valid: Whether domain has valid DNS records
        has_mx: Whether domain has MX records
        mx_records: List of MX records
        smtp_servers: List of SMTP server hostnames
        validation_time: Timestamp of validation
        error: Error message if validation failed
    """

    domain: str
    is_valid: bool
    has_mx: bool
    mx_records: List[str]
    smtp_servers: List[str]
    validation_time: str
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class EmailPatternInferenceAgent:
    """
    Email pattern inference agent for targeted enumeration.

    This agent generates probable email addresses for security testing
    by analyzing naming patterns and validating email domains.

    ATTACK RELEVANCE:
        - Generates email lists for credential stuffing
        - Identifies targets for spear-phishing campaigns
        - Assists in password spraying preparation
        - Enables targeted social engineering attacks

    Pattern Types Generated:
        - firstname.lastname@domain.com
        - f.lastname@domain.com
        - firstname_lastname@domain.com
        - firstnamelastname@domain.com
        - firstname@domain.com
        - lastname@domain.com
        - flastname@domain.com
        - firstname.l@domain.com
        - And more variations...

    Attributes:
        dns_timeout: DNS query timeout in seconds
        common_patterns: List of common email format patterns
    """

    # Common email patterns used by organizations
    # Ordered by likelihood/commonness
    COMMON_PATTERNS = [
        "{first}.{last}",  # john.doe (most common)
        "{first}{last}",  # johndoe
        "{first}_{last}",  # john_doe
        "{first}-{last}",  # john-doe
        "{first}",  # john
        "{last}",  # doe
        "{f}{last}",  # jdoe
        "{first}{l}",  # johnd
        "{f}.{last}",  # j.doe
        "{first}.{l}",  # john.d
        "{last}.{first}",  # doe.john (less common)
        "{last}{first}",  # doejohn (rare)
        "{last}.{f}",  # doe.j
        "{first}{middle_i}{last}",  # johnmdoe (with middle initial)
    ]

    # Confidence scores for different pattern sources
    CONFIDENCE_SCORES = {
        "verified": 1.0,  # Confirmed existing email
        "common": 0.8,  # Common corporate pattern
        "inferred": 0.6,  # Inferred from similar domains
        "standard": 0.5,  # Standard pattern variations
        "rare": 0.3,  # Uncommon patterns
    }

    def __init__(self, dns_timeout: int = 5):
        """
        Initialize the Email Pattern Inference Agent.

        Args:
            dns_timeout: DNS query timeout in seconds
        """
        self.dns_timeout = dns_timeout
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
        self.resolver.timeout = dns_timeout
        self.resolver.lifetime = dns_timeout

    def _sanitize_name_component(self, name: str) -> str:
        """
        Sanitize name component for email generation.

        Args:
            name: Name component to sanitize

        Returns:
            Sanitized lowercase name without special characters
        """
        # Remove special characters, keep only alphanumeric
        sanitized = re.sub(r"[^a-zA-Z0-9]", "", name)
        return sanitized.lower()

    def _parse_full_name(self, full_name: str) -> Dict[str, str]:
        """
        Parse full name into components.

        Args:
            full_name: Full name string (e.g., "John Michael Doe")

        Returns:
            Dictionary with first, middle, last name components
        """
        parts = [p.strip() for p in full_name.split() if p.strip()]

        result = {
            "first": "",
            "middle": "",
            "last": "",
            "f": "",  # First initial
            "l": "",  # Last initial
            "m": "",  # Middle initial
            "middle_i": "",  # Middle initial
        }

        if len(parts) == 1:
            result["first"] = self._sanitize_name_component(parts[0])
        elif len(parts) == 2:
            result["first"] = self._sanitize_name_component(parts[0])
            result["last"] = self._sanitize_name_component(parts[1])
        elif len(parts) >= 3:
            result["first"] = self._sanitize_name_component(parts[0])
            result["middle"] = self._sanitize_name_component(parts[1])
            result["last"] = self._sanitize_name_component(parts[-1])

        # Generate initials
        if result["first"]:
            result["f"] = result["first"][0]
        if result["last"]:
            result["l"] = result["last"][0]
        if result["middle"]:
            result["m"] = result["middle"][0]
            result["middle_i"] = result["m"]

        return result

    async def validate_domain(self, domain: str) -> DomainValidation:
        """
        Validate domain and check for MX records.

        This is CRITICAL for phishing campaigns - ensures emails
        will actually be deliverable to the target domain.

        Args:
            domain: Domain to validate

        Returns:
            DomainValidation object with DNS and MX record information
        """
        try:
            mx_records = []
            smtp_servers = []

            # Query MX records
            try:
                mx_answers = self.resolver.resolve(domain, "MX")
                has_mx = True

                for rdata in mx_answers:
                    mx_host = str(rdata.exchange).rstrip(".")
                    mx_records.append(f"{rdata.preference} {mx_host}")
                    smtp_servers.append(mx_host)

            except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                has_mx = False

            # If no MX, try A record as fallback
            if not has_mx:
                try:
                    a_answers = self.resolver.resolve(domain, "A")
                    if a_answers:
                        # Domain exists but no MX (might use A record for mail)
                        is_valid = True
                        smtp_servers = [domain]
                    else:
                        is_valid = False
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
                    is_valid = False
            else:
                is_valid = True

            return DomainValidation(
                domain=domain,
                is_valid=is_valid,
                has_mx=has_mx,
                mx_records=mx_records,
                smtp_servers=smtp_servers,
                validation_time=datetime.utcnow().isoformat(),
                error=None,
            )

        except dns.exception.Timeout:
            return DomainValidation(
                domain=domain,
                is_valid=False,
                has_mx=False,
                mx_records=[],
                smtp_servers=[],
                validation_time=datetime.utcnow().isoformat(),
                error="DNS query timeout",
            )
        except Exception as e:
            return DomainValidation(
                domain=domain,
                is_valid=False,
                has_mx=False,
                mx_records=[],
                smtp_servers=[],
                validation_time=datetime.utcnow().isoformat(),
                error=f"Validation error: {str(e)}",
            )

    def generate_email_patterns(
        self,
        name: str,
        domain: str,
        additional_patterns: Optional[List[str]] = None,
        include_rare: bool = False,
    ) -> List[EmailPattern]:
        """
        Generate email pattern variations for a name and domain.

        ATTACK USE: Generates comprehensive target lists for:
            - Password spraying (try common passwords against all emails)
            - Credential stuffing (breach data + email variations)
            - Phishing (identify valid targets for campaigns)

        Args:
            name: Full name (e.g., "John Doe" or "john.doe")
            domain: Email domain (e.g., "company.com")
            additional_patterns: Custom pattern templates
            include_rare: Include rare/uncommon patterns

        Returns:
            List of EmailPattern objects with generated addresses
        """
        # Parse name into components
        name_parts = self._parse_full_name(name)

        patterns = []
        seen_emails = set()  # Avoid duplicates

        # Use common patterns
        pattern_templates = self.COMMON_PATTERNS.copy()

        # Add custom patterns if provided
        if additional_patterns:
            pattern_templates.extend(additional_patterns)

        for template in pattern_templates:
            # Skip rare patterns if not requested
            is_rare = any(rare in template for rare in ["{last}{first}", "{last}.{f}"])
            if is_rare and not include_rare:
                continue

            try:
                # Generate email from template
                local_part = template.format(**name_parts)

                # Skip if any component is missing
                if not local_part or local_part == template:
                    continue

                email = f"{local_part}@{domain}"

                # Skip duplicates
                if email in seen_emails:
                    continue

                seen_emails.add(email)

                # Determine confidence and source
                if template in self.COMMON_PATTERNS[:5]:
                    confidence = self.CONFIDENCE_SCORES["common"]
                    source = "common"
                elif is_rare:
                    confidence = self.CONFIDENCE_SCORES["rare"]
                    source = "rare"
                else:
                    confidence = self.CONFIDENCE_SCORES["standard"]
                    source = "standard"

                patterns.append(
                    EmailPattern(
                        email=email,
                        pattern=template,
                        confidence=confidence,
                        source=source,
                        notes=None,
                    )
                )

            except KeyError:
                # Template requires components we don't have
                continue

        # Sort by confidence (highest first)
        patterns.sort(key=lambda p: p.confidence, reverse=True)

        return patterns

    def generate_username_variations(self, username: str) -> List[str]:
        """
        Generate name variations from a username.

        Useful when username might be firstname, lastname, or combination.

        Args:
            username: Username to generate variations from

        Returns:
            List of potential name variations
        """
        variations = [username]

        # Try splitting on common separators
        for sep in [".", "_", "-"]:
            if sep in username:
                parts = username.split(sep)
                if len(parts) == 2:
                    # Could be first.last or last.first
                    variations.append(f"{parts[0]} {parts[1]}")
                    variations.append(f"{parts[1]} {parts[0]}")

        # Try camelCase splitting
        if re.search(r"[a-z][A-Z]", username):
            # Split on capital letters
            parts = re.findall(r"[A-Z]?[a-z]+|[A-Z]+(?=[A-Z][a-z]|\b)", username)
            if len(parts) >= 2:
                variations.append(" ".join(parts))

        return list(set(variations))

    async def infer_email_patterns(
        self,
        identifier: str,
        domain: str,
        validate_domain: bool = True,
        include_rare: bool = False,
    ) -> Dict[str, Any]:
        """
        Main inference function - generates email patterns and validates domain.

        COMPLETE ATTACK WORKFLOW:
            1. Validate target domain (ensure deliverability)
            2. Generate all probable email formats
            3. Return ranked list for credential attacks

        Args:
            identifier: Name or username (e.g., "John Doe" or "johndoe")
            domain: Target email domain
            validate_domain: Whether to perform DNS/MX validation
            include_rare: Include uncommon patterns

        Returns:
            Structured dictionary with patterns and validation results
        """
        result = {
            "identifier": identifier,
            "domain": domain,
            "domain_validation": None,
            "patterns": [],
            "name_variations": [],
            "total_patterns": 0,
            "timestamp": datetime.utcnow().isoformat(),
        }

        # Validate domain if requested
        if validate_domain:
            domain_validation = await self.validate_domain(domain)
            result["domain_validation"] = domain_validation.to_dict()

            # If domain is invalid, note it but continue
            if not domain_validation.is_valid:
                result["warning"] = (
                    "Domain validation failed - emails may not be deliverable"
                )

        # Generate name variations
        name_variations = self.generate_username_variations(identifier)
        result["name_variations"] = name_variations

        # Generate patterns for each variation
        all_patterns = []
        seen_emails = set()

        for name_var in name_variations:
            patterns = self.generate_email_patterns(
                name_var, domain, include_rare=include_rare
            )

            # Add patterns, avoiding duplicates
            for pattern in patterns:
                if pattern.email not in seen_emails:
                    seen_emails.add(pattern.email)
                    all_patterns.append(pattern.to_dict())

        # Sort by confidence
        all_patterns.sort(key=lambda p: p["confidence"], reverse=True)

        result["patterns"] = all_patterns
        result["total_patterns"] = len(all_patterns)

        return result

    async def batch_infer_emails(
        self, identifiers: List[str], domain: str, validate_domain: bool = True
    ) -> Dict[str, Any]:
        """
        Batch process multiple identifiers for the same domain.

        ATTACK EFFICIENCY: Generate entire target lists for organizations.
        Useful for large-scale phishing or password spraying campaigns.

        Args:
            identifiers: List of names/usernames
            domain: Target domain
            validate_domain: Validate domain once

        Returns:
            Combined results for all identifiers
        """
        # Validate domain once for efficiency
        domain_validation = None
        if validate_domain:
            domain_validation = await self.validate_domain(domain)

        # Process all identifiers
        results = []
        all_unique_emails = set()

        for identifier in identifiers:
            patterns = self.generate_email_patterns(
                identifier, domain, include_rare=False
            )

            identifier_result = {
                "identifier": identifier,
                "patterns": [],
            }

            for pattern in patterns:
                if pattern.email not in all_unique_emails:
                    all_unique_emails.add(pattern.email)
                    identifier_result["patterns"].append(pattern.to_dict())

            results.append(identifier_result)

        return {
            "domain": domain,
            "domain_validation": domain_validation.to_dict()
            if domain_validation
            else None,
            "identifiers_processed": len(identifiers),
            "results": results,
            "total_unique_emails": len(all_unique_emails),
            "all_emails": sorted(list(all_unique_emails)),
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute email pattern inference based on workflow state.

        Integrates with LangGraph workflow for automated reconnaissance.

        Args:
            state: Current workflow state

        Returns:
            Updated state with email pattern data
        """
        # Extract parameters from state
        identifier = state.get("username") or state.get("target_name")
        domain = state.get("domain") or state.get("target_domain")

        if not identifier or not domain:
            raise ValueError("Both identifier and domain required in state")

        # Perform inference
        results = await self.infer_email_patterns(
            identifier,
            domain,
            validate_domain=True,
            include_rare=state.get("include_rare_patterns", False),
        )

        # Update state
        if "email_patterns" not in state:
            state["email_patterns"] = {}

        state["email_patterns"] = results

        return state
