"""
Attack Surface Prioritizer Agent for pre-attack target selection.

This agent analyzes discovered assets and their technology fingerprints to
assign exploitability scores and prioritize targets. It identifies high-value
targets based on vulnerability indicators, weak security posture, and
attack vector availability.

OFFENSIVE SECURITY USE CASES:
    - Pre-attack target prioritization
    - Resource allocation for penetration testing
    - Exploit development prioritization
    - Attack path planning and decision making
    - Identifying "low hanging fruit" vs hardened targets

ATTACK STRATEGY: Focus resources on highest-value, most exploitable targets first
"""

from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
import re


class PriorityLevel(Enum):
    """Priority levels for attack targets."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


@dataclass
class ScoringFactor:
    """
    Individual scoring factor.
    
    Attributes:
        category: Factor category (auth, tech, security, etc.)
        description: Human-readable description
        score: Points assigned (0-100)
        weight: Weight multiplier (0.0-2.0)
        reasoning: Explanation of why this score was assigned
    """
    category: str
    description: str
    score: int
    weight: float
    reasoning: str
    
    def weighted_score(self) -> float:
        """Calculate weighted score."""
        return self.score * self.weight


@dataclass
class PrioritizedAsset:
    """
    Asset with exploitability score and prioritization.
    
    Attributes:
        asset: Asset identifier (URL, domain, etc.)
        asset_type: Type of asset
        total_score: Total exploitability score (0-100)
        priority_level: Priority classification
        scoring_factors: List of factors contributing to score
        recommended_attacks: Suggested attack vectors
        risk_summary: High-level risk assessment
        metadata: Additional metadata
        ranked_position: Position in priority ranking
        timestamp: Analysis timestamp
    """
    asset: str
    asset_type: str
    total_score: float
    priority_level: PriorityLevel
    scoring_factors: List[ScoringFactor] = field(default_factory=list)
    recommended_attacks: List[str] = field(default_factory=list)
    risk_summary: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    ranked_position: Optional[int] = None
    timestamp: Optional[str] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        data = asdict(self)
        data['priority_level'] = self.priority_level.value
        data['scoring_factors'] = [
            {
                'category': f.category,
                'description': f.description,
                'score': f.score,
                'weight': f.weight,
                'weighted_score': f.weighted_score(),
                'reasoning': f.reasoning,
            }
            for f in self.scoring_factors
        ]
        return data


class AttackSurfacePrioritizerAgent:
    """
    Attack surface prioritization agent for target selection.
    
    This agent performs comprehensive exploitability analysis by:
        - Analyzing authentication mechanisms (bypass opportunities)
        - Identifying admin panels (privileged access targets)
        - Evaluating API security (injection, auth bypass)
        - Assessing legacy technology risks (known CVEs)
        - Checking WAF/security presence (defensive barriers)
        - Scoring sensitive endpoints (data exposure)
    
    ATTACK DECISION MATRIX:
        HIGH PRIORITY = High Impact + Low Difficulty
            - Admin panels without WAF
            - APIs with weak auth
            - Legacy systems with known CVEs
            - Endpoints with missing security headers
        
        MEDIUM PRIORITY = Medium Impact OR Medium Difficulty
            - Standard web apps with some security
            - Modern tech with minor misconfigurations
        
        LOW PRIORITY = Low Impact OR High Difficulty
            - Static sites
            - Well-hardened modern applications
            - Strong WAF/CDN protection
    
    Attributes:
        scoring_weights: Configurable weight multipliers for each category
    """
    
    # Scoring weights for different categories
    # Higher weight = more important for prioritization
    DEFAULT_WEIGHTS = {
        "admin_panel": 2.0,          # Admin access = critical
        "authentication": 1.8,        # Auth bypass = high value
        "api_endpoint": 1.7,          # APIs often have vulnerabilities
        "legacy_technology": 1.6,     # Old tech = known exploits
        "missing_waf": 1.5,           # No WAF = easier exploitation
        "sensitive_endpoint": 1.4,    # Data exposure targets
        "cms_vulnerabilities": 1.3,   # CMS plugins = common vulns
        "weak_security_headers": 1.2, # Missing protections
        "development_endpoint": 1.8,  # Dev/staging = weaker security
        "backup_files": 1.5,          # Exposed backups = high value
    }
    
    # High-value endpoint patterns
    # ATTACK TARGETS: These typically provide privileged access or sensitive data
    HIGH_VALUE_PATTERNS = {
        "admin": r'/(admin|administrator|manage|backend|console|dashboard|control[_-]?panel)',
        "api": r'/(api|rest|graphql|v\d+|swagger|openapi)',
        "auth": r'/(login|signin|auth|authenticate|oauth|sso|saml)',
        "dev": r'/(dev|development|staging|test|debug|demo)',
        "sensitive": r'/(config|configuration|settings|env|backup|dump|export)',
        "upload": r'/(upload|file|media|assets)',
    }
    
    # Legacy technology indicators
    # ATTACK GOLDMINE: Old versions = known CVEs
    LEGACY_INDICATORS = {
        "php5": {"score": 80, "reason": "PHP 5 is EOL - multiple known CVEs"},
        "php/5": {"score": 80, "reason": "PHP 5 is EOL - multiple known CVEs"},
        "java/1.6": {"score": 85, "reason": "Java 6 is extremely outdated - critical vulnerabilities"},
        "java/1.7": {"score": 75, "reason": "Java 7 is EOL - known vulnerabilities"},
        "apache/2.2": {"score": 70, "reason": "Apache 2.2 is EOL - security updates stopped"},
        "iis/6": {"score": 90, "reason": "IIS 6 has critical vulnerabilities"},
        "iis/7": {"score": 70, "reason": "IIS 7 is outdated - security concerns"},
        "nginx/1.0": {"score": 75, "reason": "Very old nginx version - likely vulnerable"},
        "tomcat/6": {"score": 80, "reason": "Tomcat 6 is EOL - multiple CVEs"},
        "tomcat/7": {"score": 70, "reason": "Tomcat 7 is EOL - known vulnerabilities"},
        "wordpress/3": {"score": 90, "reason": "WordPress 3.x has critical vulnerabilities"},
        "wordpress/4": {"score": 75, "reason": "WordPress 4.x is outdated - known issues"},
        "drupal/6": {"score": 95, "reason": "Drupal 6 has critical SQLi vulnerabilities"},
        "drupal/7": {"score": 85, "reason": "Drupal 7 has known vulnerabilities"},
        "jquery/1": {"score": 60, "reason": "jQuery 1.x has XSS vulnerabilities"},
    }
    
    def __init__(self, custom_weights: Optional[Dict[str, float]] = None):
        """
        Initialize the Attack Surface Prioritizer Agent.
        
        Args:
            custom_weights: Custom scoring weights (overrides defaults)
        """
        self.weights = self.DEFAULT_WEIGHTS.copy()
        if custom_weights:
            self.weights.update(custom_weights)
    
    def _score_authentication(
        self,
        asset: Dict[str, Any],
        tech_fingerprint: Optional[Dict[str, Any]] = None
    ) -> Optional[ScoringFactor]:
        """
        Score authentication-related attack surface.
        
        ATTACK PRIORITY: Auth endpoints are primary targets for:
            - Credential stuffing
            - Brute force attacks
            - Authentication bypass
            - Session hijacking
        
        Args:
            asset: Asset information
            tech_fingerprint: Technology fingerprint if available
            
        Returns:
            ScoringFactor for authentication or None
        """
        asset_url = asset.get("asset", "").lower()
        score = 0
        reasoning_parts = []
        
        # Check for auth endpoint patterns
        for pattern_name, pattern in self.HIGH_VALUE_PATTERNS.items():
            if pattern_name == "auth" and re.search(pattern, asset_url):
                score = 70
                reasoning_parts.append("Authentication endpoint detected")
                break
        
        if tech_fingerprint:
            auth_mech = tech_fingerprint.get("auth_mechanisms", {})
            
            # JWT detected = token manipulation opportunities
            if auth_mech.get("jwt"):
                score += 15
                reasoning_parts.append("JWT authentication (token manipulation possible)")
            
            # Basic auth = easy to intercept/replay
            if auth_mech.get("basic_auth"):
                score += 20
                reasoning_parts.append("Basic authentication (credential exposure risk)")
            
            # OAuth without proper validation
            if auth_mech.get("oauth"):
                score += 10
                reasoning_parts.append("OAuth implementation (misconfiguration potential)")
            
            # Session-based with predictable cookies
            if auth_mech.get("session_based"):
                score += 5
                reasoning_parts.append("Session-based authentication")
        
        if score > 0:
            return ScoringFactor(
                category="authentication",
                description="Authentication endpoint vulnerability",
                score=min(score, 100),
                weight=self.weights["authentication"],
                reasoning="; ".join(reasoning_parts)
            )
        
        return None
    
    def _score_admin_panel(self, asset: Dict[str, Any]) -> Optional[ScoringFactor]:
        """
        Score admin panel accessibility.
        
        CRITICAL TARGET: Admin panels provide:
            - Privileged access to entire application
            - Configuration control
            - User management
            - Often have default credentials
        
        Args:
            asset: Asset information
            
        Returns:
            ScoringFactor for admin panel or None
        """
        asset_url = asset.get("asset", "").lower()
        
        # Check for admin patterns
        if re.search(self.HIGH_VALUE_PATTERNS["admin"], asset_url):
            # Higher score if discovered in robots.txt (hidden but accessible)
            source = asset.get("source", "")
            if "robots" in source:
                score = 90
                reasoning = "Admin panel found in robots.txt - likely unprotected or weakly protected"
            else:
                score = 80
                reasoning = "Admin panel accessible - high-value target for privilege escalation"
            
            return ScoringFactor(
                category="admin_panel",
                description="Administrative interface detected",
                score=score,
                weight=self.weights["admin_panel"],
                reasoning=reasoning
            )
        
        return None
    
    def _score_api_endpoint(
        self,
        asset: Dict[str, Any],
        tech_fingerprint: Optional[Dict[str, Any]] = None
    ) -> Optional[ScoringFactor]:
        """
        Score API endpoint exploitability.
        
        API ATTACK VECTORS:
            - Injection attacks (SQLi, NoSQLi, command injection)
            - Broken authentication/authorization
            - Mass assignment
            - Rate limiting bypass
            - IDOR (Insecure Direct Object Reference)
        
        Args:
            asset: Asset information
            tech_fingerprint: Technology fingerprint if available
            
        Returns:
            ScoringFactor for API endpoint or None
        """
        asset_url = asset.get("asset", "").lower()
        
        # Check for API patterns
        if re.search(self.HIGH_VALUE_PATTERNS["api"], asset_url):
            score = 65
            reasoning_parts = ["API endpoint detected"]
            
            # REST APIs without versioning = potential instability
            if "/api/" in asset_url and not re.search(r'/v\d+/', asset_url):
                score += 10
                reasoning_parts.append("unversioned API")
            
            # GraphQL = specific attack vectors
            if "graphql" in asset_url:
                score += 15
                reasoning_parts.append("GraphQL endpoint (introspection, depth attacks)")
            
            # Swagger/OpenAPI documentation = complete API map
            if any(pattern in asset_url for pattern in ["swagger", "openapi", "api-docs"]):
                score += 20
                reasoning_parts.append("API documentation exposed (complete endpoint map)")
            
            # Check tech fingerprint for API-related tech
            if tech_fingerprint:
                backend = tech_fingerprint.get("backend", {})
                if backend.get("primary"):
                    tech = backend["primary"].get("technology", "")
                    if tech in ["node.js", "python"]:
                        reasoning_parts.append(f"{tech} backend (injection opportunities)")
            
            return ScoringFactor(
                category="api_endpoint",
                description="API endpoint with attack potential",
                score=min(score, 100),
                weight=self.weights["api_endpoint"],
                reasoning="; ".join(reasoning_parts)
            )
        
        return None
    
    def _score_legacy_technology(
        self,
        tech_fingerprint: Optional[Dict[str, Any]] = None
    ) -> Optional[ScoringFactor]:
        """
        Score legacy technology presence.
        
        EXPLOITATION ADVANTAGE: Legacy tech = known CVEs, exploit code available
        
        Args:
            tech_fingerprint: Technology fingerprint
            
        Returns:
            ScoringFactor for legacy technology or None
        """
        if not tech_fingerprint:
            return None
        
        # Check web server version
        web_server = tech_fingerprint.get("web_server", {})
        server_raw = web_server.get("raw", "").lower()
        
        for legacy_sig, info in self.LEGACY_INDICATORS.items():
            if legacy_sig in server_raw:
                return ScoringFactor(
                    category="legacy_technology",
                    description=f"Legacy technology: {legacy_sig}",
                    score=info["score"],
                    weight=self.weights["legacy_technology"],
                    reasoning=info["reason"]
                )
        
        # Check CMS version
        cms = tech_fingerprint.get("cms", {})
        cms_primary = cms.get("primary", {})
        if cms_primary:
            cms_name = cms_primary.get("cms", "")
            cms_version = cms_primary.get("version", "")
            
            if cms_version:
                cms_sig = f"{cms_name}/{cms_version.split('.')[0]}"
                if cms_sig in self.LEGACY_INDICATORS:
                    info = self.LEGACY_INDICATORS[cms_sig]
                    return ScoringFactor(
                        category="legacy_technology",
                        description=f"Legacy CMS: {cms_name} {cms_version}",
                        score=info["score"],
                        weight=self.weights["cms_vulnerabilities"],
                        reasoning=info["reason"]
                    )
        
        return None
    
    def _score_waf_presence(
        self,
        tech_fingerprint: Optional[Dict[str, Any]] = None
    ) -> Optional[ScoringFactor]:
        """
        Score based on WAF/security presence (or lack thereof).
        
        NO WAF = EASIER EXPLOITATION:
            - No request filtering
            - No rate limiting
            - No payload detection
            - Direct application access
        
        Args:
            tech_fingerprint: Technology fingerprint
            
        Returns:
            ScoringFactor for missing WAF or None
        """
        if not tech_fingerprint:
            return None
        
        security = tech_fingerprint.get("security", {})
        waf_cdn = security.get("waf_cdn", {})
        
        has_waf = waf_cdn.get("has_waf", False)
        has_cdn = waf_cdn.get("has_cdn", False)
        
        # No WAF and no CDN = direct access to application
        if not has_waf and not has_cdn:
            return ScoringFactor(
                category="missing_waf",
                description="No WAF or CDN protection detected",
                score=75,
                weight=self.weights["missing_waf"],
                reasoning="Direct application access - no filtering or rate limiting"
            )
        
        # Has CDN but no WAF = some protection but exploitable
        if has_cdn and not has_waf:
            return ScoringFactor(
                category="missing_waf",
                description="CDN present but no WAF",
                score=50,
                weight=self.weights["missing_waf"],
                reasoning="CDN provides caching but no application-layer protection"
            )
        
        # Has WAF = lower priority (but not impossible)
        if has_waf:
            waf_detected = waf_cdn.get("detected", [])
            waf_name = waf_detected[0]["name"] if waf_detected else "unknown"
            
            return ScoringFactor(
                category="missing_waf",
                description=f"WAF detected: {waf_name}",
                score=20,
                weight=self.weights["missing_waf"],
                reasoning=f"{waf_name} WAF present - bypass techniques required"
            )
        
        return None
    
    def _score_security_headers(
        self,
        tech_fingerprint: Optional[Dict[str, Any]] = None
    ) -> Optional[ScoringFactor]:
        """
        Score based on security header presence.
        
        MISSING HEADERS = EXPLOITATION OPPORTUNITIES:
            - No CSP = XSS easier
            - No X-Frame-Options = Clickjacking possible
            - No HSTS = MITM attacks viable
        
        Args:
            tech_fingerprint: Technology fingerprint
            
        Returns:
            ScoringFactor for weak security headers or None
        """
        if not tech_fingerprint:
            return None
        
        security = tech_fingerprint.get("security", {})
        headers = security.get("security_headers", {})
        
        security_score = headers.get("score", 100)
        missing = headers.get("missing", [])
        
        # Invert security score to get vulnerability score
        vulnerability_score = 100 - security_score
        
        if vulnerability_score > 30:  # At least 30% vulnerable
            critical_missing = [h for h in missing if h in [
                "content-security-policy",
                "strict-transport-security",
                "x-frame-options"
            ]]
            
            reasoning_parts = [f"Security header score: {security_score}/100"]
            if critical_missing:
                reasoning_parts.append(f"Missing critical headers: {', '.join(critical_missing)}")
            
            return ScoringFactor(
                category="weak_security_headers",
                description="Weak security header configuration",
                score=int(vulnerability_score),
                weight=self.weights["weak_security_headers"],
                reasoning="; ".join(reasoning_parts)
            )
        
        return None
    
    def _score_sensitive_endpoint(self, asset: Dict[str, Any]) -> Optional[ScoringFactor]:
        """
        Score sensitive endpoints (config, backup, etc.).
        
        HIGH VALUE: These often contain:
            - Credentials
            - Source code
            - Database dumps
            - Configuration details
        
        Args:
            asset: Asset information
            
        Returns:
            ScoringFactor for sensitive endpoint or None
        """
        asset_url = asset.get("asset", "").lower()
        asset_type = asset.get("asset_type", "")
        
        # Sensitive file types
        if asset_type == "sensitive_file":
            score = 85
            reasoning = f"Sensitive file accessible: {asset.get('metadata', {}).get('file_path', 'unknown')}"
            
            # Higher score if file is readable (200) vs forbidden (403)
            status_code = asset.get("status_code")
            if status_code == 200:
                score = 95
                reasoning += " (readable)"
            elif status_code == 403:
                score = 70
                reasoning += " (forbidden but exists - bypass possible)"
            
            return ScoringFactor(
                category="sensitive_endpoint",
                description="Sensitive file/endpoint detected",
                score=score,
                weight=self.weights["sensitive_endpoint"],
                reasoning=reasoning
            )
        
        # Check for sensitive URL patterns
        if re.search(self.HIGH_VALUE_PATTERNS["sensitive"], asset_url):
            return ScoringFactor(
                category="sensitive_endpoint",
                description="Sensitive endpoint pattern",
                score=75,
                weight=self.weights["sensitive_endpoint"],
                reasoning="Endpoint matches sensitive pattern (config/backup/env)"
            )
        
        return None
    
    def _score_development_endpoint(self, asset: Dict[str, Any]) -> Optional[ScoringFactor]:
        """
        Score development/staging endpoints.
        
        DEV ENDPOINTS = WEAKER SECURITY:
            - Often have debug mode enabled
            - May have default credentials
            - Less monitoring/logging
            - May expose sensitive info
        
        Args:
            asset: Asset information
            
        Returns:
            ScoringFactor for development endpoint or None
        """
        asset_str = asset.get("asset", "").lower()
        
        # Check for dev patterns
        if re.search(self.HIGH_VALUE_PATTERNS["dev"], asset_str):
            return ScoringFactor(
                category="development_endpoint",
                description="Development/staging environment",
                score=80,
                weight=self.weights["development_endpoint"],
                reasoning="Dev/staging environments typically have weaker security and debug features enabled"
            )
        
        return None
    
    def _determine_priority_level(self, score: float) -> PriorityLevel:
        """
        Determine priority level from score.
        
        Args:
            score: Total exploitability score (0-100)
            
        Returns:
            PriorityLevel classification
        """
        if score >= 80:
            return PriorityLevel.CRITICAL
        elif score >= 60:
            return PriorityLevel.HIGH
        elif score >= 40:
            return PriorityLevel.MEDIUM
        elif score >= 20:
            return PriorityLevel.LOW
        else:
            return PriorityLevel.MINIMAL
    
    def _recommend_attacks(
        self,
        scoring_factors: List[ScoringFactor],
        tech_fingerprint: Optional[Dict[str, Any]] = None
    ) -> List[str]:
        """
        Recommend specific attack vectors based on scoring factors.
        
        Args:
            scoring_factors: List of scoring factors
            tech_fingerprint: Technology fingerprint
            
        Returns:
            List of recommended attack vectors
        """
        recommendations = []
        
        # Build recommendations based on scoring factors
        for factor in scoring_factors:
            if factor.category == "authentication":
                recommendations.extend([
                    "Credential stuffing with breach data",
                    "Brute force attack with common passwords",
                    "Authentication bypass techniques",
                ])
            
            elif factor.category == "admin_panel":
                recommendations.extend([
                    "Default credential testing",
                    "Path traversal to access admin",
                    "Authentication bypass",
                    "Privilege escalation",
                ])
            
            elif factor.category == "api_endpoint":
                recommendations.extend([
                    "API parameter fuzzing",
                    "IDOR testing",
                    "SQL/NoSQL injection",
                    "Mass assignment exploitation",
                    "Rate limiting bypass",
                ])
            
            elif factor.category == "legacy_technology":
                recommendations.extend([
                    "CVE exploitation for detected versions",
                    "Known vulnerability scanning",
                    "Metasploit module usage",
                ])
            
            elif factor.category == "missing_waf":
                recommendations.extend([
                    "Direct injection attacks (no filtering)",
                    "Automated vulnerability scanning",
                ])
            
            elif factor.category == "sensitive_endpoint":
                recommendations.extend([
                    "File download and analysis",
                    "Credential extraction",
                    "Source code review",
                ])
            
            elif factor.category == "development_endpoint":
                recommendations.extend([
                    "Debug mode exploitation",
                    "Default credential testing",
                    "Error-based information disclosure",
                ])
        
        # Add tech-specific recommendations
        if tech_fingerprint:
            backend = tech_fingerprint.get("backend", {})
            if backend.get("primary"):
                tech = backend["primary"].get("technology", "")
                
                if tech == "php":
                    recommendations.append("PHP-specific attacks (LFI, RFI, type juggling)")
                elif tech == "node.js":
                    recommendations.append("Prototype pollution, command injection")
                elif tech == "python":
                    recommendations.append("SSTI (Server-Side Template Injection)")
                elif tech == "java":
                    recommendations.append("Deserialization attacks, XXE")
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations[:10]  # Limit to top 10
    
    def _generate_risk_summary(
        self,
        scoring_factors: List[ScoringFactor],
        total_score: float,
        priority_level: PriorityLevel
    ) -> str:
        """
        Generate human-readable risk summary.
        
        Args:
            scoring_factors: List of scoring factors
            total_score: Total exploitability score
            priority_level: Priority classification
            
        Returns:
            Risk summary string
        """
        top_factors = sorted(
            scoring_factors,
            key=lambda f: f.weighted_score(),
            reverse=True
        )[:3]
        
        summary_parts = [
            f"{priority_level.value.upper()} priority target (score: {total_score:.1f}/100)."
        ]
        
        if top_factors:
            factor_descriptions = [f.description for f in top_factors]
            summary_parts.append(
                f"Key factors: {', '.join(factor_descriptions[:2])}."
            )
        
        return " ".join(summary_parts)
    
    def prioritize_asset(
        self,
        asset: Dict[str, Any],
        tech_fingerprint: Optional[Dict[str, Any]] = None
    ) -> PrioritizedAsset:
        """
        Analyze and prioritize a single asset.
        
        Args:
            asset: Asset information
            tech_fingerprint: Optional technology fingerprint
            
        Returns:
            PrioritizedAsset with complete scoring and recommendations
        """
        scoring_factors = []
        
        # Run all scoring functions
        scoring_methods = [
            self._score_authentication,
            self._score_admin_panel,
            self._score_api_endpoint,
            self._score_sensitive_endpoint,
            self._score_development_endpoint,
        ]
        
        for method in scoring_methods:
            try:
                if method in [self._score_authentication, self._score_api_endpoint]:
                    factor = method(asset, tech_fingerprint)
                else:
                    factor = method(asset)
                
                if factor:
                    scoring_factors.append(factor)
            except Exception:
                continue
        
        # Tech fingerprint-specific scoring
        if tech_fingerprint:
            tech_methods = [
                self._score_legacy_technology,
                self._score_waf_presence,
                self._score_security_headers,
            ]
            
            for method in tech_methods:
                try:
                    factor = method(tech_fingerprint)
                    if factor:
                        scoring_factors.append(factor)
                except Exception:
                    continue
        
        # Calculate total score
        if scoring_factors:
            weighted_scores = [f.weighted_score() for f in scoring_factors]
            total_score = sum(weighted_scores) / len(scoring_factors)
        else:
            total_score = 10  # Minimal score if no factors
        
        # Cap at 100
        total_score = min(total_score, 100)
        
        # Determine priority level
        priority_level = self._determine_priority_level(total_score)
        
        # Generate recommendations
        recommended_attacks = self._recommend_attacks(scoring_factors, tech_fingerprint)
        
        # Generate risk summary
        risk_summary = self._generate_risk_summary(
            scoring_factors,
            total_score,
            priority_level
        )
        
        return PrioritizedAsset(
            asset=asset.get("asset", "unknown"),
            asset_type=asset.get("asset_type", "unknown"),
            total_score=round(total_score, 2),
            priority_level=priority_level,
            scoring_factors=scoring_factors,
            recommended_attacks=recommended_attacks,
            risk_summary=risk_summary,
            metadata=asset.get("metadata", {})
        )
    
    def prioritize_assets(
        self,
        assets: List[Dict[str, Any]],
        tech_fingerprints: Optional[Dict[str, Dict[str, Any]]] = None
    ) -> Dict[str, Any]:
        """
        Prioritize multiple assets and rank them.
        
        ATTACK PLANNING: Use this to determine which targets to hit first.
        
        Args:
            assets: List of asset dictionaries
            tech_fingerprints: Dictionary mapping asset URLs to fingerprints
            
        Returns:
            Complete prioritization analysis with ranked targets
        """
        tech_fingerprints = tech_fingerprints or {}
        prioritized_assets = []
        
        # Score each asset
        for asset in assets:
            asset_url = asset.get("asset", "")
            fingerprint = tech_fingerprints.get(asset_url)
            
            prioritized = self.prioritize_asset(asset, fingerprint)
            prioritized_assets.append(prioritized)
        
        # Sort by score (highest first)
        prioritized_assets.sort(key=lambda a: a.total_score, reverse=True)
        
        # Assign ranks
        for i, asset in enumerate(prioritized_assets, 1):
            asset.ranked_position = i
        
        # Categorize by priority level
        categorized = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "minimal": [],
        }
        
        for asset in prioritized_assets:
            categorized[asset.priority_level.value].append(asset.to_dict())
        
        return {
            "total_assets": len(prioritized_assets),
            "ranked_assets": [a.to_dict() for a in prioritized_assets],
            "categorized_by_priority": categorized,
            "summary": {
                "critical": len(categorized["critical"]),
                "high": len(categorized["high"]),
                "medium": len(categorized["medium"]),
                "low": len(categorized["low"]),
                "minimal": len(categorized["minimal"]),
            },
            "top_targets": [a.to_dict() for a in prioritized_assets[:10]],
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute attack surface prioritization based on workflow state.
        
        Args:
            state: Current workflow state with assets and fingerprints
            
        Returns:
            Updated state with prioritization results
        """
        # Extract assets and fingerprints from state
        assets = state.get("assets", [])
        if isinstance(assets, dict):
            assets = assets.get("assets", [])
        
        tech_fingerprints = {}
        if "tech_fingerprint" in state:
            # Single fingerprint
            url = state["tech_fingerprint"].get("url")
            if url:
                tech_fingerprints[url] = state["tech_fingerprint"]
        
        # Perform prioritization
        results = self.prioritize_assets(assets, tech_fingerprints)
        
        # Update state
        state["attack_surface_prioritization"] = results
        
        return state
