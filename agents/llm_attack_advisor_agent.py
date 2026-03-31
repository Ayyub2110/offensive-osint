"""
LLM Attack Advisor Agent

Offensive Security Use Case:
    Acts as a senior red team advisor, analyzing reconnaissance intelligence to suggest
    realistic, high-impact attack paths. This module provides strategic offensive guidance
    without performing actual exploitation.

Attack Path Capabilities:
    - Phishing campaign design (targets, pretexts, delivery mechanisms)
    - Credential stuffing/password spraying strategies
    - JWT token abuse scenarios (weak signing, expiration bypass)
    - Account takeover methodologies (session hijacking, password reset abuse)
    - Authentication bypass techniques
    - API exploitation strategies
    - Social engineering attack chains

LLM Integration:
    Uses OpenAI GPT-4 (or compatible models) to provide expert-level offensive security
    analysis based on reconnaissance data. Simulates experienced red teamer reasoning.

Output Format:
    Advisory report with:
    - Executive summary of attack surface weaknesses
    - Prioritized attack paths with step-by-step execution guidance
    - Risk/reward analysis for each approach
    - Defense evasion considerations
    - Required tools and resources

Author: AI Offensive OSINT Framework
License: MIT (Authorized Use Only)
"""

import os
import json
from typing import Dict, List, Any, Optional
from datetime import datetime


class LLMAttackAdvisorAgent:
    """
    Senior Red Team Advisor powered by LLM reasoning.

    Analyzes complete reconnaissance intelligence to generate strategic
    attack recommendations. Acts as virtual senior penetration tester.
    """

    def __init__(self, api_key: Optional[str] = None, model: str = "gpt-4"):
        """
        Initialize LLM Attack Advisor Agent.

        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            model: LLM model to use (gpt-4, gpt-4-turbo, gpt-3.5-turbo, etc.)
        """
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.model = model
        self.temperature = float(os.getenv("LLM_TEMPERATURE", "0.7"))

        # Check if OpenAI library is available
        try:
            from openai import OpenAI

            self.client = OpenAI(api_key=self.api_key) if self.api_key else None
            self.llm_available = self.client is not None
        except ImportError:
            self.client = None
            self.llm_available = False
            print(
                "[WARNING] OpenAI library not available. Install with: pip install openai"
            )

    def analyze_intelligence(self, intelligence_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point: Analyze complete intelligence and generate attack advisory.

        Args:
            intelligence_data: Complete reconnaissance data including:
                - username_correlation: Platform presence data
                - email_patterns: Generated email addresses
                - asset_discovery: Discovered assets (subdomains, endpoints, files)
                - tech_stack: Technology fingerprinting results
                - attack_surface_prioritization: Scored and ranked targets

        Returns:
            Attack advisory dictionary containing:
                - executive_summary: High-level assessment
                - attack_paths: List of detailed attack path recommendations
                - tooling_requirements: Tools needed for execution
                - timeline_estimate: Estimated time for each attack path
                - defense_evasion: Tips for avoiding detection
                - success_probability: Likelihood estimates
        """
        print(
            f"[LLM ADVISOR] Analyzing intelligence for strategic attack recommendations..."
        )

        # If LLM is not available, fall back to rule-based analysis
        if not self.llm_available:
            print("[LLM ADVISOR] LLM not configured - using rule-based analysis")
            return self._fallback_analysis(intelligence_data)

        try:
            # Prepare intelligence summary for LLM
            intel_summary = self._prepare_intelligence_summary(intelligence_data)

            # Generate LLM-powered attack advisory
            advisory = self._generate_llm_advisory(intel_summary, intelligence_data)

            print(
                f"[LLM ADVISOR] Generated {len(advisory.get('attack_paths', []))} attack path recommendations"
            )
            return advisory

        except Exception as e:
            print(f"[LLM ADVISOR] Error during LLM analysis: {e}")
            print("[LLM ADVISOR] Falling back to rule-based analysis")
            return self._fallback_analysis(intelligence_data)

    def _prepare_intelligence_summary(self, data: Dict[str, Any]) -> str:
        """
        Convert raw intelligence data into structured summary for LLM analysis.

        Args:
            data: Complete reconnaissance data

        Returns:
            Formatted intelligence summary string
        """
        summary_parts = []

        # Domain/Target context
        domain = data.get("domain") or data.get("url", "Unknown Target")
        summary_parts.append(f"TARGET: {domain}")
        summary_parts.append("=" * 60)

        # Username correlation
        if "username_correlation" in data:
            correlation = data["username_correlation"]
            platforms = correlation.get("platforms_found", [])
            if platforms:
                summary_parts.append(f"\nUSERNAME INTELLIGENCE:")
                summary_parts.append(
                    f"  Username: {correlation.get('username', 'N/A')}"
                )
                summary_parts.append(f"  Platforms found: {', '.join(platforms)}")

        # Email patterns
        if "email_patterns" in data:
            emails = data["email_patterns"].get("validated_emails", [])
            if emails:
                summary_parts.append(f"\nEMAIL INTELLIGENCE:")
                summary_parts.append(f"  Generated {len(emails)} email patterns")
                summary_parts.append(f"  Top emails: {', '.join(emails[:3])}")

        # Asset discovery summary
        if "asset_discovery" in data:
            assets = data["asset_discovery"]
            total = assets.get("total_assets", 0)
            categorized = assets.get("categorized", {})

            summary_parts.append(f"\nASSET DISCOVERY:")
            summary_parts.append(f"  Total assets: {total}")
            for category, count in categorized.items():
                summary_parts.append(f"    - {category}: {count}")

            # Highlight sensitive findings
            sensitive = [
                a
                for a in assets.get("assets", [])
                if a.get("asset_type") == "sensitive_file"
            ]
            if sensitive:
                summary_parts.append(f"  Sensitive files found: {len(sensitive)}")
                for s in sensitive[:3]:
                    summary_parts.append(f"    - {s.get('value', 'N/A')}")

        # Technology stack
        if "tech_stack" in data:
            tech = data["tech_stack"]
            summary_parts.append(f"\nTECHNOLOGY STACK:")

            if tech.get("web_server"):
                summary_parts.append(f"  Web Server: {tech['web_server']}")
            if tech.get("backend_technologies"):
                summary_parts.append(
                    f"  Backend: {', '.join(tech['backend_technologies'])}"
                )
            if tech.get("cms"):
                summary_parts.append(f"  CMS: {tech['cms']}")
            if tech.get("waf_cdn"):
                summary_parts.append(f"  WAF/CDN: {tech['waf_cdn']}")
            else:
                summary_parts.append(f"  WAF/CDN: None detected (direct access)")

            auth = tech.get("authentication_mechanisms", [])
            if auth:
                summary_parts.append(f"  Authentication: {', '.join(auth)}")

            security_score = tech.get("security_headers_score", 0)
            summary_parts.append(f"  Security Headers Score: {security_score}/100")

        # Priority targets
        if "attack_surface_prioritization" in data:
            prioritization = data["attack_surface_prioritization"]
            top_targets = prioritization.get("top_targets", [])[:5]

            summary_parts.append(f"\nTOP PRIORITY TARGETS:")
            for i, target in enumerate(top_targets, 1):
                url = target.get("url", "N/A")
                score = target.get("score", 0)
                priority = target.get("priority", "unknown")
                summary_parts.append(
                    f"  {i}. {url} (Score: {score:.1f}, Priority: {priority})"
                )

                reasons = target.get("reasons", [])
                if reasons:
                    summary_parts.append(f"     Reasons: {', '.join(reasons[:2])}")

        return "\n".join(summary_parts)

    def _generate_llm_advisory(
        self, intel_summary: str, full_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Use LLM to generate expert-level attack path recommendations.

        Args:
            intel_summary: Formatted intelligence summary
            full_data: Complete raw data for reference

        Returns:
            Structured attack advisory
        """
        # Construct system prompt for senior red teamer persona
        system_prompt = """You are a senior red team operator with 15+ years of offensive security experience. 
Your role is to analyze reconnaissance intelligence and provide strategic attack path recommendations.

ANALYSIS FRAMEWORK:
1. Executive Summary: High-level assessment of attack surface weaknesses
2. Attack Paths: Prioritized, realistic attack scenarios with step-by-step guidance
3. Risk/Reward: Likelihood of success vs detection risk for each path
4. Tooling: Specific tools and techniques required
5. Defense Evasion: OPSEC considerations and stealth tactics

ATTACK PATH CATEGORIES TO CONSIDER:
- Phishing & Social Engineering (credential harvesting, pretexting)
- Credential Attacks (stuffing, spraying, brute force)
- Authentication Bypass (JWT manipulation, session hijacking, OAuth abuse)
- Account Takeover (password reset abuse, session fixation)
- Web Application Exploitation (SQLi, XSS, file inclusion if tech stack suggests)
- API Abuse (broken authentication, excessive data exposure)
- Infrastructure Exploitation (subdomain takeover, exposed admin panels)

OUTPUT REQUIREMENTS:
- Be specific and actionable (not generic advice)
- Prioritize paths by probability of success
- Include estimated time/effort for each path
- Mention detection likelihood (low/medium/high)
- Reference specific findings from intelligence
- Format as structured JSON

IMPORTANT: This is an advisory only - do NOT include actual exploitation code or malicious payloads."""

        # Construct user prompt with intelligence data
        user_prompt = f"""Analyze the following reconnaissance intelligence and provide strategic attack path recommendations:

{intel_summary}

Provide a comprehensive attack advisory in JSON format with the following structure:
{{
  "executive_summary": "Brief assessment of key weaknesses and recommended approach",
  "attack_paths": [
    {{
      "name": "Attack path name",
      "category": "phishing|credential_attack|jwt_abuse|account_takeover|web_exploitation|api_abuse|infrastructure",
      "description": "Detailed description of attack scenario",
      "steps": ["Step 1", "Step 2", ...],
      "prerequisites": ["Requirement 1", "Requirement 2", ...],
      "tools_required": ["Tool 1", "Tool 2", ...],
      "success_probability": "high|medium|low",
      "detection_likelihood": "high|medium|low",
      "estimated_effort": "hours|days|weeks",
      "impact": "Description of successful exploitation impact",
      "intelligence_basis": "Specific findings that enable this attack"
    }}
  ],
  "defense_evasion_tips": ["Tip 1", "Tip 2", ...],
  "recommended_order": ["Attack path name 1", "Attack path name 2", ...]
}}

Focus on the most realistic and high-impact attack paths based on the intelligence gathered."""

        try:
            # Call OpenAI API
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self.temperature,
                max_tokens=3000,
            )

            # Extract and parse response
            advisory_text = response.choices[0].message.content

            # Try to parse as JSON
            try:
                advisory = json.loads(advisory_text)
            except json.JSONDecodeError:
                # If not valid JSON, extract JSON from markdown code blocks
                import re

                json_match = re.search(
                    r"```(?:json)?\s*(\{.*?\})\s*```", advisory_text, re.DOTALL
                )
                if json_match:
                    advisory = json.loads(json_match.group(1))
                else:
                    # Fall back to structured text parsing
                    advisory = {
                        "executive_summary": advisory_text[:500],
                        "attack_paths": [],
                        "raw_llm_response": advisory_text,
                    }

            # Add metadata
            advisory["generated_at"] = datetime.now().isoformat()
            advisory["model_used"] = self.model
            advisory["intelligence_quality"] = self._assess_intelligence_quality(
                full_data
            )

            return advisory

        except Exception as e:
            print(f"[LLM ADVISOR] Error calling LLM API: {e}")
            raise

    def _assess_intelligence_quality(self, data: Dict[str, Any]) -> str:
        """
        Assess quality of gathered intelligence for attack planning.

        Args:
            data: Complete reconnaissance data

        Returns:
            Quality assessment (excellent/good/moderate/limited)
        """
        if data is None:
            return "limited"

        quality_score = 0
        max_score = 0

        # Check username correlation
        uc = data.get("username_correlation") or {}
        if uc.get("platforms_found"):
            quality_score += len(uc["platforms_found"]) * 10
        max_score += 40

        # Check email patterns
        ep = data.get("email_patterns") or {}
        if ep.get("validated_emails"):
            quality_score += len(ep["validated_emails"]) * 5
        max_score += 50

        # Check asset discovery
        ad = data.get("asset_discovery") or {}
        total_assets = ad.get("total_assets", 0)
        quality_score += min(total_assets * 2, 100)
        max_score += 100

        # Check tech stack info
        ts = data.get("tech_stack") or {}
        if ts.get("web_server"):
            quality_score += 20
        if ts.get("backend_technologies"):
            quality_score += 20
        max_score += 40

        # Check prioritization
        asp = data.get("attack_surface_prioritization") or {}
        if asp.get("top_targets"):
            quality_score += min(len(asp["top_targets"]) * 10, 50)
        max_score += 50

        # Calculate percentage
        percentage = (quality_score / max_score * 100) if max_score > 0 else 0

        if percentage >= 75:
            return "excellent"
        elif percentage >= 50:
            return "good"
        elif percentage >= 25:
            return "moderate"
        else:
            return "limited"

    def _fallback_analysis(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Rule-based attack advisory when LLM is not available.

        Provides strategic recommendations based on intelligence patterns
        without requiring LLM API access.

        Args:
            data: Complete reconnaissance data

        Returns:
            Attack advisory dictionary (rule-based)
        """
        if data is None:
            data = {}

        advisory = {
            "executive_summary": "",
            "attack_paths": [],
            "defense_evasion_tips": [],
            "recommended_order": [],
            "generated_at": datetime.now().isoformat(),
            "model_used": "rule-based (LLM not available)",
            "intelligence_quality": self._assess_intelligence_quality(data),
        }

        attack_paths = []

        # Analyze email patterns for credential attacks
        email_patterns = data.get("email_patterns") or {}
        if email_patterns.get("validated_emails"):
            emails = email_patterns["validated_emails"]
            attack_paths.append(
                {
                    "name": "Credential Stuffing Campaign",
                    "category": "credential_attack",
                    "description": f"Leverage {len(emails)} validated email patterns for credential stuffing using known breach databases",
                    "steps": [
                        "Collect email:password pairs from breach databases (Dehashed, BreachCompilation)",
                        f"Test {len(emails)} email patterns against authentication endpoints",
                        "Use rotating proxies to avoid rate limiting",
                        "Prioritize emails with high confidence scores",
                        "Attempt password reuse across multiple services",
                    ],
                    "prerequisites": [
                        "Breach database access",
                        "Authentication endpoint identified",
                    ],
                    "tools_required": [
                        "CredMaster",
                        "Snipr",
                        "Burp Suite Intruder",
                        "Rotating Proxy Service",
                    ],
                    "success_probability": "medium",
                    "detection_likelihood": "medium",
                    "estimated_effort": "days",
                    "impact": "Account compromise enabling lateral movement and data exfiltration",
                    "intelligence_basis": f"Generated {len(emails)} validated email patterns with domain confirmation",
                }
            )

        # Analyze username correlation for social engineering
        username_correlation = data.get("username_correlation") or {}
        if username_correlation.get("platforms_found"):
            platforms = username_correlation["platforms_found"]
            username = username_correlation.get("username", "target")

            attack_paths.append(
                {
                    "name": "Targeted Phishing via Social Media Intelligence",
                    "category": "phishing",
                    "description": f"Craft personalized phishing campaign using intelligence from {len(platforms)} social platforms",
                    "steps": [
                        f"Harvest detailed profile information from {', '.join(platforms)}",
                        "Identify interests, contacts, and communication patterns",
                        "Clone legitimate service login pages (email provider, corporate SSO)",
                        "Craft personalized pretext based on social media activity",
                        "Deploy phishing page with credential harvesting",
                        "Use harvested credentials for account takeover",
                    ],
                    "prerequisites": [
                        "Social media profile access",
                        "Phishing infrastructure",
                    ],
                    "tools_required": [
                        "Gophish",
                        "Evilginx2",
                        "Social-Engineer Toolkit",
                        "Domain fronting service",
                    ],
                    "success_probability": "high",
                    "detection_likelihood": "low",
                    "estimated_effort": "days",
                    "impact": "Account compromise with high confidence due to personalized approach",
                    "intelligence_basis": f"Username '{username}' confirmed on {len(platforms)} platforms: {', '.join(platforms)}",
                }
            )

        # Analyze tech stack for JWT abuse
        tech_stack = data.get("tech_stack") or {}
        if "jwt" in str(tech_stack).lower() or "bearer" in str(tech_stack).lower():
            attack_paths.append(
                {
                    "name": "JWT Token Manipulation Attack",
                    "category": "jwt_abuse",
                    "description": "Exploit weak JWT implementation for authentication bypass",
                    "steps": [
                        "Capture JWT tokens from authentication responses",
                        "Analyze token structure (header, payload, signature)",
                        "Test for algorithm confusion (RS256 → HS256)",
                        "Check for weak signing secrets (brute force with common wordlists)",
                        "Test 'none' algorithm acceptance",
                        "Modify payload claims (user role, permissions, expiration)",
                        "Replay modified tokens for privilege escalation",
                    ],
                    "prerequisites": [
                        "Valid JWT token sample",
                        "Authentication endpoint",
                    ],
                    "tools_required": [
                        "jwt_tool",
                        "Burp Suite JWT Editor",
                        "Hashcat",
                        "Custom scripts",
                    ],
                    "success_probability": "medium",
                    "detection_likelihood": "low",
                    "estimated_effort": "hours",
                    "impact": "Authentication bypass or privilege escalation to admin access",
                    "intelligence_basis": "JWT/Bearer authentication mechanism detected in tech stack",
                }
            )

        # Analyze admin panels for account takeover
        prioritization = data.get("attack_surface_prioritization") or {}
        top_targets = prioritization.get("top_targets") or []
        admin_targets = [
            t
            for t in top_targets
            if t
            and "admin" in t.get("url", "").lower()
            or t
            and "login" in t.get("url", "").lower()
        ]

        if admin_targets:
            target = admin_targets[0]
            attack_paths.append(
                {
                    "name": "Account Takeover via Password Reset Abuse",
                    "category": "account_takeover",
                    "description": f"Exploit password reset functionality on {target.get('url', 'admin panel')}",
                    "steps": [
                        "Identify password reset mechanism",
                        "Test for weak reset token generation (predictable, short)",
                        "Check for token reuse and lack of expiration",
                        "Test for account enumeration via reset form",
                        "Attempt email parameter pollution",
                        "Try host header injection for reset link hijacking",
                        "Test for race conditions in password reset flow",
                    ],
                    "prerequisites": [
                        "Valid email address",
                        "Password reset functionality exists",
                    ],
                    "tools_required": [
                        "Burp Suite",
                        "Custom token analysis scripts",
                        "Email monitoring",
                    ],
                    "success_probability": "medium",
                    "detection_likelihood": "medium",
                    "estimated_effort": "hours",
                    "impact": "Account takeover of privileged users including administrators",
                    "intelligence_basis": f"High-priority admin/login endpoint identified: {target.get('url', 'N/A')} (score: {target.get('score', 0):.1f})",
                }
            )

        # Analyze sensitive files for direct exploitation
        asset_discovery = data.get("asset_discovery") or {}
        assets = asset_discovery.get("assets") or []
        sensitive_files = [
            a for a in assets if a and a.get("asset_type") == "sensitive_file"
        ]

        if sensitive_files:
            attack_paths.append(
                {
                    "name": "Exposed Configuration File Exploitation",
                    "category": "infrastructure",
                    "description": f"Extract credentials and secrets from {len(sensitive_files)} exposed sensitive files",
                    "steps": [
                        f"Download {len(sensitive_files)} identified sensitive files",
                        "Extract credentials, API keys, database connections",
                        "Test extracted credentials against identified services",
                        "Use API keys for service enumeration and data access",
                        "Leverage database credentials for direct database access",
                        "Check for hardcoded secrets in .env, config files",
                    ],
                    "prerequisites": ["Direct file access confirmed"],
                    "tools_required": [
                        "curl/wget",
                        "truffleHog",
                        "GitLeaks",
                        "Custom parsers",
                    ],
                    "success_probability": "high",
                    "detection_likelihood": "low",
                    "estimated_effort": "hours",
                    "impact": "Direct access to backend systems, databases, and APIs",
                    "intelligence_basis": f"{len(sensitive_files)} sensitive files discovered: {', '.join([f.get('value', '') for f in sensitive_files[:3]])}",
                }
            )

        # Check for WAF/CDN absence
        tech = data.get("tech_stack") or {}
        if not tech.get("waf_cdn"):
            attack_paths.append(
                {
                    "name": "Direct Web Application Attack (No WAF)",
                    "category": "web_exploitation",
                    "description": "Direct exploitation without WAF protection",
                    "steps": [
                        "No WAF detected - direct application access possible",
                        "Perform active vulnerability scanning (SQLi, XSS, IDOR)",
                        "Test for common web vulnerabilities without rate limiting concerns",
                        "Brute force authentication endpoints",
                        "Attempt file upload vulnerabilities",
                        "Test for server-side request forgery (SSRF)",
                    ],
                    "prerequisites": ["Direct application access"],
                    "tools_required": [
                        "sqlmap",
                        "Burp Suite Pro",
                        "OWASP ZAP",
                        "Nuclei",
                        "ffuf",
                    ],
                    "success_probability": "high",
                    "detection_likelihood": "high",
                    "estimated_effort": "days",
                    "impact": "Full application compromise including database access",
                    "intelligence_basis": "No WAF/CDN protection detected - direct access to application",
                }
            )

        # Build executive summary
        if attack_paths:
            advisory["attack_paths"] = attack_paths
            advisory["recommended_order"] = [
                ap["name"]
                for ap in sorted(
                    attack_paths,
                    key=lambda x: {"high": 3, "medium": 2, "low": 1}.get(
                        x["success_probability"], 0
                    ),
                    reverse=True,
                )
            ]

            high_prob_attacks = [
                ap for ap in attack_paths if ap["success_probability"] == "high"
            ]
            advisory["executive_summary"] = (
                f"Analysis identified {len(attack_paths)} viable attack paths. "
                f"{len(high_prob_attacks)} paths have HIGH success probability. "
                f"Recommended initial approach: {advisory['recommended_order'][0]}. "
                f"Intelligence quality: {advisory['intelligence_quality']}."
            )
        else:
            advisory["executive_summary"] = (
                "Limited attack surface identified. Recommend additional reconnaissance."
            )

        # Defense evasion tips
        advisory["defense_evasion_tips"] = [
            "Use rotating residential proxies to avoid IP-based blocking",
            "Implement realistic timing delays between requests (3-30 seconds)",
            "Randomize user agents and HTTP headers to mimic legitimate traffic",
            "Monitor for honeypot indicators (fake admin panels, trap endpoints)",
            "Use HTTPS and encrypted channels for command & control",
            "Segment attack infrastructure from personal/corporate networks",
        ]

        return advisory


# Example usage and testing
if __name__ == "__main__":
    # Example intelligence data for testing
    test_intelligence = {
        "domain": "targetcorp.com",
        "username_correlation": {
            "username": "johndoe",
            "platforms_found": ["github", "twitter"],
            "details": {},
        },
        "email_patterns": {
            "validated_emails": [
                "john.doe@targetcorp.com",
                "j.doe@targetcorp.com",
                "johnd@targetcorp.com",
            ]
        },
        "asset_discovery": {
            "total_assets": 45,
            "categorized": {"subdomain": 15, "endpoint": 20, "sensitive_file": 3},
            "assets": [
                {"asset_type": "sensitive_file", "value": ".env"},
                {"asset_type": "subdomain", "value": "admin.targetcorp.com"},
            ],
        },
        "tech_stack": {
            "web_server": "nginx",
            "backend_technologies": ["php"],
            "authentication_mechanisms": ["jwt"],
            "waf_cdn": None,
            "security_headers_score": 35,
        },
        "attack_surface_prioritization": {
            "top_targets": [
                {
                    "url": "admin.targetcorp.com/login",
                    "score": 85.5,
                    "priority": "critical",
                    "reasons": ["admin_panel", "authentication_endpoint"],
                }
            ]
        },
    }

    # Initialize agent
    advisor = LLMAttackAdvisorAgent()

    # Generate advisory
    advisory = advisor.analyze_intelligence(test_intelligence)

    # Print results
    print("\n" + "=" * 60)
    print("ATTACK ADVISORY REPORT")
    print("=" * 60)
    print(f"\nExecutive Summary:\n{advisory.get('executive_summary', 'N/A')}")
    print(f"\nAttack Paths Identified: {len(advisory.get('attack_paths', []))}")

    for i, path in enumerate(advisory.get("attack_paths", []), 1):
        print(f"\n{i}. {path.get('name', 'Unknown')} ({path.get('category', 'N/A')})")
        print(
            f"   Success Probability: {path.get('success_probability', 'N/A').upper()}"
        )
        print(
            f"   Detection Likelihood: {path.get('detection_likelihood', 'N/A').upper()}"
        )
        print(f"   Effort: {path.get('estimated_effort', 'N/A')}")
        print(f"   Basis: {path.get('intelligence_basis', 'N/A')}")

    print(f"\nRecommended Order: {', '.join(advisory.get('recommended_order', []))}")
