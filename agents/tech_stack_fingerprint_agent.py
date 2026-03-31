"""
Technology Stack Fingerprinting Agent for vulnerability prioritization.

This agent identifies web technologies, frameworks, and security mechanisms
to build a complete technology profile. This intelligence is critical for
selecting appropriate attack vectors and exploits.

OFFENSIVE SECURITY USE CASES:
    - Vulnerability prioritization (known CVEs for detected versions)
    - Exploit selection (framework-specific attacks)
    - WAF/CDN bypass strategy planning
    - Authentication attack vector identification
    - Technology-specific payload crafting

ATTACK STRATEGY: Technology stack → Known vulnerabilities → Targeted exploits
"""

import asyncio
import aiohttp
import re
from typing import Dict, Any, List, Optional, Set, Tuple
from dataclasses import dataclass, asdict, field
from datetime import datetime
from urllib.parse import urlparse
import hashlib


@dataclass
class TechnologyFingerprint:
    """
    Complete technology stack fingerprint.

    Attributes:
        url: Target URL analyzed
        web_server: Web server information
        backend: Backend technology indicators
        frontend: Frontend frameworks and libraries
        auth_mechanisms: Authentication/authorization indicators
        security: WAF, CDN, and security headers
        cms: Content Management System detection
        databases: Database hints
        cloud_provider: Cloud platform indicators
        vulnerabilities: Known vulnerability patterns
        confidence_score: Overall confidence (0.0-1.0)
        metadata: Additional metadata
        timestamp: Analysis timestamp
    """

    url: str
    web_server: Dict[str, Any] = field(default_factory=dict)
    backend: Dict[str, Any] = field(default_factory=dict)
    frontend: Dict[str, Any] = field(default_factory=dict)
    auth_mechanisms: Dict[str, Any] = field(default_factory=dict)
    security: Dict[str, Any] = field(default_factory=dict)
    cms: Dict[str, Any] = field(default_factory=dict)
    databases: List[str] = field(default_factory=list)
    cloud_provider: Optional[str] = None
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    confidence_score: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: Optional[str] = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class TechStackFingerprintAgent:
    """
    Technology stack fingerprinting agent for attack surface analysis.

    This agent performs comprehensive technology detection using:
        - HTTP response headers (Server, X-Powered-By, etc.)
        - HTML meta tags and comments
        - JavaScript framework patterns
        - CSS framework signatures
        - Cookie patterns (session management)
        - Error page fingerprinting
        - CDN/WAF detection

    ATTACK INTELLIGENCE:
        - Each technology has specific CVEs and exploits
        - Older versions = higher priority targets
        - WAF presence = need for evasion techniques
        - Auth type = determines credential attack method
        - CMS detection = known plugin vulnerabilities

    Attributes:
        timeout: Request timeout in seconds
        user_agent: User-Agent for HTTP requests
    """

    # Web server signatures
    # ATTACK RELEVANCE: Server type determines attack vectors
    SERVER_SIGNATURES = {
        "nginx": ["nginx"],
        "apache": ["apache"],
        "iis": ["microsoft-iis", "iis"],
        "lighttpd": ["lighttpd"],
        "tomcat": ["tomcat", "coyote"],
        "jetty": ["jetty"],
        "weblogic": ["weblogic"],
        "websphere": ["websphere"],
        "gunicorn": ["gunicorn"],
        "uvicorn": ["uvicorn"],
        "werkzeug": ["werkzeug"],
        "express": ["express"],
        "kestrel": ["kestrel"],
        "caddy": ["caddy"],
    }

    # Backend technology indicators
    # ATTACK RELEVANCE: Determines exploit payloads and injection types
    BACKEND_INDICATORS = {
        "php": {
            "headers": ["x-powered-by"],
            "patterns": ["php", "phpsessid"],
            "extensions": [".php"],
        },
        "asp.net": {
            "headers": ["x-aspnet-version", "x-aspnetmvc-version"],
            "patterns": ["asp.net", "aspxauth"],
            "extensions": [".aspx", ".asp"],
        },
        "java": {
            "headers": ["x-powered-by"],
            "patterns": ["java", "jsessionid", "servlet"],
            "extensions": [".jsp", ".do", ".action"],
        },
        "python": {
            "headers": ["server"],
            "patterns": ["django", "flask", "fastapi", "werkzeug"],
            "extensions": [],
        },
        "ruby": {
            "headers": ["x-powered-by", "server"],
            "patterns": ["rack", "rails", "phusion passenger"],
            "extensions": [],
        },
        "node.js": {
            "headers": ["x-powered-by", "server"],
            "patterns": ["express", "node.js", "next.js"],
            "extensions": [],
        },
        "go": {
            "headers": ["server"],
            "patterns": ["go", "golang"],
            "extensions": [],
        },
    }

    # Frontend framework signatures
    # ATTACK RELEVANCE: Client-side vulnerabilities, XSS vectors
    FRONTEND_FRAMEWORKS = {
        "react": [
            r"react\.js",
            r"react-dom",
            r"data-reactroot",
            r"data-reactid",
            r"__REACT",
        ],
        "vue": [
            r"vue\.js",
            r"v-if",
            r"v-for",
            r"data-v-",
            r"__VUE",
        ],
        "angular": [
            r"angular\.js",
            r"ng-app",
            r"ng-controller",
            r"ng-model",
            r"[[]ng",
        ],
        "jquery": [
            r"jquery\.js",
            r"jquery\.min\.js",
            r"\$\(",
        ],
        "bootstrap": [
            r"bootstrap\.css",
            r"bootstrap\.js",
            r'class="[^"]*bootstrap[^"]*"',
        ],
        "next.js": [
            r"_next/",
            r"__NEXT_DATA__",
            r"next\.js",
        ],
        "nuxt": [
            r"_nuxt/",
            r"__NUXT__",
            r"nuxt\.js",
        ],
        "svelte": [
            r"svelte",
            r'class="svelte-',
        ],
    }

    # CMS signatures
    # ATTACK GOLDMINE: Known plugin vulnerabilities
    CMS_SIGNATURES = {
        "wordpress": {
            "paths": ["/wp-content/", "/wp-includes/", "/wp-admin/"],
            "meta": ["wordpress", "wp-"],
            "headers": [],
        },
        "drupal": {
            "paths": ["/sites/default/", "/core/", "/modules/"],
            "meta": ["drupal"],
            "headers": ["x-drupal-cache", "x-generator"],
        },
        "joomla": {
            "paths": ["/components/", "/modules/", "/templates/"],
            "meta": ["joomla"],
            "headers": [],
        },
        "magento": {
            "paths": ["/skin/frontend/", "/media/catalog/"],
            "meta": ["magento"],
            "headers": [],
        },
        "shopify": {
            "paths": ["/cdn.shopify.com/"],
            "meta": ["shopify"],
            "headers": [],
        },
    }

    # WAF/CDN signatures
    # ATTACK BARRIER: Must bypass or evade these
    WAF_CDN_SIGNATURES = {
        "cloudflare": {
            "headers": ["cf-ray", "cf-cache-status", "server"],
            "patterns": ["cloudflare"],
        },
        "akamai": {
            "headers": ["akamai-cache-status", "akamai-x-cache"],
            "patterns": ["akamai"],
        },
        "aws_cloudfront": {
            "headers": ["x-amz-cf-id", "via"],
            "patterns": ["cloudfront"],
        },
        "fastly": {
            "headers": ["fastly-debug-digest", "x-served-by"],
            "patterns": ["fastly"],
        },
        "incapsula": {
            "headers": ["x-cdn", "x-iinfo"],
            "patterns": ["incapsula"],
        },
        "sucuri": {
            "headers": ["x-sucuri-id", "x-sucuri-cache"],
            "patterns": ["sucuri"],
        },
        "modsecurity": {
            "headers": ["server"],
            "patterns": ["mod_security", "modsecurity"],
        },
        "barracuda": {
            "headers": ["x-barracuda"],
            "patterns": ["barracuda"],
        },
    }

    def __init__(
        self,
        timeout: int = 15,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        """
        Initialize the Tech Stack Fingerprint Agent.

        Args:
            timeout: Request timeout in seconds
            user_agent: User-Agent header for requests
        """
        self.timeout = timeout
        self.user_agent = user_agent
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session with SSL configuration."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
            }
            import ssl
            import certifi

            ssl_context = ssl.create_default_context()
            ssl_context.load_verify_locations(certifi.where())
            connector = aiohttp.TCPConnector(ssl=ssl_context)
            self._session = aiohttp.ClientSession(
                timeout=timeout, headers=headers, connector=connector
            )
        return self._session

    async def _close_session(self) -> None:
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    def _detect_web_server(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Detect web server from headers.

        ATTACK VALUE: Different servers have different vulnerabilities.
        Version numbers enable CVE lookup.

        Args:
            headers: HTTP response headers

        Returns:
            Web server information
        """
        server_info = {
            "type": None,
            "version": None,
            "raw": None,
        }

        server_header = headers.get("server", "").lower()
        if server_header:
            server_info["raw"] = headers.get("server")

            # Match against known servers
            for server_type, signatures in self.SERVER_SIGNATURES.items():
                for sig in signatures:
                    if sig in server_header:
                        server_info["type"] = server_type

                        # Try to extract version
                        version_match = re.search(r"[\d.]+", server_header)
                        if version_match:
                            server_info["version"] = version_match.group()
                        break
                if server_info["type"]:
                    break

        return server_info

    def _detect_backend(
        self, headers: Dict[str, str], cookies: Dict[str, str], html: str
    ) -> Dict[str, Any]:
        """
        Detect backend technology.

        ATTACK STRATEGY: Backend determines:
            - SQL injection syntax (MySQL vs PostgreSQL vs MSSQL)
            - Code injection payloads (PHP vs Python vs Node)
            - Deserialization vulnerabilities

        Args:
            headers: HTTP response headers
            cookies: Response cookies
            html: HTML response body

        Returns:
            Backend technology information
        """
        detected = []

        for tech, indicators in self.BACKEND_INDICATORS.items():
            confidence = 0
            evidence = []

            # Check headers
            for header in indicators.get("headers", []):
                if header in headers:
                    header_value = headers[header].lower()
                    for pattern in indicators["patterns"]:
                        if pattern in header_value:
                            confidence += 30
                            evidence.append(f"Header: {header}={headers[header]}")

            # Check cookies
            cookie_str = str(cookies).lower()
            for pattern in indicators["patterns"]:
                if pattern in cookie_str:
                    confidence += 20
                    evidence.append(f"Cookie pattern: {pattern}")

            # Check HTML extensions
            html_lower = html.lower()
            for ext in indicators.get("extensions", []):
                if ext in html_lower:
                    confidence += 10
                    evidence.append(f"Extension: {ext}")

            if confidence > 0:
                detected.append(
                    {
                        "technology": tech,
                        "confidence": min(confidence, 100),
                        "evidence": evidence,
                    }
                )

        # Sort by confidence
        detected.sort(key=lambda x: x["confidence"], reverse=True)

        return {
            "detected": detected,
            "primary": detected[0] if detected else None,
        }

    def _detect_frontend(self, html: str) -> Dict[str, Any]:
        """
        Detect frontend frameworks.

        ATTACK RELEVANCE: Framework-specific XSS vectors,
        client-side template injection, DOM-based attacks.

        Args:
            html: HTML response body

        Returns:
            Frontend framework information
        """
        detected = []

        for framework, patterns in self.FRONTEND_FRAMEWORKS.items():
            matches = []
            for pattern in patterns:
                if re.search(pattern, html, re.IGNORECASE):
                    matches.append(pattern)

            if matches:
                detected.append(
                    {
                        "framework": framework,
                        "confidence": min(len(matches) * 25, 100),
                        "patterns_matched": len(matches),
                    }
                )

        # Sort by confidence
        detected.sort(key=lambda x: x["confidence"], reverse=True)

        return {
            "frameworks": detected,
        }

    def _detect_auth_mechanisms(
        self, headers: Dict[str, str], cookies: Dict[str, str], html: str
    ) -> Dict[str, Any]:
        """
        Detect authentication and authorization mechanisms.

        CRITICAL FOR ATTACKS: Auth type determines:
            - Session hijacking techniques
            - Token manipulation strategies
            - Replay attack viability
            - Credential attack vectors

        Args:
            headers: HTTP response headers
            cookies: Response cookies
            html: HTML response body

        Returns:
            Authentication mechanism information
        """
        auth_info = {
            "session_based": False,
            "token_based": False,
            "oauth": False,
            "jwt": False,
            "basic_auth": False,
            "cookie_names": [],
            "tokens_found": [],
            "oauth_providers": [],
        }

        # Check for JWT tokens
        jwt_pattern = r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"
        jwt_matches = re.findall(jwt_pattern, html)
        if jwt_matches:
            auth_info["jwt"] = True
            auth_info["token_based"] = True
            auth_info["tokens_found"] = jwt_matches[:5]  # Limit output

        # Check cookies for session indicators
        session_patterns = [
            "sessionid",
            "session_id",
            "phpsessid",
            "jsessionid",
            "asp.net_sessionid",
            "aspsessionid",
            "sid",
            "sess",
        ]

        for cookie_name in cookies.keys():
            cookie_lower = cookie_name.lower()
            auth_info["cookie_names"].append(cookie_name)

            for pattern in session_patterns:
                if pattern in cookie_lower:
                    auth_info["session_based"] = True
                    break

        # Check for OAuth patterns
        oauth_patterns = [
            r"oauth",
            r"authorization_code",
            r"client_id",
            r"redirect_uri",
            r"access_token",
            r"refresh_token",
        ]

        html_lower = html.lower()
        for pattern in oauth_patterns:
            if re.search(pattern, html_lower):
                auth_info["oauth"] = True
                break

        # Detect OAuth providers
        oauth_providers = [
            "google",
            "facebook",
            "github",
            "microsoft",
            "twitter",
            "linkedin",
            "auth0",
            "okta",
        ]

        for provider in oauth_providers:
            if provider in html_lower:
                auth_info["oauth_providers"].append(provider)

        # Check for Basic Auth
        if "www-authenticate" in headers:
            if "basic" in headers["www-authenticate"].lower():
                auth_info["basic_auth"] = True

        return auth_info

    def _detect_waf_cdn(self, headers: Dict[str, str], html: str) -> Dict[str, Any]:
        """
        Detect WAF and CDN presence.

        CRITICAL DEFENSE INTEL: WAF/CDN affects:
            - Payload encoding requirements
            - Rate limiting strategies
            - IP blocking concerns
            - Request routing/caching behavior

        Args:
            headers: HTTP response headers
            html: HTML response body

        Returns:
            WAF/CDN detection information
        """
        detected = []

        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        html_lower = html.lower()

        for name, signatures in self.WAF_CDN_SIGNATURES.items():
            confidence = 0
            evidence = []

            # Check headers
            for header in signatures.get("headers", []):
                if header in headers_lower:
                    confidence += 40
                    evidence.append(f"Header: {header}")

            # Check patterns
            for pattern in signatures.get("patterns", []):
                # Check in headers
                for header_value in headers_lower.values():
                    if pattern in header_value:
                        confidence += 30
                        evidence.append(f"Pattern in headers: {pattern}")
                        break

                # Check in HTML
                if pattern in html_lower:
                    confidence += 20
                    evidence.append(f"Pattern in HTML: {pattern}")

            if confidence > 0:
                detected.append(
                    {
                        "name": name,
                        "type": "CDN"
                        if "cdn" in name
                        or name in ["cloudflare", "akamai", "fastly", "aws_cloudfront"]
                        else "WAF",
                        "confidence": min(confidence, 100),
                        "evidence": evidence,
                    }
                )

        # Sort by confidence
        detected.sort(key=lambda x: x["confidence"], reverse=True)

        return {
            "detected": detected,
            "has_waf": any(d["type"] == "WAF" for d in detected),
            "has_cdn": any(d["type"] == "CDN" for d in detected),
        }

    def _detect_cms(self, headers: Dict[str, str], html: str) -> Dict[str, Any]:
        """
        Detect Content Management System.

        ATTACK GOLDMINE: CMS = known plugin vulnerabilities.
        WordPress, Drupal, Joomla have massive vulnerability databases.

        Args:
            headers: HTTP response headers
            html: HTML response body

        Returns:
            CMS detection information
        """
        detected = []

        html_lower = html.lower()
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}

        for cms_name, signatures in self.CMS_SIGNATURES.items():
            confidence = 0
            evidence = []

            # Check paths in HTML
            for path in signatures.get("paths", []):
                if path in html_lower:
                    confidence += 30
                    evidence.append(f"Path: {path}")

            # Check meta tags
            for meta in signatures.get("meta", []):
                if meta in html_lower:
                    confidence += 25
                    evidence.append(f"Meta: {meta}")

            # Check headers
            for header in signatures.get("headers", []):
                if header in headers_lower:
                    confidence += 35
                    evidence.append(f"Header: {header}")

            if confidence > 0:
                # Try to extract version
                version = None
                if cms_name == "wordpress":
                    version_match = re.search(r"wp-content/[^/]+/(\d+\.\d+)", html)
                    if version_match:
                        version = version_match.group(1)

                detected.append(
                    {
                        "cms": cms_name,
                        "confidence": min(confidence, 100),
                        "version": version,
                        "evidence": evidence,
                    }
                )

        # Sort by confidence
        detected.sort(key=lambda x: x["confidence"], reverse=True)

        return {
            "detected": detected,
            "primary": detected[0] if detected else None,
        }

    def _detect_security_headers(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        Analyze security headers.

        DEFENSE ASSESSMENT: Missing security headers = easier exploitation

        Args:
            headers: HTTP response headers

        Returns:
            Security header analysis
        """
        security_headers = {
            "strict-transport-security": False,
            "content-security-policy": False,
            "x-frame-options": False,
            "x-content-type-options": False,
            "x-xss-protection": False,
            "referrer-policy": False,
            "permissions-policy": False,
        }

        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header in security_headers.keys():
            if header in headers_lower:
                security_headers[header] = headers_lower[header]

        # Calculate security score
        present = sum(1 for v in security_headers.values() if v)
        total = len(security_headers)
        security_score = (present / total) * 100

        return {
            "headers": security_headers,
            "score": round(security_score, 2),
            "missing": [k for k, v in security_headers.items() if not v],
        }

    def _detect_cloud_provider(
        self, headers: Dict[str, str], html: str
    ) -> Optional[str]:
        """
        Detect cloud hosting provider.

        Args:
            headers: HTTP response headers
            html: HTML response body

        Returns:
            Cloud provider name if detected
        """
        cloud_signatures = {
            "aws": ["amazonaws.com", "cloudfront", "x-amz"],
            "azure": ["azure", "windows.net", "azurewebsites"],
            "gcp": ["google", "gcp", "appspot"],
            "heroku": ["heroku"],
            "digitalocean": ["digitalocean"],
            "vercel": ["vercel"],
            "netlify": ["netlify"],
        }

        headers_str = str(headers).lower()
        html_lower = html.lower()

        for provider, signatures in cloud_signatures.items():
            for sig in signatures:
                if sig in headers_str or sig in html_lower:
                    return provider

        return None

    async def fingerprint(self, url: str) -> TechnologyFingerprint:
        """
        Perform complete technology stack fingerprinting.

        COMPLETE ATTACK INTELLIGENCE: Builds comprehensive tech profile
        for vulnerability prioritization and exploit selection.

        Args:
            url: Target URL to fingerprint

        Returns:
            Complete TechnologyFingerprint object
        """
        fingerprint = TechnologyFingerprint(url=url)

        try:
            session = await self._get_session()

            # Make request
            async with session.get(url, allow_redirects=True) as response:
                headers = dict(response.headers)
                cookies = {
                    cookie.key: cookie.value for cookie in response.cookies.values()
                }
                html = await response.text()

                # Detect web server
                fingerprint.web_server = self._detect_web_server(headers)

                # Detect backend
                fingerprint.backend = self._detect_backend(headers, cookies, html)

                # Detect frontend
                fingerprint.frontend = self._detect_frontend(html)

                # Detect authentication
                fingerprint.auth_mechanisms = self._detect_auth_mechanisms(
                    headers, cookies, html
                )

                # Detect WAF/CDN
                waf_cdn = self._detect_waf_cdn(headers, html)

                # Detect CMS
                fingerprint.cms = self._detect_cms(headers, html)

                # Analyze security headers
                security_headers = self._detect_security_headers(headers)

                # Detect cloud provider
                fingerprint.cloud_provider = self._detect_cloud_provider(headers, html)

                # Combine security info
                fingerprint.security = {
                    "waf_cdn": waf_cdn,
                    "security_headers": security_headers,
                }

                # Calculate confidence score
                total_detections = (
                    (1 if fingerprint.web_server["type"] else 0)
                    + (1 if fingerprint.backend["detected"] else 0)
                    + (1 if fingerprint.frontend["frameworks"] else 0)
                    + (1 if fingerprint.cms["detected"] else 0)
                )
                fingerprint.confidence_score = min(total_detections / 4, 1.0)

                # Add metadata
                fingerprint.metadata = {
                    "status_code": response.status,
                    "final_url": str(response.url),
                    "content_length": len(html),
                }

        except Exception as e:
            fingerprint.metadata = {"error": str(e), "status": "failed"}

        return fingerprint

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute tech stack fingerprinting based on workflow state.

        Args:
            state: Current workflow state

        Returns:
            Updated state with fingerprint results
        """
        try:
            # Extract URL from state
            url = state.get("url") or state.get("target_url")

            if not url:
                raise ValueError("No URL provided in state")

            # Add protocol if missing
            if not url.startswith(("http://", "https://")):
                url = f"https://{url}"

            # Perform fingerprinting
            fingerprint = await self.fingerprint(url)

            # Update state
            if "tech_fingerprint" not in state:
                state["tech_fingerprint"] = {}

            state["tech_fingerprint"] = fingerprint.to_dict()

            return state

        finally:
            await self._close_session()
