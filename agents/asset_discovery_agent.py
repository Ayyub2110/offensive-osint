"""
Asset Discovery Agent for attack surface enumeration.

This agent discovers subdomains, web assets, and hidden endpoints to map
the complete attack surface of a target domain. It uses multiple techniques
to uncover assets that may be vulnerable or provide additional entry points.

OFFENSIVE SECURITY USE CASES:
    - Attack surface mapping and expansion
    - Subdomain takeover identification
    - Finding forgotten/dev/staging environments
    - Discovering hidden admin panels and endpoints
    - Identifying S3 buckets, cloud resources, APIs
    - Locating backup files and sensitive directories

ATTACK SURFACE EXPANSION: More assets = more potential vulnerabilities
"""

import asyncio
import dns.resolver
import dns.exception
from typing import Dict, Any, List, Optional, Set
from dataclasses import dataclass, asdict
from datetime import datetime
from urllib.parse import urljoin, urlparse, urlunparse
import aiohttp
import re
import xml.etree.ElementTree as ET


@dataclass
class Asset:
    """
    Discovered asset/subdomain.

    Attributes:
        asset: Asset identifier (subdomain, URL, endpoint)
        asset_type: Type (subdomain, url, endpoint, file)
        source: Discovery source (wordlist, robots, sitemap, etc.)
        status_code: HTTP status code if applicable
        ip_addresses: Resolved IP addresses
        metadata: Additional metadata
        discovered_at: Discovery timestamp
    """

    asset: str
    asset_type: str
    source: str
    status_code: Optional[int] = None
    ip_addresses: List[str] = None
    metadata: Optional[Dict[str, Any]] = None
    discovered_at: Optional[str] = None

    def __post_init__(self):
        if self.ip_addresses is None:
            self.ip_addresses = []
        if self.metadata is None:
            self.metadata = {}
        if self.discovered_at is None:
            self.discovered_at = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)


class AssetDiscoveryAgent:
    """
    Asset discovery agent for attack surface enumeration.

    This agent maps the complete attack surface by discovering:
        - Subdomains (common names, patterns)
        - Web endpoints and directories
        - Hidden admin panels and dev environments
        - API endpoints and documentation
        - Backup files and sensitive resources
        - Cloud storage (S3, Azure, etc.)

    ATTACK STRATEGY:
        1. Subdomain enumeration (increases targets)
        2. robots.txt analysis (reveals restricted areas)
        3. sitemap.xml parsing (finds all public pages)
        4. HTTP header analysis (discovers technologies, redirects)
        5. Response body scanning (finds hidden links, APIs)

    Attributes:
        timeout: Request timeout in seconds
        dns_timeout: DNS query timeout
        max_concurrent: Maximum concurrent requests
        user_agent: User-Agent for HTTP requests
    """

    # Common subdomain wordlist for brute force enumeration
    # ATTACK RELEVANCE: These often host dev, staging, admin interfaces
    COMMON_SUBDOMAINS = [
        "www",
        "mail",
        "ftp",
        "localhost",
        "webmail",
        "smtp",
        "pop",
        "ns1",
        "webdisk",
        "ns2",
        "cpanel",
        "whm",
        "autodiscover",
        "autoconfig",
        "m",
        "imap",
        "test",
        "ns",
        "blog",
        "pop3",
        "dev",
        "www2",
        "admin",
        "forum",
        "news",
        "vpn",
        "ns3",
        "mail2",
        "new",
        "mysql",
        "old",
        "lists",
        "support",
        "mobile",
        "mx",
        "static",
        "docs",
        "beta",
        "shop",
        "sql",
        "secure",
        "demo",
        "cp",
        "calendar",
        "wiki",
        "web",
        "media",
        "email",
        "images",
        "img",
        "www1",
        "intranet",
        "portal",
        "video",
        "sip",
        "dns2",
        "api",
        "cdn",
        "stats",
        "dns1",
        "ns4",
        "www3",
        "dns",
        "search",
        "staging",
        "server",
        "mx1",
        "chat",
        "wap",
        "my",
        "svn",
        "mail1",
        "sites",
        "proxy",
        "ads",
        "host",
        "crm",
        "cms",
        "backup",
        "mx2",
        "lyncdiscover",
        "info",
        "apps",
        "download",
        "remote",
        "db",
        "forums",
        "store",
        "relay",
        "files",
        "newsletter",
        "app",
        "live",
        "owa",
        "en",
        "start",
        "sms",
        "office",
        "exchange",
        "ipv4",
        # High-value targets for exploitation
        "jenkins",
        "gitlab",
        "git",
        "bitbucket",
        "jira",
        "confluence",
        "phpmyadmin",
        "adminer",
        "grafana",
        "kibana",
        "prometheus",
        "docker",
        "kubernetes",
        "k8s",
        "rancher",
        "portainer",
        "sonarqube",
        "nexus",
        "artifactory",
        "registry",
        "elasticsearch",
        "rabbitmq",
        "redis",
        "mongodb",
        "s3",
        "bucket",
        "storage",
        "assets",
        "uploads",
    ]

    # Common backup file extensions and patterns
    # ATTACK RELEVANCE: Often contain source code, credentials, configs
    BACKUP_PATTERNS = [
        ".bak",
        ".backup",
        ".old",
        ".tmp",
        ".temp",
        ".save",
        ".swp",
        ".swo",
        "~",
        ".orig",
        ".copy",
    ]

    # Sensitive files to check
    # ATTACK RELEVANCE: Expose configuration, credentials, structure
    SENSITIVE_FILES = [
        "robots.txt",
        "sitemap.xml",
        "sitemap_index.xml",
        ".git/config",
        ".env",
        ".env.local",
        ".env.production",
        "web.config",
        "config.php",
        "configuration.php",
        "settings.py",
        "config.yml",
        "config.yaml",
        ".htaccess",
        ".htpasswd",
        "phpinfo.php",
        "info.php",
        "test.php",
        "admin.php",
        "login.php",
        "wp-admin/",
        "administrator/",
        "backup.sql",
        "dump.sql",
        "database.sql",
        "composer.json",
        "package.json",
        "Gemfile",
        "README.md",
        "CHANGELOG.md",
        "TODO.txt",
        "crossdomain.xml",
        "clientaccesspolicy.xml",
    ]

    def __init__(
        self,
        timeout: int = 10,
        dns_timeout: int = 5,
        max_concurrent: int = 10,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        """
        Initialize the Asset Discovery Agent.

        Args:
            timeout: HTTP request timeout in seconds
            dns_timeout: DNS query timeout in seconds
            max_concurrent: Maximum concurrent requests
            user_agent: User-Agent header for requests
        """
        self.timeout = timeout
        self.dns_timeout = dns_timeout
        self.max_concurrent = max_concurrent
        self.user_agent = user_agent

        # DNS resolver with public DNS fallback
        self.resolver = dns.resolver.Resolver()
        self.resolver.nameservers = ["8.8.8.8", "8.8.4.4"]
        self.resolver.timeout = dns_timeout
        self.resolver.lifetime = dns_timeout

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

    async def _resolve_dns(self, hostname: str) -> List[str]:
        """
        Resolve hostname to IP addresses.

        Args:
            hostname: Hostname to resolve

        Returns:
            List of IP addresses
        """
        try:
            answers = self.resolver.resolve(hostname, "A")
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.Timeout):
            return []
        except Exception:
            return []

    async def discover_subdomains(
        self, domain: str, wordlist: Optional[List[str]] = None
    ) -> List[Asset]:
        """
        Discover subdomains using DNS enumeration.

        ATTACK VALUE: Subdomains often host:
            - Dev/staging environments (weaker security)
            - Admin panels (privileged access)
            - Old versions (unpatched vulnerabilities)
            - APIs (authentication bypass potential)

        Args:
            domain: Base domain to enumerate
            wordlist: Custom subdomain wordlist (uses default if None)

        Returns:
            List of discovered subdomain assets
        """
        if wordlist is None:
            wordlist = self.COMMON_SUBDOMAINS

        assets = []
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_subdomain(sub: str):
            async with semaphore:
                subdomain = f"{sub}.{domain}"
                ip_addresses = await self._resolve_dns(subdomain)

                if ip_addresses:
                    assets.append(
                        Asset(
                            asset=subdomain,
                            asset_type="subdomain",
                            source="wordlist_enumeration",
                            ip_addresses=ip_addresses,
                            metadata={"subdomain_prefix": sub},
                        )
                    )

        # Check all subdomains concurrently
        tasks = [check_subdomain(sub) for sub in wordlist]
        await asyncio.gather(*tasks, return_exceptions=True)

        return assets

    async def parse_robots_txt(self, base_url: str) -> List[Asset]:
        """
        Parse robots.txt to discover restricted/sensitive paths.

        ATTACK GOLDMINE: robots.txt often reveals:
            - Admin panels (Disallow: /admin)
            - API endpoints (Disallow: /api/internal)
            - Backup directories (Disallow: /backups)
            - Development areas (Disallow: /dev)

        These "hidden" paths are primary targets for exploitation.

        Args:
            base_url: Base URL of the target

        Returns:
            List of discovered endpoint assets
        """
        assets = []
        robots_url = urljoin(base_url, "/robots.txt")

        try:
            session = await self._get_session()
            async with session.get(robots_url) as response:
                if response.status == 200:
                    content = await response.text()

                    # Parse Disallow and Allow directives
                    for line in content.splitlines():
                        line = line.strip()

                        # Extract paths from Disallow/Allow/Sitemap
                        if line.lower().startswith(("disallow:", "allow:")):
                            path = line.split(":", 1)[1].strip()
                            if path and path != "/":
                                full_url = urljoin(base_url, path)
                                assets.append(
                                    Asset(
                                        asset=full_url,
                                        asset_type="endpoint",
                                        source="robots.txt",
                                        metadata={
                                            "directive": line.split(":")[0].lower(),
                                            "path": path,
                                            "note": "Restricted in robots.txt - high value target",
                                        },
                                    )
                                )

                        elif line.lower().startswith("sitemap:"):
                            sitemap_url = line.split(":", 1)[1].strip()
                            assets.append(
                                Asset(
                                    asset=sitemap_url,
                                    asset_type="sitemap",
                                    source="robots.txt",
                                    metadata={"type": "sitemap_reference"},
                                )
                            )

        except Exception:
            pass  # robots.txt not found or error

        return assets

    async def parse_sitemap(self, sitemap_url: str) -> List[Asset]:
        """
        Parse sitemap.xml to discover all documented URLs.

        ATTACK BENEFIT: Sitemaps provide complete URL inventory.
        Useful for identifying all application endpoints and parameters.

        Args:
            sitemap_url: URL of the sitemap

        Returns:
            List of discovered URL assets
        """
        assets = []

        try:
            session = await self._get_session()
            async with session.get(sitemap_url) as response:
                if response.status == 200:
                    content = await response.text()

                    try:
                        # Parse XML
                        root = ET.fromstring(content)

                        # Handle namespace
                        ns = {"ns": "http://www.sitemaps.org/schemas/sitemap/0.9"}

                        # Extract URLs from <loc> tags
                        for loc in root.findall(".//ns:loc", ns):
                            url = loc.text
                            if url:
                                assets.append(
                                    Asset(
                                        asset=url,
                                        asset_type="url",
                                        source="sitemap.xml",
                                        metadata={"sitemap_source": sitemap_url},
                                    )
                                )

                        # Also check for sitemap index files
                        for sitemap in root.findall(".//ns:sitemap/ns:loc", ns):
                            sub_sitemap_url = sitemap.text
                            if sub_sitemap_url and sub_sitemap_url != sitemap_url:
                                # Recursively parse sub-sitemaps
                                sub_assets = await self.parse_sitemap(sub_sitemap_url)
                                assets.extend(sub_assets)

                    except ET.ParseError:
                        # Not valid XML, might be text-based sitemap
                        for line in content.splitlines():
                            line = line.strip()
                            if line.startswith("http"):
                                assets.append(
                                    Asset(
                                        asset=line,
                                        asset_type="url",
                                        source="sitemap.xml",
                                        metadata={"format": "text"},
                                    )
                                )

        except Exception:
            pass  # Sitemap not found or error

        return assets

    async def discover_sensitive_files(self, base_url: str) -> List[Asset]:
        """
        Check for common sensitive files and directories.

        ATTACK PRIORITY: These files often contain:
            - Source code (.git/config)
            - Credentials (.env files)
            - Database dumps (.sql files)
            - Configuration (web.config, settings.py)

        Args:
            base_url: Base URL to check

        Returns:
            List of discovered sensitive file assets
        """
        assets = []
        session = await self._get_session()
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def check_file(file_path: str):
            async with semaphore:
                url = urljoin(base_url, file_path)
                try:
                    async with session.head(url, allow_redirects=False) as response:
                        # Consider 200, 403 (forbidden but exists), and some 3xx as indicators
                        if response.status in [200, 403]:
                            assets.append(
                                Asset(
                                    asset=url,
                                    asset_type="sensitive_file",
                                    source="file_enumeration",
                                    status_code=response.status,
                                    metadata={
                                        "file_path": file_path,
                                        "risk": "high"
                                        if response.status == 200
                                        else "medium",
                                    },
                                )
                            )
                except Exception:
                    pass

        # Check all sensitive files
        tasks = [check_file(file_path) for file_path in self.SENSITIVE_FILES]
        await asyncio.gather(*tasks, return_exceptions=True)

        return assets

    async def analyze_http_response(self, url: str) -> List[Asset]:
        """
        Analyze HTTP response for asset discovery hints.

        Extracts information from:
            - HTTP headers (Server, X-Powered-By, CSP, etc.)
            - Response body (links, API endpoints, comments)
            - Redirects (alternate domains/endpoints)

        Args:
            url: URL to analyze

        Returns:
            List of discovered assets from response analysis
        """
        assets = []

        try:
            session = await self._get_session()
            async with session.get(url, allow_redirects=True) as response:
                # Extract from headers
                headers_of_interest = [
                    "Server",
                    "X-Powered-By",
                    "X-AspNet-Version",
                    "X-Generator",
                    "X-Drupal-Cache",
                    "X-Varnish",
                    "Link",
                    "Location",
                    "Content-Security-Policy",
                ]

                for header in headers_of_interest:
                    if header in response.headers:
                        assets.append(
                            Asset(
                                asset=response.headers[header],
                                asset_type="technology",
                                source="http_headers",
                                metadata={"header": header, "url": url},
                            )
                        )

                # Extract URLs from response body
                if response.status == 200:
                    content = await response.text()

                    # Find URLs in content (simple regex)
                    url_pattern = r'https?://[^\s<>"\']+|/[^\s<>"\']*'
                    found_urls = re.findall(url_pattern, content)

                    for found_url in set(found_urls[:100]):  # Limit to avoid spam
                        if found_url.startswith("http"):
                            full_url = found_url
                        else:
                            full_url = urljoin(url, found_url)

                        # Only include if same domain
                        if urlparse(url).netloc == urlparse(full_url).netloc:
                            assets.append(
                                Asset(
                                    asset=full_url,
                                    asset_type="url",
                                    source="response_body",
                                    metadata={"found_in": url},
                                )
                            )

        except Exception:
            pass

        return assets

    def _normalize_asset(self, asset: Asset) -> str:
        """
        Normalize asset for deduplication.

        Args:
            asset: Asset to normalize

        Returns:
            Normalized asset string
        """
        asset_str = asset.asset.lower().strip()

        # Normalize URLs
        if asset.asset_type in ["url", "endpoint"]:
            parsed = urlparse(asset_str)
            # Remove default ports
            netloc = parsed.netloc
            if ":80" in netloc or ":443" in netloc:
                netloc = netloc.replace(":80", "").replace(":443", "")

            # Rebuild without fragment
            normalized = urlunparse(
                (
                    parsed.scheme,
                    netloc,
                    parsed.path.rstrip("/"),
                    parsed.params,
                    parsed.query,
                    "",  # Remove fragment
                )
            )
            return normalized

        return asset_str

    def _deduplicate_assets(self, assets: List[Asset]) -> List[Asset]:
        """
        Remove duplicate assets.

        Args:
            assets: List of assets to deduplicate

        Returns:
            Deduplicated list of assets
        """
        seen = set()
        unique_assets = []

        for asset in assets:
            normalized = self._normalize_asset(asset)
            if normalized not in seen:
                seen.add(normalized)
                unique_assets.append(asset)

        return unique_assets

    async def discover_assets(
        self,
        domain: str,
        include_subdomains: bool = True,
        include_files: bool = True,
        custom_wordlist: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Comprehensive asset discovery for a domain.

        COMPLETE ATTACK SURFACE MAPPING:
            1. Enumerate subdomains (expand targets)
            2. Parse robots.txt (find restricted areas)
            3. Parse sitemaps (discover all endpoints)
            4. Check sensitive files (find misconfigurations)
            5. Analyze responses (extract technologies, links)

        Args:
            domain: Target domain
            include_subdomains: Whether to enumerate subdomains
            include_files: Whether to check for sensitive files
            custom_wordlist: Custom subdomain wordlist

        Returns:
            Comprehensive asset discovery results
        """
        all_assets = []

        # Determine base URL
        base_url = f"https://{domain}"

        # 1. Subdomain enumeration
        if include_subdomains:
            subdomain_assets = await self.discover_subdomains(domain, custom_wordlist)
            all_assets.extend(subdomain_assets)

        # 2. robots.txt parsing
        robots_assets = await self.parse_robots_txt(base_url)
        all_assets.extend(robots_assets)

        # 3. sitemap.xml parsing
        sitemap_url = urljoin(base_url, "/sitemap.xml")
        sitemap_assets = await self.parse_sitemap(sitemap_url)
        all_assets.extend(sitemap_assets)

        # Also try sitemap_index.xml
        sitemap_index_url = urljoin(base_url, "/sitemap_index.xml")
        sitemap_index_assets = await self.parse_sitemap(sitemap_index_url)
        all_assets.extend(sitemap_index_assets)

        # 4. Sensitive file discovery
        if include_files:
            file_assets = await self.discover_sensitive_files(base_url)
            all_assets.extend(file_assets)

        # 5. HTTP response analysis
        response_assets = await self.analyze_http_response(base_url)
        all_assets.extend(response_assets)

        # Deduplicate
        unique_assets = self._deduplicate_assets(all_assets)

        # Categorize by type
        categorized = {}
        for asset in unique_assets:
            asset_type = asset.asset_type
            if asset_type not in categorized:
                categorized[asset_type] = []
            categorized[asset_type].append(asset.to_dict())

        return {
            "domain": domain,
            "total_assets": len(unique_assets),
            "assets": [asset.to_dict() for asset in unique_assets],
            "categorized": categorized,
            "summary": {
                asset_type: len(assets) for asset_type, assets in categorized.items()
            },
            "timestamp": datetime.utcnow().isoformat(),
        }

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute asset discovery based on workflow state.

        Args:
            state: Current workflow state

        Returns:
            Updated state with asset discovery results
        """
        try:
            # Extract domain from state
            domain = state.get("domain") or state.get("target")

            if not domain:
                raise ValueError("No domain provided in state")

            # Clean domain (remove protocol if present)
            domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

            # Perform asset discovery
            results = await self.discover_assets(
                domain,
                include_subdomains=state.get("include_subdomains", True),
                include_files=state.get("include_sensitive_files", True),
            )

            # Update state
            if "asset_discovery" not in state:
                state["asset_discovery"] = {}

            state["asset_discovery"] = results

            return state

        finally:
            await self._close_session()
