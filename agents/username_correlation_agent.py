"""
Username Correlation Agent for cross-platform username enumeration.

This agent performs username correlation across multiple social media and
development platforms to identify potential user accounts associated with
a given username. Uses non-intrusive HTTP checks based on status codes
and redirect patterns.

IMPORTANT: This tool performs only basic availability checks using public
endpoints. It does not scrape content or violate platform Terms of Service.
"""

import asyncio
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import aiohttp
from datetime import datetime


class PlatformStatus(Enum):
    """Status of username check on a platform."""

    EXISTS = "exists"
    NOT_FOUND = "not_found"
    UNCERTAIN = "uncertain"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class PlatformResult:
    """
    Result of username check on a single platform.

    Attributes:
        platform: Name of the platform
        username: Username checked
        status: Check status (exists, not_found, etc.)
        url: Profile URL if exists
        status_code: HTTP status code received
        response_time_ms: Response time in milliseconds
        timestamp: Check timestamp
        notes: Additional information or error details
    """

    platform: str
    username: str
    status: PlatformStatus
    url: Optional[str] = None
    status_code: Optional[int] = None
    response_time_ms: Optional[float] = None
    timestamp: Optional[str] = None
    notes: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with serializable values."""
        data = asdict(self)
        data["status"] = self.status.value
        return data


class UsernameCorrelationAgent:
    """
    Username correlation agent for multi-platform username enumeration.

    This agent checks username availability across various platforms using
    HTTP status codes and redirect patterns. It performs only basic checks
    that respect platform ToS by not scraping content.

    Supported Platforms:
        - GitHub: Developer platform
        - Reddit: Social news platform
        - Twitter/X: Microblogging platform (basic check)
        - Instagram: Photo sharing platform (basic check)

    Attributes:
        timeout: Request timeout in seconds
        max_concurrent: Maximum concurrent requests
        user_agent: User-Agent header for requests
    """

    # Platform configurations
    PLATFORMS = {
        "github": {
            "url_template": "https://github.com/{username}",
            "method": "GET",
            "exists_codes": [200],
            "not_found_codes": [404],
        },
        "reddit": {
            "url_template": "https://www.reddit.com/user/{username}/about.json",
            "method": "GET",
            "exists_codes": [200],
            "not_found_codes": [404],
        },
        "twitter": {
            "url_template": "https://twitter.com/{username}",
            "method": "GET",
            "exists_codes": [200],
            "not_found_codes": [404],
            # Note: Twitter may return other codes, this is a basic check
        },
        "instagram": {
            "url_template": "https://www.instagram.com/{username}/",
            "method": "HEAD",
            "exists_codes": [200],
            "not_found_codes": [404],
            # Note: Instagram may block automated requests, use with caution
        },
    }

    def __init__(
        self,
        timeout: int = 10,
        max_concurrent: int = 5,
        user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    ):
        """
        Initialize the Username Correlation Agent.

        Args:
            timeout: Request timeout in seconds (default: 10)
            max_concurrent: Maximum concurrent requests (default: 5)
            user_agent: User-Agent string for HTTP requests
        """
        self.timeout = timeout
        self.max_concurrent = max_concurrent
        self.user_agent = user_agent
        self._session: Optional[aiohttp.ClientSession] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """
        Get or create aiohttp session with SSL configuration.

        Returns:
            Active aiohttp ClientSession
        """
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            headers = {
                "User-Agent": self.user_agent,
                "Accept": "text/html,application/json,*/*",
                "Accept-Language": "en-US,en;q=0.9",
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
        """Close the aiohttp session if open."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    async def _check_platform(
        self, username: str, platform: str, config: Dict[str, Any]
    ) -> PlatformResult:
        """
        Check username existence on a specific platform.

        Args:
            username: Username to check
            platform: Platform name
            config: Platform configuration

        Returns:
            PlatformResult with check status and details
        """
        start_time = asyncio.get_event_loop().time()
        url = config["url_template"].format(username=username)

        try:
            session = await self._get_session()
            method = config.get("method", "GET")

            # Perform HTTP request
            if method == "HEAD":
                async with session.head(url, allow_redirects=True) as response:
                    status_code = response.status
                    final_url = str(response.url)
            else:
                async with session.get(url, allow_redirects=True) as response:
                    status_code = response.status
                    final_url = str(response.url)

            # Calculate response time
            response_time = (asyncio.get_event_loop().time() - start_time) * 1000

            # Determine status based on status code
            status = self._interpret_status_code(
                status_code,
                config.get("exists_codes", [200]),
                config.get("not_found_codes", [404]),
            )

            # Check for suspicious redirects
            if final_url != url and status == PlatformStatus.EXISTS:
                # Some platforms redirect to login or error pages
                if any(
                    keyword in final_url.lower()
                    for keyword in ["login", "signin", "error", "suspended"]
                ):
                    status = PlatformStatus.UNCERTAIN
                    notes = "Redirected to suspicious page"
                else:
                    notes = f"Redirected to {final_url}"
            else:
                notes = None

            return PlatformResult(
                platform=platform,
                username=username,
                status=status,
                url=url if status == PlatformStatus.EXISTS else None,
                status_code=status_code,
                response_time_ms=round(response_time, 2),
                timestamp=datetime.utcnow().isoformat(),
                notes=notes,
            )

        except asyncio.TimeoutError:
            return PlatformResult(
                platform=platform,
                username=username,
                status=PlatformStatus.TIMEOUT,
                url=url,
                timestamp=datetime.utcnow().isoformat(),
                notes=f"Request timeout after {self.timeout}s",
            )

        except aiohttp.ClientError as e:
            return PlatformResult(
                platform=platform,
                username=username,
                status=PlatformStatus.ERROR,
                url=url,
                timestamp=datetime.utcnow().isoformat(),
                notes=f"Client error: {str(e)}",
            )

        except Exception as e:
            return PlatformResult(
                platform=platform,
                username=username,
                status=PlatformStatus.ERROR,
                url=url,
                timestamp=datetime.utcnow().isoformat(),
                notes=f"Unexpected error: {str(e)}",
            )

    def _interpret_status_code(
        self, status_code: int, exists_codes: List[int], not_found_codes: List[int]
    ) -> PlatformStatus:
        """
        Interpret HTTP status code to determine username existence.

        Args:
            status_code: HTTP status code
            exists_codes: List of codes indicating existence
            not_found_codes: List of codes indicating not found

        Returns:
            PlatformStatus based on status code
        """
        if status_code in exists_codes:
            return PlatformStatus.EXISTS
        elif status_code in not_found_codes:
            return PlatformStatus.NOT_FOUND
        elif 500 <= status_code < 600:
            return PlatformStatus.ERROR
        else:
            return PlatformStatus.UNCERTAIN

    async def check_username(
        self, username: str, platforms: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Check username across multiple platforms.

        Args:
            username: Username to check
            platforms: List of platform names to check (default: all)

        Returns:
            Dictionary containing:
                - username: Checked username
                - results: List of platform results
                - summary: Summary statistics
                - timestamp: Check timestamp
        """
        if not username or not username.strip():
            raise ValueError("Username cannot be empty")

        username = username.strip()

        # Determine which platforms to check
        if platforms is None:
            platforms = list(self.PLATFORMS.keys())
        else:
            # Validate platform names
            invalid = set(platforms) - set(self.PLATFORMS.keys())
            if invalid:
                raise ValueError(f"Invalid platforms: {invalid}")

        # Create tasks for concurrent checking
        tasks = []
        for platform in platforms:
            config = self.PLATFORMS[platform]
            task = self._check_platform(username, platform, config)
            tasks.append(task)

        # Execute checks with concurrency limit
        semaphore = asyncio.Semaphore(self.max_concurrent)

        async def bounded_check(task):
            async with semaphore:
                return await task

        results = await asyncio.gather(*[bounded_check(task) for task in tasks])

        # Generate summary statistics
        summary = self._generate_summary(results)

        return {
            "username": username,
            "platforms_checked": len(platforms),
            "results": [result.to_dict() for result in results],
            "summary": summary,
            "timestamp": datetime.utcnow().isoformat(),
        }

    def _generate_summary(self, results: List[PlatformResult]) -> Dict[str, Any]:
        """
        Generate summary statistics from results.

        Args:
            results: List of platform results

        Returns:
            Summary dictionary with counts and statistics
        """
        summary = {
            "total": len(results),
            "exists": 0,
            "not_found": 0,
            "uncertain": 0,
            "errors": 0,
            "timeouts": 0,
            "platforms_found": [],
            "avg_response_time_ms": 0.0,
        }

        response_times = []

        for result in results:
            if result.status == PlatformStatus.EXISTS:
                summary["exists"] += 1
                summary["platforms_found"].append(result.platform)
            elif result.status == PlatformStatus.NOT_FOUND:
                summary["not_found"] += 1
            elif result.status == PlatformStatus.UNCERTAIN:
                summary["uncertain"] += 1
            elif result.status == PlatformStatus.ERROR:
                summary["errors"] += 1
            elif result.status == PlatformStatus.TIMEOUT:
                summary["timeouts"] += 1

            if result.response_time_ms is not None:
                response_times.append(result.response_time_ms)

        if response_times:
            summary["avg_response_time_ms"] = round(
                sum(response_times) / len(response_times), 2
            )

        return summary

    async def execute(self, state: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute username correlation based on workflow state.

        This method integrates with the LangGraph workflow, extracting
        username from state and updating state with correlation results.

        Args:
            state: Current workflow state

        Returns:
            Updated state with username correlation data
        """
        try:
            # Extract username from state
            username = state.get("username") or state.get("target")

            if not username:
                raise ValueError("No username provided in state")

            # Perform username correlation
            results = await self.check_username(username)

            # Update state
            if "username_correlation" not in state:
                state["username_correlation"] = {}

            state["username_correlation"] = results

            return state

        finally:
            # Clean up session
            await self._close_session()

    async def batch_check_usernames(
        self, usernames: List[str], platforms: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        """
        Check multiple usernames across platforms.

        Args:
            usernames: List of usernames to check
            platforms: List of platforms to check (default: all)

        Returns:
            List of results for each username
        """
        try:
            tasks = [self.check_username(username, platforms) for username in usernames]
            results = await asyncio.gather(*tasks, return_exceptions=True)

            # Convert exceptions to error dictionaries
            processed_results = []
            for i, result in enumerate(results):
                if isinstance(result, Exception):
                    processed_results.append(
                        {
                            "username": usernames[i],
                            "error": str(result),
                            "timestamp": datetime.utcnow().isoformat(),
                        }
                    )
                else:
                    processed_results.append(result)

            return processed_results

        finally:
            await self._close_session()

    def __del__(self):
        """Cleanup on deletion."""
        if self._session and not self._session.closed:
            # Schedule session close if event loop is running
            try:
                loop = asyncio.get_event_loop()
                if loop.is_running():
                    asyncio.create_task(self._close_session())
            except RuntimeError:
                pass
