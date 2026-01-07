"""TIDAL API client for authentication and data retrieval.

This module provides async API access to TIDAL's music streaming service,
supporting multiple session types (TV, Mobile) for different audio formats.
"""

import base64
import hashlib
import secrets
from abc import ABC, abstractmethod
from datetime import UTC, datetime, timedelta
from enum import Enum, auto
from typing import Any
from urllib.parse import parse_qs, urlparse

import msgspec
from aiohttp import ClientResponseError, ClientSession
from yarl import URL

from haberlea.utils.exceptions import ModuleAPIError, ModuleAuthError
from haberlea.utils.utils import create_aiohttp_session


class SessionType(Enum):
    """TIDAL session types for different audio format access."""

    TV = auto()
    MOBILE_ATMOS = auto()
    MOBILE_DEFAULT = auto()


class TidalSession(ABC):
    """Abstract base class for TIDAL session management.

    Handles OAuth token storage, refresh, and authentication headers.
    """

    TIDAL_AUTH_BASE: str
    client_id: str

    def __init__(self) -> None:
        """Initialize session with empty credentials."""
        self.access_token: str | None = None
        self.refresh_token: str | None = None
        self.expires: datetime | None = None
        self.user_id: str | None = None
        self.country_code: str | None = None
        self.session: ClientSession = create_aiohttp_session()

    def set_storage(self, storage: dict[str, Any]) -> None:
        """Load session data from storage dictionary.

        Args:
            storage: Dictionary containing session credentials.
        """
        self.access_token = storage.get("access_token")
        self.refresh_token = storage.get("refresh_token")
        expires = storage.get("expires")
        if isinstance(expires, str):
            self.expires = datetime.fromisoformat(expires)
        else:
            self.expires = expires
        self.user_id = storage.get("user_id")
        self.country_code = storage.get("country_code")

    def get_storage(self) -> dict[str, Any]:
        """Export session data to storage dictionary.

        Returns:
            Dictionary containing session credentials.
        """
        return {
            "access_token": self.access_token,
            "refresh_token": self.refresh_token,
            "expires": self.expires.isoformat() if self.expires else None,
            "user_id": self.user_id,
            "country_code": self.country_code,
        }

    async def get_subscription(self) -> str:
        """Get the user's subscription type.

        Returns:
            Subscription type string (e.g., "HIFI", "PREMIUM").

        Raises:
            ModuleAuthError: If the request fails.
        """
        if not self.access_token:
            raise ModuleAuthError(module_name="tidal")

        url = f"https://api.tidal.com/v1/users/{self.user_id}/subscription"
        params: dict[str, str] = {}
        if self.country_code:
            params["countryCode"] = self.country_code

        async with self.session.get(
            url, params=params, headers=self.auth_headers
        ) as response:
            if response.status != 200:
                raise ModuleAuthError(module_name="tidal")
            data = msgspec.json.decode(await response.read())
            return data["subscription"]["type"]

    @property
    @abstractmethod
    def auth_headers(self) -> dict[str, str]:
        """Authentication headers for API requests.

        Returns:
            Dictionary of HTTP headers.
        """
        ...

    async def valid(self) -> bool:
        """Check if the session is still valid.

        Returns:
            True if session is valid, False otherwise.
        """
        if self.access_token is None:
            return False
        if self.expires and datetime.now(UTC) > self.expires.replace(tzinfo=UTC):
            return False

        try:
            async with self.session.get(
                "https://api.tidal.com/v1/sessions", headers=self.auth_headers
            ) as response:
                return response.status == 200
        except Exception:
            return False

    @property
    def _refresh_extra_data(self) -> dict[str, str]:
        """Extra data fields for refresh token request.

        Override in subclasses to provide additional fields like client_secret.
        """
        return {}

    async def refresh_session(self) -> bool:
        """Refresh the session tokens.

        Returns:
            True if refresh was successful, False otherwise.
        """
        if not self.refresh_token:
            return False

        data = {
            "refresh_token": self.refresh_token,
            "client_id": self.client_id,
            "grant_type": "refresh_token",
            **self._refresh_extra_data,
        }

        async with self.session.post(
            f"{self.TIDAL_AUTH_BASE}oauth2/token",
            data=data,
        ) as response:
            if response.status != 200:
                return False
            resp_data = msgspec.json.decode(await response.read())
            self._update_tokens_from_response(resp_data)
            return True

    def _update_tokens_from_response(self, data: dict[str, Any]) -> None:
        """Update tokens from OAuth response data.

        Args:
            data: OAuth response containing tokens and expiry.
        """
        self.access_token = data["access_token"]
        self.expires = datetime.now(UTC) + timedelta(seconds=data["expires_in"])
        if "refresh_token" in data:
            self.refresh_token = data["refresh_token"]


class TidalMobileSession(TidalSession):
    """TIDAL session using mobile Android OAuth flow."""

    SESSION_TYPE = "Mobile"
    TIDAL_LOGIN_BASE = "https://login.tidal.com/api/"
    TIDAL_AUTH_BASE = "https://auth.tidal.com/v1/"

    def __init__(self, client_token: str) -> None:
        """Initialize mobile session.

        Args:
            client_token: TIDAL client token for mobile API.
        """
        super().__init__()
        self.client_id = client_token
        self.redirect_uri = "https://tidal.com/android/login/auth"
        self.code_verifier = base64.urlsafe_b64encode(secrets.token_bytes(32)).rstrip(
            b"="
        )
        self.code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(self.code_verifier).digest()
        ).rstrip(b"=")
        self.client_unique_key = secrets.token_hex(8)
        self.user_agent = (
            "Mozilla/5.0 (Linux; Android 13; Pixel 8 Build/TQ2A.230505.002; wv) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/119.0.6045.163 "
            "Mobile Safari/537.36"
        )

    async def _get_datadome_cookie(self) -> tuple[str, str]:
        """Get DataDome cookie for bot protection.

        Returns:
            Tuple of (cookie_name, cookie_value).

        Raises:
            ModuleAuthError: If cookie retrieval fails.
        """
        dd_data = {
            "jsData": (
                f'{{"opts":"endpoint,ajaxListenerPath","ua":"{self.user_agent}"}}'
            ),
            "ddk": "1F633CDD8EF22541BD6D9B1B8EF13A",
            "Referer": "https%3A%2F%2Ftidal.com%2F",
            "responsePage": "origin",
            "ddv": "4.17.0",
        }

        async with self.session.post(
            "https://dd.tidal.com/js/",
            data=dd_data,
            headers={
                "user-agent": self.user_agent,
                "content-type": "application/x-www-form-urlencoded",
            },
        ) as response:
            if response.status != 200:
                raise ModuleAuthError(module_name="tidal")
            data = msgspec.json.decode(await response.read())
            if not data.get("cookie"):
                raise ModuleAuthError(module_name="tidal")
            dd_cookie = data["cookie"].split(";")[0]
            return dd_cookie.split("=", 1)

    async def _get_csrf_token(self, params: dict[str, str]) -> str:
        """Get CSRF token from login page.

        Args:
            params: OAuth parameters.

        Returns:
            CSRF token value.

        Raises:
            ModuleAuthError: If CSRF token retrieval fails.
        """
        async with self.session.get(
            "https://login.tidal.com/authorize",
            params=params,
            headers={
                "user-agent": self.user_agent,
                "accept-language": "en-US",
                "x-requested-with": "com.aspiro.tidal",
            },
        ) as response:
            if response.status in (400, 403):
                raise ModuleAuthError(module_name="tidal")

        csrf_token = self.session.cookie_jar.filter_cookies(
            URL("https://login.tidal.com")
        ).get("_csrf-token")
        if not csrf_token:
            raise ModuleAuthError(module_name="tidal")
        return csrf_token.value

    async def _verify_email(
        self, params: dict[str, str], username: str, csrf_token: str
    ) -> None:
        """Verify email address.

        Args:
            params: OAuth parameters.
            username: User email.
            csrf_token: CSRF token.

        Raises:
            ModuleAuthError: If email verification fails.
        """
        async with self.session.post(
            f"{self.TIDAL_LOGIN_BASE}email",
            params=params,
            json={"email": username},
            headers={
                "user-agent": self.user_agent,
                "x-csrf-token": csrf_token,
                "accept": "application/json, text/plain, */*",
                "content-type": "application/json",
                "accept-language": "en-US",
                "x-requested-with": "com.aspiro.tidal",
            },
        ) as response:
            if response.status != 200:
                raise ModuleAuthError(module_name="tidal")
            data = msgspec.json.decode(await response.read())
            if not data.get("isValidEmail") or data.get("newUser"):
                raise ModuleAuthError(module_name="tidal")

    async def _login_with_credentials(
        self, params: dict[str, str], username: str, password: str, csrf_token: str
    ) -> None:
        """Login with username and password.

        Args:
            params: OAuth parameters.
            username: User email.
            password: User password.
            csrf_token: CSRF token.

        Raises:
            ModuleAuthError: If login fails.
        """
        async with self.session.post(
            f"{self.TIDAL_LOGIN_BASE}email/user/existing",
            params=params,
            json={"email": username, "password": password},
            headers={
                "User-Agent": self.user_agent,
                "x-csrf-token": csrf_token,
                "accept": "application/json, text/plain, */*",
                "content-type": "application/json",
                "accept-language": "en-US",
                "x-requested-with": "com.aspiro.tidal",
            },
        ) as response:
            if response.status != 200:
                raise ModuleAuthError(module_name="tidal")

    async def _get_oauth_code(self) -> str:
        """Get OAuth authorization code.

        Returns:
            OAuth authorization code.

        Raises:
            ModuleAuthError: If code retrieval fails.
        """
        async with self.session.get(
            "https://login.tidal.com/success",
            allow_redirects=False,
            headers={
                "user-agent": self.user_agent,
                "accept-language": "en-US",
                "x-requested-with": "com.aspiro.tidal",
            },
        ) as response:
            if response.status == 401 or response.status != 302:
                raise ModuleAuthError(module_name="tidal")
            location = response.headers.get("location", "")
            url = urlparse(location)
            oauth_code = parse_qs(url.query).get("code", [None])[0]
            if not oauth_code:
                raise ModuleAuthError(module_name="tidal")
            return oauth_code

    async def _exchange_code_for_token(self, oauth_code: str) -> None:
        """Exchange OAuth code for access token.

        Args:
            oauth_code: OAuth authorization code.

        Raises:
            ModuleAuthError: If token exchange fails.
        """
        async with self.session.post(
            f"{self.TIDAL_AUTH_BASE}oauth2/token",
            data={
                "code": oauth_code,
                "client_id": self.client_id,
                "grant_type": "authorization_code",
                "redirect_uri": self.redirect_uri,
                "scope": "r_usr w_usr w_sub",
                "code_verifier": self.code_verifier.decode(),
                "client_unique_key": self.client_unique_key,
            },
            headers={"User-Agent": self.user_agent},
        ) as response:
            if response.status != 200:
                raise ModuleAuthError(module_name="tidal")
            data = msgspec.json.decode(await response.read())
            self._update_tokens_from_response(data)

    async def _fetch_user_info(self) -> None:
        """Fetch user information.

        Raises:
            ModuleAuthError: If user info retrieval fails.
        """
        async with self.session.get(
            "https://api.tidal.com/v1/sessions", headers=self.auth_headers
        ) as response:
            if response.status != 200:
                raise ModuleAuthError(module_name="tidal")
            data = msgspec.json.decode(await response.read())
            self.user_id = str(data["userId"])
            self.country_code = data["countryCode"]

    async def auth(self, username: str, password: str) -> None:
        """Authenticate with username and password.

        Args:
            username: TIDAL account email.
            password: TIDAL account password.

        Raises:
            ModuleAuthError: If authentication fails.
        """
        # Get DataDome cookie for bot protection
        cookie_name, cookie_value = await self._get_datadome_cookie()
        self.session.cookie_jar.update_cookies({cookie_name: cookie_value})

        # Prepare OAuth parameters
        params: dict[str, str] = {
            "response_type": "code",
            "redirect_uri": self.redirect_uri,
            "lang": "en_US",
            "appMode": "android",
            "client_id": self.client_id,
            "client_unique_key": self.client_unique_key,
            "code_challenge": self.code_challenge.decode(),
            "code_challenge_method": "S256",
            "restrict_signup": "true",
        }

        # Get CSRF token
        csrf_token = await self._get_csrf_token(params)

        # Verify email
        await self._verify_email(params, username, csrf_token)

        # Login with credentials
        await self._login_with_credentials(params, username, password, csrf_token)

        # Get OAuth authorization code
        oauth_code = await self._get_oauth_code()

        # Exchange code for token
        await self._exchange_code_for_token(oauth_code)

        # Get user info
        await self._fetch_user_info()

    @property
    def auth_headers(self) -> dict[str, str]:
        """Authentication headers for API requests."""
        return {
            "Host": "api.tidal.com",
            "X-Tidal-Token": self.client_id,
            "Authorization": f"Bearer {self.access_token}",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "User-Agent": "TIDAL_ANDROID/1039 okhttp/3.14.9",
        }


class TidalTvSession(TidalSession):
    """TIDAL session using AndroidTV OAuth flow."""

    SESSION_TYPE = "Tv"
    TIDAL_AUTH_BASE = "https://auth.tidal.com/v1/"

    def __init__(self, client_token: str, client_secret: str) -> None:
        """Initialize TV session.

        Args:
            client_token: TIDAL client token for TV API.
            client_secret: TIDAL client secret for TV API.
        """
        super().__init__()
        self.client_id = client_token
        self.client_secret = client_secret

    async def auth(self, username: str = "", password: str = "") -> tuple[str, str]:
        """Start device authorization flow.

        Args:
            username: Unused for TV auth.
            password: Unused for TV auth.

        Returns:
            Tuple of (device_code, user_code) for user to complete auth.

        Raises:
            ModuleAuthError: If authorization request fails.
        """
        async with self.session.post(
            f"{self.TIDAL_AUTH_BASE}oauth2/device_authorization",
            data={"client_id": self.client_id, "scope": "r_usr w_usr"},
        ) as response:
            if response.status != 200:
                raise ModuleAuthError(module_name="tidal")
            data = msgspec.json.decode(await response.read())
            return data["deviceCode"], data["userCode"]

    async def check_auth(self, device_code: str) -> bool:
        """Check if device authorization is complete.

        Args:
            device_code: Device code from auth() call.

        Returns:
            True if authorization is complete.
        """
        async with self.session.post(
            f"{self.TIDAL_AUTH_BASE}oauth2/token",
            data={
                "client_id": self.client_id,
                "device_code": device_code,
                "client_secret": self.client_secret,
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "scope": "r_usr w_usr",
            },
        ) as response:
            if response.status == 400:
                return False
            if response.status != 200:
                return False
            data = msgspec.json.decode(await response.read())
            self._update_tokens_from_response(data)

        # Get user info
        async with self.session.get(
            "https://api.tidal.com/v1/sessions", headers=self.auth_headers
        ) as response:
            if response.status != 200:
                return False
            data = msgspec.json.decode(await response.read())
            self.user_id = str(data["userId"])
            self.country_code = data["countryCode"]
            return True

    @property
    def _refresh_extra_data(self) -> dict[str, str]:
        """Extra data including client_secret for TV session refresh."""
        return {"client_secret": self.client_secret}

    @property
    def auth_headers(self) -> dict[str, str]:
        """Authentication headers for API requests."""
        return {
            "X-Tidal-Token": self.client_id,
            "Authorization": f"Bearer {self.access_token}",
            "Connection": "Keep-Alive",
            "Accept-Encoding": "gzip",
            "User-Agent": "TIDAL_ANDROID/1039 okhttp/3.14.9",
        }


class TidalApi:
    """TIDAL API client for data retrieval.

    Manages multiple sessions and provides async access to TIDAL's API endpoints.

    Attributes:
        sessions: Dictionary of session type to TidalSession instances.
        default: Current default session type for API calls.
    """

    TIDAL_API_BASE = "https://api.tidal.com/v1/"

    def __init__(
        self, sessions: dict[str, TidalTvSession | TidalMobileSession]
    ) -> None:
        """Initialize the API client.

        Args:
            sessions: Dictionary mapping session type names to TidalSession instances.
        """
        self.sessions = sessions
        self.default: SessionType = SessionType.TV
        self._session: ClientSession | None = None

    async def _ensure_session(self) -> ClientSession:
        """Ensure aiohttp session exists.

        Returns:
            Active aiohttp ClientSession.
        """
        if self._session is None or self._session.closed:
            self._session = create_aiohttp_session()
        return self._session

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self._session and not self._session.closed:
            await self._session.close()
        for session in self.sessions.values():
            if session.session and not session.session.closed:
                await session.session.close()

    def _prepare_request_params(
        self, params: dict[str, Any], current_session: TidalSession
    ) -> dict[str, Any]:
        """Prepare request parameters with defaults.

        Args:
            params: Original query parameters.
            current_session: Current TIDAL session.

        Returns:
            Updated parameters dictionary.
        """
        params["countryCode"] = current_session.country_code
        if "limit" not in params:
            params["limit"] = "9999"
        return params

    def _check_response_errors(
        self, resp_json: dict[str, Any], url: str
    ) -> dict[str, Any]:
        """Check for errors in API response.

        Args:
            resp_json: JSON response from API.
            url: API endpoint path.

        Returns:
            Response JSON if no errors.

        Raises:
            ModuleAPIError: If response contains errors.
        """
        if "status" not in resp_json:
            return resp_json

        status = resp_json["status"]
        if status == 404:
            if resp_json.get("subStatus") == 2001:
                raise ModuleAPIError(
                    error_code=404,
                    error_message="Content may be region-locked",
                    api_endpoint=url,
                    module_name="tidal",
                )
            if resp_json.get("error") == "Not Found":
                return resp_json
        if status != 200:
            raise ModuleAPIError(
                error_code=status,
                error_message=resp_json.get("userMessage", "Unknown error"),
                api_endpoint=url,
                module_name="tidal",
            )

        return resp_json

    async def _handle_api_response(
        self,
        response,
        url: str,
        current_session: TidalSession,
        params: dict[str, Any],
        refresh: bool,
    ) -> dict[str, Any]:
        """Handle API response and errors.

        Args:
            response: aiohttp response object.
            url: API endpoint path.
            current_session: Current TIDAL session.
            params: Request parameters.
            refresh: Whether this is a retry after token refresh.

        Returns:
            JSON response as dictionary.

        Raises:
            ModuleAPIError: If the response is invalid or contains errors.
        """
        # Retry with refresh on 401/403
        if not refresh and response.status in (401, 403):
            await current_session.refresh_session()
            return await self._get(url, params, refresh=True)

        try:
            resp_json = msgspec.json.decode(await response.read())
        except Exception as decode_err:
            raise ModuleAPIError(
                error_code=response.status,
                error_message="Invalid JSON response",
                api_endpoint=url,
                module_name="tidal",
            ) from decode_err

        # Check for errors in response
        return self._check_response_errors(resp_json, url)

    async def _get(
        self,
        url: str,
        params: dict[str, Any] | None = None,
        refresh: bool = False,
    ) -> dict[str, Any]:
        """Make a GET request to the API.

        Args:
            url: API endpoint path.
            params: Query parameters.
            refresh: Whether this is a retry after token refresh.

        Returns:
            JSON response as dictionary.

        Raises:
            ModuleAPIError: If the request fails.
        """
        if params is None:
            params = {}

        session = await self._ensure_session()
        current_session = self.sessions.get(self.default.name)
        if not current_session:
            raise ModuleAPIError(
                error_code=500,
                error_message="No active session",
                api_endpoint=url,
                module_name="tidal",
            )

        params = self._prepare_request_params(params, current_session)

        try:
            async with session.get(
                f"{self.TIDAL_API_BASE}{url}",
                headers=current_session.auth_headers,
                params=params,
            ) as response:
                return await self._handle_api_response(
                    response, url, current_session, params, refresh
                )

        except ClientResponseError as e:
            raise ModuleAPIError(
                error_code=e.status,
                error_message=e.message,
                api_endpoint=url,
                module_name="tidal",
            ) from e

    async def get_stream_url(self, track_id: str, quality: str) -> dict[str, Any]:
        """Get track streaming URL.

        Args:
            track_id: Track identifier.
            quality: Audio quality (LOW, HIGH, LOSSLESS, HI_RES, HI_RES_LOSSLESS).

        Returns:
            Stream URL and format information.
        """
        return await self._get(
            f"tracks/{track_id}/playbackinfopostpaywall/v4",
            {
                "playbackmode": "STREAM",
                "assetpresentation": "FULL",
                "audioquality": quality,
                "prefetch": "false",
            },
        )

    async def get_track(self, track_id: str) -> dict[str, Any]:
        """Get track metadata.

        Args:
            track_id: Track identifier.

        Returns:
            Track metadata dictionary.
        """
        return await self._get(f"tracks/{track_id}")

    async def get_album(self, album_id: str) -> dict[str, Any]:
        """Get album metadata.

        Args:
            album_id: Album identifier.

        Returns:
            Album metadata dictionary.
        """
        return await self._get(f"albums/{album_id}")

    async def get_album_tracks(self, album_id: str) -> dict[str, Any]:
        """Get album tracks.

        Args:
            album_id: Album identifier.

        Returns:
            Album tracks dictionary.
        """
        return await self._get(f"albums/{album_id}/tracks")

    async def get_album_contributors(
        self, album_id: str, offset: int = 0, limit: int = 100
    ) -> dict[str, Any]:
        """Get album track contributors.

        Args:
            album_id: Album identifier.
            offset: Pagination offset.
            limit: Maximum items per page.

        Returns:
            Album contributors dictionary.
        """
        return await self._get(
            f"albums/{album_id}/items/credits",
            params={
                "replace": "true",
                "offset": str(offset),
                "limit": str(limit),
                "includeContributors": "true",
            },
        )

    async def get_playlist(self, playlist_id: str) -> dict[str, Any]:
        """Get playlist metadata.

        Args:
            playlist_id: Playlist identifier.

        Returns:
            Playlist metadata dictionary.
        """
        return await self._get(f"playlists/{playlist_id}")

    async def get_playlist_items(self, playlist_id: str) -> dict[str, Any]:
        """Get playlist items with pagination.

        Args:
            playlist_id: Playlist identifier.

        Returns:
            Playlist items dictionary.
        """
        result = await self._get(
            f"playlists/{playlist_id}/items", {"offset": "0", "limit": "100"}
        )

        if result.get("totalNumberOfItems", 0) <= 100:
            return result

        offset = len(result.get("items", []))
        while offset < result.get("totalNumberOfItems", 0):
            buf = await self._get(
                f"playlists/{playlist_id}/items",
                {"offset": str(offset), "limit": "100"},
            )
            result["items"].extend(buf.get("items", []))
            offset += len(buf.get("items", []))

        return result

    async def get_artist(self, artist_id: str) -> dict[str, Any]:
        """Get artist metadata.

        Args:
            artist_id: Artist identifier.

        Returns:
            Artist metadata dictionary.
        """
        return await self._get(f"artists/{artist_id}")

    async def get_artist_albums(self, artist_id: str) -> dict[str, Any]:
        """Get artist albums.

        Args:
            artist_id: Artist identifier.

        Returns:
            Artist albums dictionary.
        """
        return await self._get(f"artists/{artist_id}/albums")

    async def get_artist_albums_ep_singles(self, artist_id: str) -> dict[str, Any]:
        """Get artist EPs and singles.

        Args:
            artist_id: Artist identifier.

        Returns:
            Artist EPs and singles dictionary.
        """
        return await self._get(
            f"artists/{artist_id}/albums", params={"filter": "EPSANDSINGLES"}
        )

    async def get_track_contributors(self, track_id: str) -> dict[str, Any]:
        """Get track contributors.

        Args:
            track_id: Track identifier.

        Returns:
            Track contributors dictionary.
        """
        return await self._get(f"tracks/{track_id}/contributors")

    async def get_lyrics(self, track_id: str) -> dict[str, Any]:
        """Get track lyrics.

        Args:
            track_id: Track identifier.

        Returns:
            Lyrics dictionary.
        """
        return await self._get(
            f"tracks/{track_id}/lyrics",
            params={"deviceType": "TV", "locale": "en_US"},
        )

    async def get_tracks_by_isrc(self, isrc: str) -> dict[str, Any]:
        """Search tracks by ISRC.

        Args:
            isrc: International Standard Recording Code.

        Returns:
            Search results dictionary.
        """
        return await self._get("tracks", params={"isrc": isrc})

    async def search(self, query: str, limit: int = 20) -> dict[str, Any]:
        """Search for content.

        Args:
            query: Search query string.
            limit: Maximum number of results.

        Returns:
            Search results dictionary.
        """
        return await self._get(
            "search",
            params={
                "query": query,
                "offset": "0",
                "limit": str(limit),
                "includeContributors": "true",
            },
        )
