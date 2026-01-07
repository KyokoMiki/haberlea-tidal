"""TIDAL module interface for Haberlea.

This module provides the main interface for downloading music from TIDAL,
supporting various audio formats including FLAC, MQA, Dolby Atmos, and Sony 360RA.
"""

import asyncio
import base64
import io
import re
from typing import Any

import aiofiles
import av
import msgspec
from bs4 import BeautifulSoup
from rich import print

from haberlea.plugins.base import ModuleBase
from haberlea.utils.models import (
    AlbumInfo,
    ArtistInfo,
    CodecEnum,
    CodecOptions,
    CoverInfo,
    CoverOptions,
    CreditsInfo,
    DownloadEnum,
    DownloadTypeEnum,
    ImageFileTypeEnum,
    LyricsInfo,
    MediaIdentification,
    ModuleController,
    ModuleFlags,
    ModuleInformation,
    ModuleModes,
    PlaylistInfo,
    QualityEnum,
    SearchResult,
    Tags,
    TrackDownloadInfo,
    TrackInfo,
)
from haberlea.utils.progress import advance, get_current_task, reset
from haberlea.utils.utils import create_aiohttp_session, download_file, sanitise_name

from .tidal_api import (
    SessionType,
    TidalApi,
    TidalMobileSession,
    TidalTvSession,
)

module_information = ModuleInformation(
    service_name="TIDAL",
    module_supported_modes=(
        ModuleModes.download
        | ModuleModes.credits
        | ModuleModes.covers
        | ModuleModes.lyrics
    ),
    flags=ModuleFlags.enable_jwt_system,
    global_settings={
        "tv_token": "cgiF7TQuB97BUIu3",
        "tv_secret": "1nqpgx8uvBdZigrx4hUPDV2hOwgYAAAG5DYXOr6uNf8=",
        "mobile_atmos_token": "km8T1xS355y7dd3H",
        "mobile_token": "6BDSRdpK9hqEBTgU",
        "enable_mobile": True,
        "prefer_ac4": False,
    },
    session_storage_variables=["sessions"],
    netlocation_constant="tidal",
    url_constants={
        "track": DownloadTypeEnum.track,
        "album": DownloadTypeEnum.album,
        "playlist": DownloadTypeEnum.playlist,
        "artist": DownloadTypeEnum.artist,
    },
    test_url="https://tidal.com/browse/track/92265335",
)


class AudioTrack(msgspec.Struct):
    """Audio track information from MPEG-DASH manifest.

    Attributes:
        codec: Audio codec type.
        sample_rate: Sample rate in Hz.
        bitrate: Bitrate in bits per second.
        urls: List of segment URLs.
    """

    codec: CodecEnum
    sample_rate: int
    bitrate: int
    urls: list[str]


class ModuleInterface(ModuleBase):
    """TIDAL module interface implementation.

    Handles authentication, metadata retrieval, and track downloading
    from the TIDAL music streaming service.
    """

    def __init__(self, module_controller: ModuleController) -> None:
        """Initialize the TIDAL module.

        Args:
            module_controller: Controller providing access to settings and resources.
        """
        super().__init__(module_controller)
        self.settings = module_controller.module_settings
        self.cover_size = (
            module_controller.haberlea_options.default_cover_options.resolution
        )

        # Quality mapping: LOW=96kbps AAC, HIGH=320kbps AAC,
        # LOSSLESS=44.1/16 FLAC, HI_RES=MQA/HI_RES_LOSSLESS
        self.quality_parse: dict[QualityEnum, str] = {
            QualityEnum.MINIMUM: "LOW",
            QualityEnum.LOW: "LOW",
            QualityEnum.MEDIUM: "HIGH",
            QualityEnum.HIGH: "HIGH",
            QualityEnum.LOSSLESS: "LOSSLESS",
            QualityEnum.HIFI: "HI_RES",
        }

        self.sessions: dict[str, TidalTvSession | TidalMobileSession] = {}
        self.api: TidalApi | None = None
        self.album_cache: dict[str, dict[str, Any]] = {}

        # Try to restore saved sessions
        self._restore_sessions()

    def _restore_sessions(self) -> None:
        """Restore saved sessions from storage."""
        saved_sessions = (
            self.module_controller.temporary_settings_controller.read("sessions") or {}
        )

        if not saved_sessions:
            return

        enable_mobile = self.settings.get("enable_mobile", True)
        session_types = [SessionType.TV.name]
        if enable_mobile:
            session_types.extend(
                [SessionType.MOBILE_DEFAULT.name, SessionType.MOBILE_ATMOS.name]
            )

        for session_type in session_types:
            if session_type not in saved_sessions:
                continue

            session = self._init_session(session_type)
            session.session = create_aiohttp_session()
            session.set_storage(saved_sessions[session_type])
            self.sessions[session_type] = session

        if self.sessions:
            self.api = TidalApi(self.sessions)

    async def close(self) -> None:
        """Close the module and release resources."""
        if self.api:
            await self.api.close()

    async def login(self, email: str, password: str) -> None:
        """Authenticate with TIDAL.

        For TV session, email should be empty and password is ignored.
        For Mobile session, provide email and password.

        Args:
            email: User email (empty for TV auth).
            password: User password.
        """
        # Load saved sessions
        saved_sessions = (
            self.module_controller.temporary_settings_controller.read("sessions") or {}
        )

        # Initialize sessions based on settings
        enable_mobile = self.settings.get("enable_mobile", True)
        session_types = [SessionType.TV.name]
        if enable_mobile:
            session_types.extend(
                [SessionType.MOBILE_DEFAULT.name, SessionType.MOBILE_ATMOS.name]
            )

        for session_type in session_types:
            session = self._init_session(session_type)
            session.session = create_aiohttp_session()

            if session_type in saved_sessions:
                session.set_storage(saved_sessions[session_type])
                # Try to refresh if expired
                if not await session.valid():
                    await session.refresh_session()
                    saved_sessions[session_type] = session.get_storage()
            else:
                # Need to authenticate
                if session_type == SessionType.TV.name:
                    tv_session = session
                    if isinstance(tv_session, TidalTvSession):
                        device_code, user_code = await tv_session.auth()
                        print(f"Please visit https://link.tidal.com/{user_code}")
                        print("Waiting for authorization...")
                        # Poll for completion
                        while not await tv_session.check_auth(device_code):
                            await asyncio.sleep(2)
                        print("Authorization successful!")
                else:
                    # Use refresh token from TV session if available
                    tv_sess = self.sessions.get(SessionType.TV.name)
                    if tv_sess and tv_sess.refresh_token:
                        session.refresh_token = tv_sess.refresh_token
                        session.user_id = tv_sess.user_id
                        session.country_code = tv_sess.country_code
                        await session.refresh_session()
                    elif email and isinstance(session, TidalMobileSession):
                        await session.auth(email, password)

                saved_sessions[session_type] = session.get_storage()

            self.sessions[session_type] = session

        # Save sessions
        self.module_controller.temporary_settings_controller.set(
            "sessions", saved_sessions
        )

        # Initialize API with sessions
        self.api = TidalApi(self.sessions)

    def _init_session(self, session_type: str) -> TidalTvSession | TidalMobileSession:
        """Initialize a session based on type.

        Args:
            session_type: Session type name.

        Returns:
            Initialized session instance.
        """
        if session_type == SessionType.TV.name:
            return TidalTvSession(
                self.settings.get("tv_token", "cgiF7TQuB97BUIu3"),
                self.settings.get(
                    "tv_secret", "1nqpgx8uvBdZigrx4hUPDV2hOwgYAAAG5DYXOr6uNf8="
                ),
            )
        elif session_type == SessionType.MOBILE_ATMOS.name:
            return TidalMobileSession(
                self.settings.get("mobile_atmos_token", "km8T1xS355y7dd3H")
            )
        else:
            return TidalMobileSession(
                self.settings.get("mobile_token", "6BDSRdpK9hqEBTgU")
            )

    @staticmethod
    def _generate_artwork_url(cover_id: str, size: int, max_size: int = 1280) -> str:
        """Generate artwork URL for given cover ID.

        Args:
            cover_id: TIDAL cover identifier.
            size: Desired image size.
            max_size: Maximum supported size before using origin.

        Returns:
            Artwork URL string.
        """
        supported_sizes = [80, 160, 320, 480, 640, 1080, 1280]
        best_size = min(supported_sizes, key=lambda x: abs(x - size))
        if best_size > max_size:
            image_name = "origin.jpg"
        else:
            image_name = f"{best_size}x{best_size}.jpg"
        return (
            f"https://resources.tidal.com/images/"
            f"{cover_id.replace('-', '/')}/{image_name}"
        )

    @staticmethod
    def _generate_animated_artwork_url(cover_id: str, size: int = 1280) -> str:
        """Generate animated artwork URL.

        Args:
            cover_id: TIDAL video cover identifier.
            size: Desired video size.

        Returns:
            Animated artwork URL string.
        """
        return (
            f"https://resources.tidal.com/videos/"
            f"{cover_id.replace('-', '/')}/{size}x{size}.mp4"
        )

    def custom_url_parse(self, url: str) -> MediaIdentification | None:
        """Parse a TIDAL URL to extract media type and ID.

        Args:
            url: TIDAL URL to parse.

        Returns:
            MediaIdentification with parsed info, or None if invalid.
        """
        match = re.search(
            r"https?://tidal\.com/(?:browse/)?"
            r"(?P<media_type>track|album|playlist|artist)/"
            r"(?P<media_id>[A-Za-z0-9-]+)",
            url,
        )

        if not match:
            return None

        media_types = {
            "track": DownloadTypeEnum.track,
            "album": DownloadTypeEnum.album,
            "artist": DownloadTypeEnum.artist,
            "playlist": DownloadTypeEnum.playlist,
        }

        return MediaIdentification(
            media_type=media_types[match.group("media_type")],
            media_id=match.group("media_id"),
            original_url=url,
        )

    def _extract_search_metadata(
        self, item: dict[str, Any], query_type: DownloadTypeEnum
    ) -> tuple[str | None, list[str] | None, str | None, int | None]:
        """Extract metadata from search result item.

        Args:
            item: Search result item dictionary.
            query_type: Type of content being searched.

        Returns:
            Tuple of (name, artists, year, duration).
        """
        name: str | None = None
        artists: list[str] | None = None
        year: str | None = None
        duration: int | None = None

        if query_type is DownloadTypeEnum.artist:
            name = item.get("name")
        elif query_type is DownloadTypeEnum.playlist:
            creator = item.get("creator", {})
            if "name" in creator:
                artists = [creator["name"]]
            elif item.get("type") == "EDITORIAL":
                artists = [module_information.service_name]
            else:
                artists = ["Unknown"]
            duration = item.get("duration")
            year = item.get("created", "")[:4] if item.get("created") else None
        elif query_type is DownloadTypeEnum.track:
            artists = [a.get("name") for a in item.get("artists", [])]
            album = item.get("album", {})
            year = (
                album.get("releaseDate", "")[:4] if album.get("releaseDate") else None
            )
            duration = item.get("duration")
        elif query_type is DownloadTypeEnum.album:
            artists = [a.get("name") for a in item.get("artists", [])]
            duration = item.get("duration")
            year = item.get("releaseDate", "")[:4] if item.get("releaseDate") else None

        if query_type is not DownloadTypeEnum.artist:
            name = item.get("title", "")
            if item.get("version") and name:
                name += f" ({item.get('version')})"

        return name, artists, year, duration

    def _determine_audio_quality(
        self, item: dict[str, Any], query_type: DownloadTypeEnum
    ) -> list[str] | None:
        """Determine audio quality labels for search result.

        Args:
            item: Search result item dictionary.
            query_type: Type of content being searched.

        Returns:
            List of quality labels or None.
        """
        if query_type in {DownloadTypeEnum.artist, DownloadTypeEnum.playlist}:
            return None

        audio_modes = item.get("audioModes", [])
        if "DOLBY_ATMOS" in audio_modes:
            return ["Dolby Atmos"]
        elif "SONY_360RA" in audio_modes:
            return ["360 Reality Audio"]
        elif item.get("audioQuality") == "HI_RES":
            return ["MQA"]
        else:
            return ["HiFi"]

    def _build_search_result(
        self,
        item: dict[str, Any],
        query_type: DownloadTypeEnum,
        name: str | None,
        artists: list[str] | None,
        year: str | None,
        duration: int | None,
        additional: list[str] | None,
    ) -> SearchResult:
        """Build SearchResult from extracted metadata.

        Args:
            item: Search result item dictionary.
            query_type: Type of content being searched.
            name: Result name.
            artists: List of artist names.
            year: Release year.
            duration: Duration in seconds.
            additional: Additional quality labels.

        Returns:
            Constructed SearchResult.
        """
        result_id = (
            item.get("uuid", "")
            if query_type is DownloadTypeEnum.playlist
            else str(item.get("id", ""))
        )

        return SearchResult(
            name=name,
            artists=artists,
            year=year,
            result_id=result_id,
            explicit=item.get("explicit", False),
            duration=duration,
            additional=additional,
        )

    async def search(
        self,
        query_type: DownloadTypeEnum,
        query: str,
        track_info: TrackInfo | None = None,
        limit: int = 20,
    ) -> list[SearchResult]:
        """Search for content on TIDAL.

        Args:
            query_type: Type of content to search for.
            query: Search query string.
            track_info: Optional track info for ISRC-based search.
            limit: Maximum number of results.

        Returns:
            List of SearchResult objects.
        """
        if not self.api:
            return []

        if track_info and track_info.tags.isrc:
            results = await self.api.get_tracks_by_isrc(track_info.tags.isrc)
        else:
            search_results = await self.api.search(query, limit=limit)
            results = search_results.get(f"{query_type.name}s", {})

        items = []
        for i in results.get("items", []):
            # Extract metadata
            name, artists, year, duration = self._extract_search_metadata(i, query_type)

            # Determine audio quality
            additional = self._determine_audio_quality(i, query_type)

            # Build result
            result = self._build_search_result(
                i, query_type, name, artists, year, duration, additional
            )
            items.append(result)

        return items

    async def _fetch_album_tracks(
        self, album_id: str
    ) -> tuple[list[str], dict[str, Any]]:
        """Fetch album tracks with credits or fallback to simple list.

        Args:
            album_id: Album identifier.

        Returns:
            Tuple of (track_ids, track_data).
        """
        if not self.api:
            raise RuntimeError("API not initialized")

        tracks: list[str] = []
        track_data: dict[str, Any] = {}

        try:
            limit = 100
            tracks_data = await self.api.get_album_contributors(album_id, limit=limit)
            total_tracks = tracks_data.get("totalNumberOfItems", 0)

            # Paginate if needed
            for offset in range(limit, total_tracks, limit):
                more_tracks = await self.api.get_album_contributors(
                    album_id, offset=offset, limit=limit
                )
                tracks_data["items"].extend(more_tracks.get("items", []))

            for track in tracks_data.get("items", []):
                if track.get("type") != "track":
                    continue
                item = track.get("item", {})
                track_id = str(item.get("id"))
                tracks.append(track_id)
                item["credits"] = track.get("credits", [])
                track_data[track_id] = item
        except Exception:
            # Fallback to simple track list
            tracks_data = await self.api.get_album_tracks(album_id)
            for track in tracks_data.get("items", []):
                track_id = str(track.get("id"))
                tracks.append(track_id)
                track_data[track_id] = track

        return tracks, track_data

    def _determine_album_quality(self, album_data: dict[str, Any]) -> str | None:
        """Determine quality indicator for album.

        Args:
            album_data: Album data dictionary.

        Returns:
            Quality string or None.
        """
        audio_modes = album_data.get("audioModes", [])
        if audio_modes == ["DOLBY_ATMOS"]:
            return "Dolby Atmos"
        elif audio_modes == ["SONY_360RA"]:
            return "360"
        elif album_data.get("audioQuality") == "HI_RES":
            return "M"
        return None

    def _extract_release_year(self, album_data: dict[str, Any]) -> int | None:
        """Extract release year from album data.

        Args:
            album_data: Album data dictionary.

        Returns:
            Release year or None.
        """
        if album_data.get("releaseDate"):
            return int(album_data["releaseDate"][:4])
        elif album_data.get("streamStartDate"):
            return int(album_data["streamStartDate"][:4])
        elif album_data.get("copyright"):
            years = [int(s) for s in album_data["copyright"].split() if s.isdigit()]
            if years:
                return years[0]
        return None

    def _get_album_cover_urls(
        self, album_data: dict[str, Any]
    ) -> tuple[str, ImageFileTypeEnum, str | None]:
        """Get album cover URLs.

        Args:
            album_data: Album data dictionary.

        Returns:
            Tuple of (cover_url, cover_type, animated_cover_url).
        """
        cover_type = ImageFileTypeEnum.jpg
        if album_data.get("cover"):
            cover_url = self._generate_artwork_url(
                album_data["cover"], size=self.cover_size
            )
        else:
            cover_url = (
                "https://tidal.com/browse/assets/images/"
                "defaultImages/defaultAlbumImage.png"
            )
            cover_type = ImageFileTypeEnum.png

        animated_cover_url: str | None = None
        if album_data.get("videoCover"):
            animated_cover_url = self._generate_animated_artwork_url(
                album_data["videoCover"]
            )

        return cover_url, cover_type, animated_cover_url

    async def get_album_info(
        self, album_id: str, data: dict[str, Any] | None = None
    ) -> AlbumInfo:
        """Get album information and track list.

        Args:
            album_id: Album identifier.
            data: Optional pre-fetched album data.

        Returns:
            AlbumInfo with metadata and track list.
        """
        if not self.api:
            raise RuntimeError("API not initialized")

        if data is None:
            data = {}

        if album_id in data:
            album_data = data[album_id]
        elif album_id in self.album_cache:
            album_data = self.album_cache[album_id]
        else:
            album_data = await self.api.get_album(album_id)

        # Get tracks with credits
        tracks, track_data = await self._fetch_album_tracks(album_id)

        # Determine quality indicator
        quality = self._determine_album_quality(album_data)

        # Get release year
        release_year = self._extract_release_year(album_data)

        # Get cover URLs
        cover_url, cover_type, animated_cover_url = self._get_album_cover_urls(
            album_data
        )

        return AlbumInfo(
            name=album_data.get("title", ""),
            release_year=release_year or 0,
            explicit=album_data.get("explicit", False),
            quality=quality,
            upc=album_data.get("upc"),
            duration=album_data.get("duration"),
            cover_url=cover_url,
            cover_type=cover_type,
            animated_cover_url=animated_cover_url,
            artist=album_data.get("artist", {}).get("name", ""),
            artist_id=str(album_data.get("artist", {}).get("id", "")),
            tracks=tracks,
            track_data=track_data,
        )

    async def get_playlist_info(self, playlist_id: str) -> PlaylistInfo:
        """Get playlist information and track list.

        Args:
            playlist_id: Playlist identifier.

        Returns:
            PlaylistInfo with metadata and track list.
        """
        if not self.api:
            raise RuntimeError("API not initialized")

        playlist_data = await self.api.get_playlist(playlist_id)
        playlist_tracks = await self.api.get_playlist_items(playlist_id)

        tracks: list[str] = []
        track_data: dict[str, Any] = {}
        for track in playlist_tracks.get("items", []):
            if track.get("type") != "track":
                continue
            item = track.get("item", {})
            track_id = str(item.get("id"))
            tracks.append(track_id)
            track_data[track_id] = item

        # Creator name
        creator = playlist_data.get("creator", {})
        if "name" in creator:
            creator_name = creator["name"]
        elif playlist_data.get("type") == "EDITORIAL":
            creator_name = module_information.service_name
        else:
            creator_name = "Unknown"

        # Cover URL
        cover_url: str
        cover_type = ImageFileTypeEnum.jpg
        if playlist_data.get("squareImage"):
            cover_url = self._generate_artwork_url(
                playlist_data["squareImage"], size=self.cover_size, max_size=1080
            )
        else:
            cover_url = (
                "https://tidal.com/browse/assets/images/"
                "defaultImages/defaultPlaylistImage.png"
            )
            cover_type = ImageFileTypeEnum.png

        return PlaylistInfo(
            name=playlist_data.get("title", ""),
            creator=creator_name,
            tracks=tracks,
            release_year=int(playlist_data.get("created", "0000")[:4]),
            duration=playlist_data.get("duration"),
            creator_id=str(creator.get("id", "")),
            cover_url=cover_url,
            cover_type=cover_type,
            track_data=track_data,
        )

    async def get_artist_info(
        self, artist_id: str, get_credited_albums: bool = False
    ) -> ArtistInfo:
        """Get artist information and discography.

        Args:
            artist_id: Artist identifier.
            get_credited_albums: Whether to include credited albums.

        Returns:
            ArtistInfo with metadata and album list.
        """
        if not self.api:
            raise RuntimeError("API not initialized")

        artist_data = await self.api.get_artist(artist_id)
        artist_albums = await self.api.get_artist_albums(artist_id)
        artist_singles = await self.api.get_artist_albums_ep_singles(artist_id)

        # Combine albums and singles, remove duplicates
        all_albums = artist_albums.get("items", []) + artist_singles.get("items", [])
        album_ids = list({str(album.get("id")) for album in all_albums})

        album_data = {str(album.get("id")): album for album in all_albums}

        return ArtistInfo(
            name=artist_data.get("name", ""),
            albums=album_ids,
            album_data=album_data,
        )

    def _parse_manifest(
        self, stream_data: dict[str, Any], fallback_codec: CodecEnum = CodecEnum.FLAC
    ) -> tuple[AudioTrack | None, CodecEnum, dict[str, Any]]:
        """Parse stream manifest and extract audio track information.

        Args:
            stream_data: Stream data containing manifest.
            fallback_codec: Codec to use if parsing fails.

        Returns:
            Tuple of (audio_track, codec, manifest_dict).
        """
        manifest_type = stream_data.get("manifestMimeType", "")
        manifest_dict: dict[str, Any] = {}
        audio_track: AudioTrack | None = None
        track_codec = fallback_codec

        if manifest_type == "application/dash+xml":
            manifest_bytes = base64.b64decode(stream_data["manifest"])
            audio_tracks = self._parse_mpd(manifest_bytes)
            if audio_tracks:
                audio_track = audio_tracks[0]
                track_codec = audio_track.codec
        else:
            manifest_dict = msgspec.json.decode(
                base64.b64decode(stream_data["manifest"])
            )
            codecs = manifest_dict.get("codecs", "")
            if "mp4a" in codecs:
                track_codec = CodecEnum.AAC
            else:
                try:
                    track_codec = CodecEnum[codecs.upper()]
                except KeyError:
                    track_codec = fallback_codec

        return audio_track, track_codec, manifest_dict

    async def _fetch_album_data(
        self, album_id: str, track_data: dict[str, Any], data: dict[str, Any]
    ) -> dict[str, Any]:
        """Fetch album data with fallback for region-locked albums.

        Args:
            album_id: Album identifier.
            track_data: Track data dictionary.
            data: Pre-fetched data dictionary.

        Returns:
            Album data dictionary.
        """
        if not self.api:
            raise RuntimeError("API not initialized")

        try:
            if album_id in data:
                return data[album_id]
            elif album_id in self.album_cache:
                return self.album_cache[album_id]
            else:
                return await self.api.get_album(album_id)
        except Exception:
            # Fallback for region-locked albums
            album_data = track_data.get("album", {})
            album_data.update(
                {
                    "artist": track_data.get("artist", {}),
                    "numberOfVolumes": 1,
                    "audioQuality": "LOSSLESS",
                    "audioModes": ["STEREO"],
                }
            )
            self.album_cache[album_id] = album_data
            return album_data

    def _determine_audio_format(
        self,
        track_data: dict[str, Any],
        codec_options: CodecOptions,
        quality_tier: QualityEnum,
    ) -> str | None:
        """Determine audio format based on media tags and codec options.

        Args:
            track_data: Track data dictionary.
            codec_options: Codec preference options.
            quality_tier: Desired quality tier.

        Returns:
            Audio format string or None.
        """
        media_tags = track_data.get("mediaMetadata", {}).get("tags", [])
        audio_format: str | None = None

        if codec_options.spatial_codecs:
            if "SONY_360RA" in media_tags:
                audio_format = "360ra"
            elif "DOLBY_ATMOS" in media_tags:
                audio_format = "ac4" if self.settings.get("prefer_ac4") else "ac3"

        if (
            "HIRES_LOSSLESS" in media_tags
            and not audio_format
            and quality_tier is QualityEnum.HIFI
        ):
            audio_format = "flac_hires"

        return audio_format

    def _select_session_for_format(self, audio_format: str | None) -> str | None:
        """Select appropriate session for audio format.

        Args:
            audio_format: Audio format string.

        Returns:
            Final audio format (may be None if session unavailable).
        """
        if not self.api:
            raise RuntimeError("API not initialized")

        session_map = {
            "flac_hires": SessionType.MOBILE_DEFAULT,
            "360ra": SessionType.MOBILE_DEFAULT,
            "ac4": SessionType.MOBILE_ATMOS,
            "ac3": SessionType.TV,
            None: SessionType.TV,
        }
        target_session = session_map.get(audio_format, SessionType.TV)

        if target_session.name in self.sessions:
            self.api.default = target_session
            return audio_format
        else:
            self.api.default = SessionType.TV
            return None

    async def _fetch_stream_data(
        self, track_id: str, audio_format: str | None, quality_tier: QualityEnum
    ) -> tuple[dict[str, Any] | None, str | None]:
        """Fetch stream data from API.

        Args:
            track_id: Track identifier.
            audio_format: Audio format string.
            quality_tier: Desired quality tier.

        Returns:
            Tuple of (stream_data, error_message).
        """
        if not self.api:
            return None, "API not initialized"

        try:
            quality_str = (
                "HI_RES_LOSSLESS"
                if audio_format == "flac_hires"
                else self.quality_parse[quality_tier]
            )
            stream_data = await self.api.get_stream_url(track_id, quality_str)
            return stream_data, None
        except Exception as e:
            error = str(e)
            if "Asset is not ready for playback" in error:
                error = f"Track [{track_id}] is not available in your region"
            return None, error

    async def _process_stream_data(
        self,
        stream_data: dict[str, Any] | None,
        track_id: str,
        codec_options: CodecOptions,
    ) -> tuple[AudioTrack | None, CodecEnum, dict[str, Any] | None]:
        """Process stream data and handle codec restrictions.

        Args:
            stream_data: Stream data dictionary.
            track_id: Track identifier.
            codec_options: Codec preference options.

        Returns:
            Tuple of (audio_track, codec, download_data).
        """
        if not stream_data:
            return None, CodecEnum.FLAC, None

        audio_track, track_codec, manifest_dict = self._parse_manifest(stream_data)

        # Handle proprietary codec restrictions
        if (
            not track_codec.spatial
            and not codec_options.proprietary_codecs
            and track_codec.proprietary
        ):
            if not self.api:
                raise RuntimeError("API not initialized")
            stream_data = await self.api.get_stream_url(track_id, "LOSSLESS")
            audio_track, track_codec, manifest_dict = self._parse_manifest(
                stream_data, CodecEnum.FLAC
            )

        if audio_track:
            download_data = {"audio_track": audio_track}
        else:
            download_data = {"file_url": manifest_dict.get("urls", [""])[0]}

        return audio_track, track_codec, download_data

    def _calculate_audio_specs(
        self,
        track_codec: CodecEnum,
        stream_data: dict[str, Any] | None,
        audio_track: AudioTrack | None,
    ) -> tuple[int, float, int | None]:
        """Calculate bit depth, sample rate, and bitrate.

        Args:
            track_codec: Track codec.
            stream_data: Stream data dictionary.
            audio_track: Audio track information.

        Returns:
            Tuple of (bit_depth, sample_rate, bitrate).
        """
        bit_depth = 16
        sample_rate = 44.1
        bitrate: int | None = None

        if track_codec in {CodecEnum.EAC3, CodecEnum.MHA1, CodecEnum.AC4}:
            sample_rate = 48.0
            bit_depth = 16
        elif stream_data:
            if stream_data.get("audioQuality") == "HI_RES_LOSSLESS":
                bit_depth = 24
            if audio_track:
                sample_rate = audio_track.sample_rate / 1000

        # Determine bitrate
        if stream_data:
            bitrate_map = {
                "HIGH": 320,
                "LOSSLESS": 1411,
                "HI_RES": None,
                "HI_RES_LOSSLESS": None,
            }
            bitrate = bitrate_map.get(stream_data.get("audioQuality", ""), 320)

            audio_mode = stream_data.get("audioMode", "")
            if audio_mode == "DOLBY_ATMOS":
                bitrate = 768 if track_codec == CodecEnum.EAC3 else 256
            elif audio_mode == "SONY_360RA":
                bitrate = 667

            if audio_track:
                bitrate = audio_track.bitrate // 1000

        return bit_depth, sample_rate, bitrate

    def _build_track_name_and_cover(
        self, track_data: dict[str, Any]
    ) -> tuple[str, str, int]:
        """Build track name, cover URL, and release year.

        Args:
            track_data: Track data dictionary.

        Returns:
            Tuple of (track_name, cover_url, release_year).
        """
        # Build track name
        track_name = track_data.get("title", "")
        if track_data.get("version"):
            track_name += f" ({track_data['version']})"

        # Cover URL
        album_cover = track_data.get("album", {}).get("cover")
        if album_cover:
            cover_url = self._generate_artwork_url(album_cover, size=self.cover_size)
        else:
            cover_url = (
                "https://tidal.com/browse/assets/images/"
                "defaultImages/defaultTrackImage.png"
            )

        # Release year
        release_year: int = 0
        if track_data.get("streamStartDate"):
            release_year = int(track_data["streamStartDate"][:4])
        elif track_data.get("dateAdded"):
            release_year = int(track_data["dateAdded"][:4])

        return track_name, cover_url, release_year

    async def get_track_info(
        self,
        track_id: str,
        quality_tier: QualityEnum,
        codec_options: CodecOptions,
        data: dict[str, Any] | None = None,
    ) -> TrackInfo:
        """Get track information and metadata.

        Args:
            track_id: Track identifier.
            quality_tier: Desired audio quality.
            codec_options: Codec preference options.
            data: Optional pre-fetched track data.

        Returns:
            TrackInfo with metadata and download information.
        """
        if not self.api:
            raise RuntimeError("API not initialized")

        if data is None:
            data = {}

        track_data = (
            data[track_id] if track_id in data else await self.api.get_track(track_id)
        )

        album_id = str(track_data.get("album", {}).get("id", ""))

        # Get album data
        album_data = await self._fetch_album_data(album_id, track_data, data)

        # Determine format and session
        audio_format = self._determine_audio_format(
            track_data, codec_options, quality_tier
        )
        audio_format = self._select_session_for_format(audio_format)

        # Get stream data
        stream_data, error = await self._fetch_stream_data(
            track_id, audio_format, quality_tier
        )

        # Process stream data
        audio_track, track_codec, download_data = await self._process_stream_data(
            stream_data, track_id, codec_options
        )

        # Calculate audio specifications
        bit_depth, sample_rate, bitrate = self._calculate_audio_specs(
            track_codec, stream_data, audio_track
        )

        # Build track name and cover
        track_name, cover_url, release_year = self._build_track_name_and_cover(
            track_data
        )

        tags = self._convert_tags(track_data, album_data)

        return TrackInfo(
            name=track_name,
            album=album_data.get("title", ""),
            album_id=album_id,
            artists=[a.get("name", "") for a in track_data.get("artists", [])],
            artist_id=str(track_data.get("artist", {}).get("id", "")),
            release_year=release_year,
            bit_depth=bit_depth,
            sample_rate=sample_rate,
            bitrate=bitrate,
            duration=track_data.get("duration"),
            cover_url=cover_url,
            explicit=track_data.get("explicit", False),
            tags=tags,
            codec=track_codec,
            download_data=download_data,
            lyrics_data={"track_data": track_data},
            credits_data={track_id: track_data.get("credits", [])}
            if "credits" in track_data
            else None,
            error=error,
        )

    async def get_track_download(
        self,
        target_path: str,
        url: str = "",
        data: dict[str, Any] | None = None,
    ) -> TrackDownloadInfo:
        """Download track file.

        Args:
            target_path: Target file path for direct download.
            url: The URL to download the track from (for simple downloads).
            data: Optional extra data containing audio_track or file_url.

        Returns:
            TrackDownloadInfo with download information.
        """
        if data is None:
            data = {}

        file_url = data.get("file_url") or url
        audio_track: AudioTrack | None = data.get("audio_track")

        # Simple URL download (MHA1, EC-3, MQA, etc.)
        if file_url and not audio_track:
            await download_file(file_url, target_path)
            return TrackDownloadInfo(download_type=DownloadEnum.DIRECT)

        # MPEG-DASH segmented download
        if audio_track:
            temp_segments: list[bytes] = []

            # Calculate total size for progress reporting
            total_segments = len(audio_track.urls)
            task_id = get_current_task()
            if task_id:
                reset(task_id)

            # Download all segments
            session = create_aiohttp_session()
            try:
                for segment_url in audio_track.urls:
                    async with session.get(segment_url) as response:
                        response.raise_for_status()
                        segment_data = await response.read()
                        temp_segments.append(segment_data)
                        # Report progress based on segment count
                        if task_id:
                            await advance(task_id, 1, total_segments)
            finally:
                await session.close()

            # Merge segments
            merged_data = b"".join(temp_segments)

            # Convert using PyAV
            output_path = await self._convert_mp4_to_target(
                merged_data, target_path, audio_track.codec
            )

            if output_path != target_path:
                # Conversion failed, return as different codec
                return TrackDownloadInfo(
                    download_type=DownloadEnum.TEMP_FILE_PATH,
                    temp_file_path=output_path,
                    different_codec=CodecEnum.AAC,
                )

            return TrackDownloadInfo(download_type=DownloadEnum.DIRECT)

        return TrackDownloadInfo(download_type=DownloadEnum.URL, file_url=url)

    async def _convert_mp4_to_target(
        self, mp4_data: bytes, target_path: str, codec: CodecEnum
    ) -> str:
        """Remux audio stream from fMP4 container to target format using PyAV.

        Performs stream copy (no re-encoding) for lossless conversion.
        Runs PyAV operations in a thread to avoid blocking the event loop.

        Args:
            mp4_data: Raw MP4 data bytes.
            target_path: Target output path.
            codec: Target codec.

        Returns:
            Path to the output file.
        """
        # Map codec to output format
        format_map = {
            CodecEnum.FLAC: "flac",
            CodecEnum.AAC: "adts",
            CodecEnum.EAC3: "eac3",
            CodecEnum.AC4: "ac4",
            CodecEnum.MHA1: "mha1",
        }
        output_format = format_map.get(codec, "flac")

        try:
            # Run PyAV operations in a thread to avoid blocking
            await asyncio.to_thread(
                self._pyav_remux, mp4_data, target_path, output_format
            )
            return target_path

        except Exception as e:
            # Log the error for debugging
            print(f"PyAV remux failed: {e}, falling back to m4a")
            # Fallback: just save as m4a
            fallback_path = target_path.rsplit(".", 1)[0] + ".m4a"
            async with aiofiles.open(fallback_path, "wb") as f:
                await f.write(mp4_data)
            return fallback_path

    @staticmethod
    def _pyav_remux(mp4_data: bytes, target_path: str, output_format: str) -> None:
        """Remux MP4 data to target format using PyAV (blocking).

        Args:
            mp4_data: Raw MP4 data bytes.
            target_path: Target output path.
            output_format: Output format string for PyAV.
        """
        with av.open(io.BytesIO(mp4_data), mode="r") as input_container:
            input_stream = input_container.streams.audio[0]

            with av.open(target_path, mode="w", format=output_format) as out:
                output_stream = out.add_stream_from_template(template=input_stream)

                for packet in input_container.demux(input_stream):
                    if packet.dts is None:
                        continue
                    packet.stream = output_stream
                    out.mux(packet)

    def _parse_codec(self, codec_str: str) -> CodecEnum:
        """Parse codec string to CodecEnum.

        Args:
            codec_str: Codec string from manifest.

        Returns:
            CodecEnum value.
        """
        codec_upper = codec_str.upper()
        if codec_upper.startswith("MP4A"):
            return CodecEnum.AAC
        try:
            return CodecEnum[codec_upper]
        except KeyError:
            return CodecEnum.FLAC

    def _parse_segment_timeline(self, seg_timeline) -> list[int]:
        """Parse segment timeline to get segment numbers.

        Args:
            seg_timeline: SegmentTimeline XML element.

        Returns:
            List of segment time values.
        """
        seg_num_list: list[int] = []
        cur_time = 0

        for s in seg_timeline.find_all("S"):
            if s.get("t"):
                cur_time = int(str(s.get("t") or "0"))

            repeat = int(str(s.get("r") or "0")) + 1
            for _ in range(repeat):
                seg_num_list.append(cur_time)
                cur_time += int(str(s.get("d") or "0"))

        return seg_num_list

    def _generate_segment_urls(
        self, media_template: str, seg_num_list: list[int], start_number: int
    ) -> list[str]:
        """Generate segment URLs from template.

        Args:
            media_template: Media URL template.
            seg_num_list: List of segment numbers.
            start_number: Starting segment number.

        Returns:
            List of segment URLs.
        """
        urls = []
        for i, _ in enumerate(seg_num_list):
            seg_url = media_template.replace("$Number$", str(start_number + i))
            urls.append(seg_url)
        return urls

    def _build_audio_track(self, rep, seg_template) -> AudioTrack | None:
        """Build AudioTrack from representation.

        Args:
            rep: Representation XML element.
            seg_template: SegmentTemplate XML element.

        Returns:
            AudioTrack object or None if invalid.
        """
        if seg_template is None:
            return None

        # Parse codec
        codec_str = str(rep.get("codecs") or "")
        codec = self._parse_codec(codec_str)

        # Build track URLs
        track_urls = [str(seg_template.get("initialization") or "")]
        start_number = int(str(seg_template.get("startNumber") or "1"))

        # Parse segment timeline
        seg_timeline = seg_template.find("SegmentTimeline")
        if seg_timeline is not None:
            seg_num_list = self._parse_segment_timeline(seg_timeline)
            media_template = str(seg_template.get("media") or "")
            segment_urls = self._generate_segment_urls(
                media_template, seg_num_list, start_number
            )
            track_urls.extend(segment_urls)

        return AudioTrack(
            codec=codec,
            sample_rate=int(str(rep.get("audioSamplingRate") or "0")),
            bitrate=int(str(rep.get("bandwidth") or "0")),
            urls=track_urls,
        )

    def _parse_mpd(self, xml_data: bytes) -> list[AudioTrack]:
        """Parse MPEG-DASH MPD manifest.

        Args:
            xml_data: Raw XML manifest data.

        Returns:
            List of AudioTrack objects.
        """
        # Parse XML with BeautifulSoup using lxml-xml parser
        soup = BeautifulSoup(xml_data, "lxml-xml")

        tracks: list[AudioTrack] = []

        for period in soup.find_all("Period"):
            for adaptation_set in period.find_all("AdaptationSet"):
                content_type = adaptation_set.get("contentType")
                if content_type != "audio":
                    continue

                for rep in adaptation_set.find_all("Representation"):
                    seg_template = rep.find("SegmentTemplate")
                    audio_track = self._build_audio_track(rep, seg_template)
                    if audio_track:
                        tracks.append(audio_track)

        return tracks

    @staticmethod
    def _convert_tags(track_data: dict[str, Any], album_data: dict[str, Any]) -> Tags:
        """Convert TIDAL metadata to Tags object.

        Args:
            track_data: Track metadata dictionary.
            album_data: Album metadata dictionary.

        Returns:
            Tags object with metadata.
        """
        return Tags(
            album_artist=album_data.get("artist", {}).get("name"),
            track_number=track_data.get("trackNumber"),
            total_tracks=album_data.get("numberOfTracks"),
            disc_number=track_data.get("volumeNumber"),
            total_discs=album_data.get("numberOfVolumes"),
            isrc=track_data.get("isrc"),
            upc=album_data.get("upc"),
            release_date=album_data.get("releaseDate"),
            copyright=track_data.get("copyright"),
            replay_gain=track_data.get("replayGain"),
            replay_peak=track_data.get("peak"),
        )

    async def get_track_cover(
        self,
        track_id: str,
        cover_options: CoverOptions,
        data: dict[str, Any] | None = None,
    ) -> CoverInfo:
        """Get track cover image information.

        Args:
            track_id: Track identifier.
            cover_options: Cover image options.
            data: Optional pre-fetched data.

        Returns:
            CoverInfo with cover URL and file type.
        """
        if not self.api:
            raise RuntimeError("API not initialized")

        if data is None:
            data = {}

        track_data = (
            data[track_id] if track_id in data else await self.api.get_track(track_id)
        )

        cover_id = track_data.get("album", {}).get("cover")
        if cover_id:
            return CoverInfo(
                url=self._generate_artwork_url(cover_id, size=cover_options.resolution),
                file_type=ImageFileTypeEnum.jpg,
            )

        return CoverInfo(
            url=(
                "https://tidal.com/browse/assets/images/"
                "defaultImages/defaultTrackImage.png"
            ),
            file_type=ImageFileTypeEnum.png,
        )

    async def get_track_lyrics(
        self, track_id: str, data: dict[str, Any] | None = None
    ) -> LyricsInfo:
        """Get track lyrics.

        Args:
            track_id: Track identifier.
            data: Optional pre-fetched data containing track_data.

        Returns:
            LyricsInfo with embedded and/or synced lyrics.
        """
        if not self.api:
            raise RuntimeError("API not initialized")

        if data is None:
            data = {}

        track_data = data.get("track_data", {})
        lyrics_data = await self.api.get_lyrics(track_id)

        # If lyrics not found, try searching for non-Atmos version
        if "error" in lyrics_data and track_data:
            title = track_data.get("title", "")
            artists = " ".join(a.get("name", "") for a in track_data.get("artists", []))
            results = await self.search(
                DownloadTypeEnum.track, f"{title} {artists}", limit=10
            )

            # Find matching non-Atmos track
            for r in results:
                if (
                    r.name == title
                    and r.artists
                    and r.artists[0] == track_data.get("artist", {}).get("name")
                    and r.additional
                    and "Dolby Atmos" not in r.additional
                ):
                    lyrics_data = await self.api.get_lyrics(r.result_id)
                    break

        embedded = lyrics_data.get("lyrics")
        synced = lyrics_data.get("subtitles")

        # Clean up synced lyrics format
        if synced:
            synced = re.sub(r"(\[\d{2}:\d{2}.\d{2,3}])(?: )", r"\1", synced)

        return LyricsInfo(embedded=embedded, synced=synced)

    async def get_track_credits(
        self, track_id: str, data: dict[str, Any] | None = None
    ) -> list[CreditsInfo]:
        """Get track credits information.

        Args:
            track_id: Track identifier.
            data: Optional pre-fetched credits data.

        Returns:
            List of CreditsInfo with contributor information.
        """
        if not self.api:
            raise RuntimeError("API not initialized")

        if data is None:
            data = {}

        credits_dict: dict[str, list[str]] = {}

        # Check if we have cached credits from album fetch
        cached_credits = data.get(track_id, [])
        if cached_credits:
            # Use cached credits from album fetch
            for contributor in cached_credits:
                role = contributor.get("type", "")
                names = [c.get("name", "") for c in contributor.get("contributors", [])]
                if role and names:
                    credits_dict[role] = names
        else:
            # Fetch credits from API
            contributors_data = await self.api.get_track_contributors(track_id)
            for contributor in contributors_data.get("items", []):
                role = contributor.get("role", "")
                name = contributor.get("name", "")
                if role and name:
                    if role not in credits_dict:
                        credits_dict[role] = []
                    credits_dict[role].append(name)

        return [
            CreditsInfo(sanitise_name(role), names)
            for role, names in credits_dict.items()
            if names
        ]
