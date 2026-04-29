"""TIDAL module interface — thin facade delegating to collaborators.

Delegates to:
- TidalMetadataParser: metadata extraction (pure functions)
- TidalStreamResolver: stream format selection and parsing
- TidalSearchAdapter: search API adaptation
"""

import logging
import re
from pathlib import Path
from typing import Any

import anyio
import av
from anyio import open_file
from anyio.to_thread import run_sync

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
    TrackDownloadInfo,
    TrackInfo,
)
from haberlea.utils.progress import advance, get_current_task, reset
from haberlea.utils.tempfile_manager import TempFileManager
from haberlea.utils.utils import create_aiohttp_session

from .metadata_parser import TidalMetadataParser
from .results import AlbumTracksResult
from .search_adapter import TidalSearchAdapter
from .stream_resolver import AudioTrack, TidalStreamResolver
from .tidal_api import SessionType, TidalApi, TidalMobileSession, TidalTvSession

logger = logging.getLogger(__name__)

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
        "name": "",
        "region": "",
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
    max_concurrent_downloads=1,
)


class ModuleInterface(ModuleBase):
    """TIDAL module interface — thin facade.

    Delegates metadata, stream, and search to collaborators.
    Retains session management and download orchestration.
    """

    def __init__(self, module_controller: ModuleController) -> None:
        """Initialize the TIDAL module.

        Args:
            module_controller: Controller providing settings and resources.
        """
        super().__init__(module_controller)
        self.settings = module_controller.module_settings
        self.cover_size = (
            module_controller.haberlea_options.default_cover_options.resolution
        )

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
        self.temp_manager = TempFileManager()

        # Collaborators (initialized after login/restore)
        self._parser = TidalMetadataParser(self.cover_size)
        self._stream: TidalStreamResolver | None = None
        self._search: TidalSearchAdapter | None = None

        self._restore_sessions()

    def _init_collaborators(self) -> None:
        """Initialize collaborators that depend on API."""
        if not self.api:
            return
        self._stream = TidalStreamResolver(
            self.api, self.sessions, self.quality_parse, self.settings
        )
        self._search = TidalSearchAdapter(self.api, self._parser)

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

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
            session.set_storage(saved_sessions[session_type])
            self.sessions[session_type] = session

        if self.sessions:
            # TidalApi creates the shared ClientSession and injects it into
            # every TidalSession it receives.
            self.api = TidalApi(self.sessions)
            self._init_collaborators()

    async def close(self) -> None:
        """Close the module and release resources."""
        if self.api:
            await self.api.close()

    async def login(self, email: str, password: str) -> None:
        """Authenticate with TIDAL.

        Args:
            email: User email (empty for TV auth).
            password: User password.
        """
        saved_sessions = (
            self.module_controller.temporary_settings_controller.read("sessions") or {}
        )

        enable_mobile = self.settings.get("enable_mobile", True)
        session_types = [SessionType.TV.name]
        if enable_mobile:
            session_types.extend(
                [SessionType.MOBILE_DEFAULT.name, SessionType.MOBILE_ATMOS.name]
            )

        # Create TidalApi up front so it owns the shared ClientSession; each
        # TidalSession gets that session injected before any HTTP call.
        self.api = TidalApi(self.sessions)

        for session_type in session_types:
            session = self._init_session(session_type)
            self.sessions[session_type] = session
            session.session = self.api.session

            if session_type in saved_sessions:
                session.set_storage(saved_sessions[session_type])
                if not await session.valid():
                    await session.refresh_session()
                    saved_sessions[session_type] = session.get_storage()
            else:
                if session_type == SessionType.TV.name:
                    if isinstance(session, TidalTvSession):
                        auth_info = await session.auth()
                        logger.info(
                            "Please visit https://link.tidal.com/%s",
                            auth_info.user_code,
                        )
                        logger.info("Waiting for authorization...")
                        while not await session.check_auth(auth_info.device_code):
                            await anyio.sleep(2)
                        logger.info("Authorization successful!")
                else:
                    tv_sess = self.sessions.get(SessionType.TV.name)
                    if tv_sess and tv_sess.refresh_token:
                        session.refresh_token = tv_sess.refresh_token
                        session.user_id = tv_sess.user_id
                        session.country_code = tv_sess.country_code
                        await session.refresh_session()
                    elif email and isinstance(session, TidalMobileSession):
                        await session.auth(email, password)

                saved_sessions[session_type] = session.get_storage()

        self.module_controller.temporary_settings_controller.set(
            "sessions", saved_sessions
        )
        self._init_collaborators()

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
                    "tv_secret",
                    "1nqpgx8uvBdZigrx4hUPDV2hOwgYAAAG5DYXOr6uNf8=",
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

    def custom_url_parse(self, url: str) -> MediaIdentification | None:
        """Parse a TIDAL URL to extract media type and ID.

        Args:
            url: TIDAL URL to parse.

        Returns:
            MediaIdentification or None if invalid.
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

    # ------------------------------------------------------------------
    # Search (delegates to TidalSearchAdapter)
    # ------------------------------------------------------------------

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
        if not self._search:
            return []
        return await self._search.search(query_type, query, track_info, limit)

    # ------------------------------------------------------------------
    # Album / Playlist / Artist info
    # ------------------------------------------------------------------

    async def _fetch_album_tracks(self, album_id: str) -> AlbumTracksResult:
        """Fetch album tracks with credits or fallback.

        Args:
            album_id: Album identifier.

        Returns:
            AlbumTracksResult with track_ids and track_data.
        """
        if not self.api:
            raise RuntimeError("API not initialized")

        tracks: list[str] = []
        track_data: dict[str, Any] = {}

        try:
            limit = 100
            tracks_data = await self.api.get_album_contributors(album_id, limit=limit)
            total_tracks = tracks_data.get("totalNumberOfItems", 0)

            all_items = list(tracks_data.get("items", []))
            for offset in range(limit, total_tracks, limit):
                more_tracks = await self.api.get_album_contributors(
                    album_id, offset=offset, limit=limit
                )
                all_items = [*all_items, *more_tracks.get("items", [])]

            for track in all_items:
                if track.get("type") != "track":
                    continue
                item = track.get("item", {})
                track_id = str(item.get("id"))
                tracks.append(track_id)
                track_data[track_id] = {
                    **item,
                    "credits": track.get("credits", []),
                }
        except Exception:
            tracks_data = await self.api.get_album_tracks(album_id)
            for track in tracks_data.get("items", []):
                track_id = str(track.get("id"))
                tracks.append(track_id)
                track_data[track_id] = track

        return AlbumTracksResult(track_ids=tracks, track_data=track_data)

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

        album_tracks = await self._fetch_album_tracks(album_id)
        quality = self._parser.determine_album_quality(album_data)
        release_year = self._parser.extract_release_year(album_data)
        cover_info = self._parser.get_album_cover_urls(album_data)

        return AlbumInfo(
            name=album_data.get("title", ""),
            release_year=release_year or 0,
            explicit=album_data.get("explicit", False),
            quality=quality,
            upc=album_data.get("upc"),
            duration=album_data.get("duration"),
            cover_url=cover_info.cover_url,
            cover_type=cover_info.cover_type,
            animated_cover_url=cover_info.animated_cover_url,
            artist=album_data.get("artist", {}).get("name", ""),
            artist_id=str(album_data.get("artist", {}).get("id", "")),
            tracks=album_tracks.track_ids,
            track_data=album_tracks.track_data,
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

        creator = playlist_data.get("creator", {})
        if "name" in creator:
            creator_name = creator["name"]
        elif playlist_data.get("type") == "EDITORIAL":
            creator_name = module_information.service_name
        else:
            creator_name = "Unknown"

        cover_url: str
        cover_type = ImageFileTypeEnum.jpg
        if playlist_data.get("squareImage"):
            cover_url = self._parser.generate_artwork_url(
                playlist_data["squareImage"],
                size=self.cover_size,
                max_size=1080,
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
        self,
        artist_id: str,
        get_credited_albums: bool = False,
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

        all_albums = artist_albums.get("items", []) + artist_singles.get("items", [])
        album_ids = list({str(album.get("id")) for album in all_albums})
        album_data = {str(album.get("id")): album for album in all_albums}

        return ArtistInfo(
            name=artist_data.get("name", ""),
            albums=album_ids,
            album_data=album_data,
        )

    # ------------------------------------------------------------------
    # Track info (delegates stream resolution)
    # ------------------------------------------------------------------

    async def _fetch_album_data(
        self,
        album_id: str,
        track_data: dict[str, Any],
        data: dict[str, Any],
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
            album_data = track_data.get("album", {})
            album_data = {
                **album_data,
                "artist": track_data.get("artist", {}),
                "numberOfVolumes": 1,
                "audioQuality": "LOSSLESS",
                "audioModes": ["STEREO"],
            }
            self.album_cache[album_id] = album_data
            return album_data

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
        if not self.api or not self._stream:
            raise RuntimeError("API not initialized")

        if data is None:
            data = {}

        track_data = (
            data[track_id] if track_id in data else await self.api.get_track(track_id)
        )

        album_id = str(track_data.get("album", {}).get("id", ""))
        album_data = await self._fetch_album_data(album_id, track_data, data)

        # Delegate stream resolution
        audio_format = self._stream.determine_audio_format(
            track_data, codec_options, quality_tier
        )
        audio_format = self._stream.select_session_for_format(audio_format)
        stream_result = await self._stream.fetch_stream(
            track_id, audio_format, quality_tier
        )
        manifest = await self._stream.process_stream_data(
            stream_result.stream_data, track_id, codec_options
        )
        audio_specs = self._stream.calculate_audio_specs(
            manifest.codec,
            stream_result.stream_data,
            manifest.audio_track,
        )

        # Delegate metadata extraction
        presentation = self._parser.extract_track_presentation(track_data)
        tags = self._parser.convert_tags(track_data, album_data)

        return TrackInfo(
            name=presentation.name,
            album=album_data.get("title", ""),
            album_id=album_id,
            artists=[a.get("name", "") for a in track_data.get("artists", [])],
            artist_id=str(track_data.get("artist", {}).get("id", "")),
            release_year=presentation.cover_type,
            bit_depth=audio_specs.bit_depth,
            sample_rate=audio_specs.sample_rate,
            bitrate=audio_specs.bitrate,
            duration=track_data.get("duration"),
            cover_url=presentation.cover_url,
            explicit=track_data.get("explicit", False),
            tags=tags,
            codec=manifest.codec,
            download_data=manifest.download_data,
            lyrics_data={"track_data": track_data},
            credits_data=(
                {track_id: track_data.get("credits", [])}
                if "credits" in track_data
                else None
            ),
            error=stream_result.session_type,
        )

    # ------------------------------------------------------------------
    # Track download
    # ------------------------------------------------------------------

    async def get_track_download(
        self,
        target_path: Path,
        url: str = "",
        data: dict[str, Any] | None = None,
    ) -> TrackDownloadInfo:
        """Download track file.

        Args:
            target_path: Target file path for direct download.
            url: URL to download from (for simple downloads).
            data: Optional extra data with audio_track or file_url.

        Returns:
            TrackDownloadInfo with download information.
        """
        if data is None:
            data = {}

        file_url = data.get("file_url") or url
        audio_track: AudioTrack | None = data.get("audio_track")

        if audio_track:
            total_segments = len(audio_track.urls)
            task_id = get_current_task()
            if task_id:
                reset(task_id)

            async with self.temp_manager.file(suffix=".mp4") as temp_mp4_path:
                session = create_aiohttp_session()
                try:
                    async with await open_file(temp_mp4_path, "wb") as temp_file:
                        for segment_url in audio_track.urls:
                            async with session.get(segment_url) as response:
                                response.raise_for_status()
                                segment_data = await response.read()
                                await temp_file.write(segment_data)
                                if task_id:
                                    await advance(task_id, 1, total_segments)
                finally:
                    await session.close()

                await self._convert_mp4_to_target(
                    temp_mp4_path,
                    target_path,
                    audio_track.codec,
                )

            return TrackDownloadInfo(download_type=DownloadEnum.DIRECT)

        return TrackDownloadInfo(download_type=DownloadEnum.URL, file_url=file_url)

    async def _convert_mp4_to_target(
        self, mp4_path: Path, target_path: Path, codec: CodecEnum
    ) -> None:
        """Remux audio from fMP4 to target format using PyAV.

        Args:
            mp4_path: Path to the temporary MP4 file.
            target_path: Target output path.
            codec: Target codec.
        """
        format_map = {
            CodecEnum.FLAC: "flac",
            CodecEnum.AAC: "adts",
            CodecEnum.EAC3: "eac3",
            CodecEnum.AC4: "ac4",
            CodecEnum.MHA1: "mha1",
        }
        output_format = format_map.get(codec, "flac")
        await run_sync(self._pyav_remux, mp4_path, target_path, output_format)

    @staticmethod
    def _pyav_remux(mp4_path: Path, target_path: Path, output_format: str) -> None:
        """Remux MP4 file to target format using PyAV (blocking).

        Args:
            mp4_path: Path to the input MP4 file.
            target_path: Target output path.
            output_format: Output format string for PyAV.
        """
        with av.open(str(mp4_path), mode="r") as input_container:
            input_stream = input_container.streams.audio[0]
            with av.open(str(target_path), mode="w", format=output_format) as out:
                output_stream = out.add_stream_from_template(template=input_stream)
                for packet in input_container.demux(input_stream):
                    if packet.dts is None:
                        continue
                    packet.stream = output_stream
                    out.mux(packet)

    # ------------------------------------------------------------------
    # Cover / Lyrics / Credits
    # ------------------------------------------------------------------

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
                url=self._parser.generate_artwork_url(
                    cover_id, size=cover_options.resolution
                ),
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

        if "error" in lyrics_data and track_data:
            title = track_data.get("title", "")
            artists = " ".join(a.get("name", "") for a in track_data.get("artists", []))
            results = await self.search(
                DownloadTypeEnum.track,
                f"{title} {artists}",
                limit=10,
            )

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

        if track_id in data:
            credits_list = data[track_id]
        else:
            credits_data = await self.api.get_track_contributors(track_id)
            credits_list = credits_data.get("items", [])

        result: list[CreditsInfo] = []
        for credit in credits_list:
            role = credit.get("type", "")
            contributors = [c.get("name", "") for c in credit.get("contributors", [])]
            if role and contributors:
                result.append(CreditsInfo(type=role, names=contributors))

        return result
