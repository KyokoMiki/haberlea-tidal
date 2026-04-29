"""TIDAL search adapter — adapts TIDAL search API to domain results.

Single responsibility: search TIDAL and convert raw API data
into domain SearchResult objects.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from haberlea.utils.models import (
    DownloadTypeEnum,
    SearchResult,
    TrackInfo,
)

from .results import SearchMetadata

if TYPE_CHECKING:
    from .metadata_parser import TidalMetadataParser
    from .tidal_api import TidalApi

# Service name constant for editorial playlists
_SERVICE_NAME = "TIDAL"


class TidalSearchAdapter:
    """Adapts TIDAL search API to domain search results."""

    def __init__(self, api: TidalApi, parser: TidalMetadataParser) -> None:
        """Initialize the search adapter.

        Args:
            api: TIDAL API client.
            parser: Metadata parser for artwork URLs.
        """
        self._api = api
        self._parser = parser

    async def search(
        self,
        query_type: DownloadTypeEnum,
        query: str,
        track_info: TrackInfo | None = None,
        limit: int = 20,
    ) -> list[SearchResult]:
        """Search TIDAL and return domain results.

        Args:
            query_type: Type of content to search for.
            query: Search query string.
            track_info: Optional track info for ISRC-based search.
            limit: Maximum number of results.

        Returns:
            List of SearchResult objects.
        """
        if track_info and track_info.tags.isrc:
            results = await self._api.get_tracks_by_isrc(track_info.tags.isrc)
        else:
            search_results = await self._api.search(query, limit=limit)
            results = search_results.get(f"{query_type.name}s", {})

        items = []
        for i in results.get("items", []):
            metadata = self.extract_search_metadata(i, query_type)
            additional = self._determine_audio_quality(i, query_type)
            result = self.build_search_result(i, query_type, metadata, additional)
            items.append(result)

        return items

    @staticmethod
    def extract_search_metadata(
        item: dict[str, Any], query_type: DownloadTypeEnum
    ) -> SearchMetadata:
        """Extract metadata from search result item.

        Args:
            item: Search result item dictionary.
            query_type: Type of content being searched.

        Returns:
            SearchMetadata with name, artists, year, and duration.
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
                artists = [_SERVICE_NAME]
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

        return SearchMetadata(name=name, artists=artists, year=year, duration=duration)

    @staticmethod
    def _determine_audio_quality(
        item: dict[str, Any], query_type: DownloadTypeEnum
    ) -> list[str] | None:
        """Determine audio quality labels for search result.

        Args:
            item: Search result item dictionary.
            query_type: Type of content being searched.

        Returns:
            List of quality labels or None.
        """
        if query_type in {
            DownloadTypeEnum.artist,
            DownloadTypeEnum.playlist,
        }:
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

    @staticmethod
    def build_search_result(
        item: dict[str, Any],
        query_type: DownloadTypeEnum,
        metadata: SearchMetadata,
        additional: list[str] | None,
    ) -> SearchResult:
        """Build SearchResult from extracted metadata.

        Args:
            item: Search result item dictionary.
            query_type: Type of content being searched.
            metadata: Extracted search metadata.
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
            name=metadata.name,
            artists=metadata.artists,
            year=metadata.year,
            result_id=result_id,
            explicit=item.get("explicit", False),
            duration=metadata.duration,
            additional=additional,
        )
