"""TIDAL metadata parser — pure functions for metadata extraction.

Single responsibility: convert raw TIDAL API data into domain objects.
No I/O, no session access. All methods are static or use only cover_size.
"""

from __future__ import annotations

from typing import Any

from haberlea.utils.models import (
    ImageFileTypeEnum,
    Tags,
)

from .results import AlbumCoverInfo, TrackPresentation


class TidalMetadataParser:
    """Extracts and transforms TIDAL metadata into domain objects.

    Pure functions: no I/O, no session access.
    """

    def __init__(self, cover_size: int) -> None:
        """Initialize the metadata parser.

        Args:
            cover_size: Default cover image size.
        """
        self._cover_size = cover_size

    @staticmethod
    def generate_artwork_url(cover_id: str, size: int, max_size: int = 1280) -> str:
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
    def generate_animated_artwork_url(cover_id: str, size: int = 1280) -> str:
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

    @staticmethod
    def convert_tags(track_data: dict[str, Any], album_data: dict[str, Any]) -> Tags:
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

    def extract_track_presentation(
        self, track_data: dict[str, Any]
    ) -> TrackPresentation:
        """Extract track name, cover URL, and release year.

        Args:
            track_data: Track data dictionary.

        Returns:
            TrackPresentation with name, cover_url, and cover_type.
        """
        track_name = track_data.get("title", "")
        if track_data.get("version"):
            track_name += f" ({track_data['version']})"

        album_cover = track_data.get("album", {}).get("cover")
        if album_cover:
            cover_url = self.generate_artwork_url(album_cover, size=self._cover_size)
        else:
            cover_url = (
                "https://tidal.com/browse/assets/images/"
                "defaultImages/defaultTrackImage.png"
            )

        release_year: int = 0
        if track_data.get("streamStartDate"):
            release_year = int(track_data["streamStartDate"][:4])
        elif track_data.get("dateAdded"):
            release_year = int(track_data["dateAdded"][:4])

        return TrackPresentation(
            name=track_name, cover_url=cover_url, cover_type=release_year
        )

    def get_album_cover_urls(self, album_data: dict[str, Any]) -> AlbumCoverInfo:
        """Get album cover URLs.

        Args:
            album_data: Album data dictionary.

        Returns:
            AlbumCoverInfo with cover_url, cover_type, and
            animated_cover_url.
        """
        cover_type = ImageFileTypeEnum.jpg
        if album_data.get("cover"):
            cover_url = self.generate_artwork_url(
                album_data["cover"], size=self._cover_size
            )
        else:
            cover_url = (
                "https://tidal.com/browse/assets/images/"
                "defaultImages/defaultAlbumImage.png"
            )
            cover_type = ImageFileTypeEnum.png

        animated_cover_url: str | None = None
        if album_data.get("videoCover"):
            animated_cover_url = self.generate_animated_artwork_url(
                album_data["videoCover"]
            )

        return AlbumCoverInfo(
            cover_url=cover_url,
            cover_type=cover_type,
            animated_cover_url=animated_cover_url,
        )

    @staticmethod
    def determine_album_quality(
        album_data: dict[str, Any],
    ) -> str | None:
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

    @staticmethod
    def extract_release_year(
        album_data: dict[str, Any],
    ) -> int | None:
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
