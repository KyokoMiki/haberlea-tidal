"""TIDAL video resolver — HLS master / variant playlist parsing.

Single responsibility: resolve the playable HLS master from TIDAL's
``playbackinfopostpaywall/v4`` payload, pick the closest variant for the
requested ``VideoQualityEnum``, and enumerate ``.ts`` segment URLs.
"""

from __future__ import annotations

import base64
import logging
from typing import TYPE_CHECKING

import m3u8
import msgspec

from haberlea.utils.models import VideoQualityEnum

if TYPE_CHECKING:
    from .tidal_api import TidalApi

logger = logging.getLogger(__name__)


# Vertical-resolution targets per quality tier. Resolvers pick the
# closest available variant to the value listed below.
_QUALITY_TO_RESOLUTION: dict[VideoQualityEnum, int] = {
    VideoQualityEnum.MINIMUM: 240,
    VideoQualityEnum.LOW: 360,
    VideoQualityEnum.MEDIUM: 480,
    VideoQualityEnum.HIGH: 720,
    VideoQualityEnum.MAX: 1080,
}

# TIDAL only honours these video qualities at the playback API level;
# anything beyond ``HIGH`` is resolved client-side by picking a
# higher-resolution variant from the master playlist.
_TIDAL_VIDEO_QUALITY = "HIGH"


def quality_to_resolution(tier: VideoQualityEnum) -> int:
    """Map a ``VideoQualityEnum`` to a target vertical resolution."""
    return _QUALITY_TO_RESOLUTION[tier]


class VideoVariant(msgspec.Struct, frozen=True, kw_only=True):
    """A single HLS variant from a master playlist.

    Attributes:
        uri: Variant playlist URI (absolute URL).
        resolution: Vertical resolution in pixels.
        codecs: Codec string from the master playlist (e.g. ``"avc1.4d401f"``).
        bandwidth: Average bandwidth in bits per second.
    """

    uri: str
    resolution: int
    codecs: str
    bandwidth: int


class TidalVideoResolver:
    """Resolves TIDAL music video streams to playable HLS variants."""

    def __init__(self, api: TidalApi) -> None:
        """Initialize the resolver.

        Args:
            api: TIDAL API client (for ``get_video_stream_url``).
        """
        self._api = api

    async def fetch_master_url(self, video_id: str) -> str:
        """Fetch the master m3u8 URL for a video.

        TIDAL returns a base64-encoded JSON manifest containing a single
        playlist URL under ``urls[0]``.

        Args:
            video_id: TIDAL video identifier.

        Returns:
            The master m3u8 absolute URL.

        Raises:
            ValueError: If the manifest payload is malformed.
        """
        stream_data = await self._api.get_video_stream_url(
            video_id, _TIDAL_VIDEO_QUALITY
        )
        manifest_b64 = stream_data.get("manifest")
        if not manifest_b64:
            raise ValueError(f"Video {video_id}: missing manifest payload")
        manifest = msgspec.json.decode(base64.b64decode(manifest_b64))
        urls = manifest.get("urls") or []
        if not urls:
            raise ValueError(f"Video {video_id}: empty manifest urls")
        return str(urls[0])

    @staticmethod
    def parse_master(master_text: str, master_url: str) -> list[VideoVariant]:
        """Parse a master m3u8 playlist body into ``VideoVariant`` items.

        Args:
            master_text: Raw m3u8 playlist text.
            master_url: Original master URL (used as base for relative URIs).

        Returns:
            List of variants ordered as declared in the playlist.
        """
        playlist = m3u8.loads(master_text, uri=master_url)
        if not playlist.is_variant:
            return []
        variants: list[VideoVariant] = []
        for item in playlist.playlists:
            stream = item.stream_info
            resolution = stream.resolution or (0, 0)
            variants.append(
                VideoVariant(
                    uri=item.absolute_uri,
                    resolution=int(resolution[1]) if resolution else 0,
                    codecs=str(stream.codecs or ""),
                    bandwidth=int(stream.bandwidth or 0),
                )
            )
        return variants

    @staticmethod
    def pick_variant(
        variants: list[VideoVariant], target_resolution: int
    ) -> VideoVariant:
        """Pick the variant whose resolution is closest to ``target_resolution``.

        Ties prefer the higher resolution.

        Args:
            variants: Non-empty list of variants.
            target_resolution: Desired vertical resolution in pixels.

        Returns:
            The matching ``VideoVariant``.

        Raises:
            ValueError: If ``variants`` is empty.
        """
        if not variants:
            raise ValueError("Cannot pick a variant from an empty list")
        return min(
            variants,
            key=lambda v: (abs(v.resolution - target_resolution), -v.resolution),
        )

    @staticmethod
    def quality_label(variant: VideoVariant) -> VideoQualityEnum:
        """Reverse-map a chosen variant resolution to the closest tier."""
        return min(
            VideoQualityEnum,
            key=lambda q: abs(_QUALITY_TO_RESOLUTION[q] - variant.resolution),
        )

    @staticmethod
    def parse_variant_segments(variant_text: str, variant_url: str) -> list[str]:
        """Parse a variant playlist into the ordered list of segment URLs.

        Args:
            variant_text: Raw m3u8 variant playlist text.
            variant_url: Original variant URL (used as base for relative URIs).

        Returns:
            List of absolute segment URLs.
        """
        playlist = m3u8.loads(variant_text, uri=variant_url)
        return [seg.absolute_uri for seg in playlist.segments]
