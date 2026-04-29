"""TIDAL result types replacing tuple return values."""

from typing import Any

import msgspec

from haberlea.utils.models import CodecEnum, ImageFileTypeEnum


class SearchMetadata(msgspec.Struct, frozen=True):
    """Search metadata, replaces 4-element tuple."""

    name: str | None
    artists: list[str] | None
    year: str | None
    duration: int | None


class AlbumTracksResult(msgspec.Struct, frozen=True):
    """Album tracks result, replaces tuple[list[str], dict]."""

    track_ids: list[str]
    track_data: dict[str, Any]


class AlbumCoverInfo(msgspec.Struct, frozen=True):
    """Album cover info, replaces 3-element tuple."""

    cover_url: str
    cover_type: ImageFileTypeEnum
    animated_cover_url: str | None


class ManifestResult(msgspec.Struct, frozen=True):
    """Stream manifest result, replaces 3-element tuple."""

    audio_track: Any | None  # AudioTrack
    codec: CodecEnum
    download_data: dict[str, Any] | None


class StreamResult(msgspec.Struct, frozen=True):
    """Stream data result, replaces 2-element tuple."""

    stream_data: dict[str, Any] | None
    session_type: str | None


class AudioSpecs(msgspec.Struct, frozen=True):
    """Audio specs, replaces 3-element tuple."""

    bit_depth: int
    sample_rate: float
    bitrate: int | None


class TrackPresentation(msgspec.Struct, frozen=True):
    """Track presentation info, replaces 3-element tuple."""

    name: str
    cover_url: str
    cover_type: int


class DatadomeCookie(msgspec.Struct, frozen=True):
    """Datadome cookie, replaces tuple[str, str]."""

    cookie: str
    device_id: str


class DeviceAuthInfo(msgspec.Struct, frozen=True):
    """Device auth info, replaces tuple[str, str]."""

    device_code: str
    user_code: str
