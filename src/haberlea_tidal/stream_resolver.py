"""TIDAL stream resolver — audio stream format selection and parsing.

Single responsibility: resolve audio streams, parse manifests,
calculate audio specs. Handles MPD parsing and codec detection.
"""

from __future__ import annotations

import base64
import logging
from typing import Any

import msgspec
from bs4 import BeautifulSoup

from haberlea.utils.models import CodecEnum, CodecOptions, QualityEnum

from .results import AudioSpecs, ManifestResult, StreamResult
from .tidal_api import SessionType, TidalApi, TidalMobileSession, TidalTvSession

logger = logging.getLogger(__name__)


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


class TidalStreamResolver:
    """Resolves audio streams: format selection, manifest parsing,
    codec detection.

    Handles MPD parsing, format negotiation, and audio spec
    calculation.
    """

    def __init__(
        self,
        api: TidalApi,
        sessions: dict[str, TidalTvSession | TidalMobileSession],
        quality_parse: dict[QualityEnum, str],
        settings: dict[str, Any],
    ) -> None:
        """Initialize the stream resolver.

        Args:
            api: TIDAL API client.
            sessions: Active session map.
            quality_parse: Quality tier to TIDAL quality string map.
            settings: Module settings dict.
        """
        self._api = api
        self._sessions = sessions
        self._quality_parse = quality_parse
        self._settings = settings

    def determine_audio_format(
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
                audio_format = "ac4" if self._settings.get("prefer_ac4") else "ac3"

        if (
            "HIRES_LOSSLESS" in media_tags
            and not audio_format
            and quality_tier is QualityEnum.HIFI
        ):
            audio_format = "flac_hires"

        return audio_format

    def select_session_for_format(self, audio_format: str | None) -> str | None:
        """Select appropriate session for audio format.

        Args:
            audio_format: Audio format string.

        Returns:
            Final audio format (may be None if session unavailable).
        """
        session_map = {
            "flac_hires": SessionType.MOBILE_DEFAULT,
            "360ra": SessionType.MOBILE_DEFAULT,
            "ac4": SessionType.MOBILE_ATMOS,
            "ac3": SessionType.TV,
            None: SessionType.TV,
        }
        target_session = session_map.get(audio_format, SessionType.TV)

        if target_session.name in self._sessions:
            self._api.default = target_session
            return audio_format
        else:
            self._api.default = SessionType.TV
            return None

    async def fetch_stream(
        self,
        track_id: str,
        audio_format: str | None,
        quality_tier: QualityEnum,
    ) -> StreamResult:
        """Fetch stream data from API.

        Args:
            track_id: Track identifier.
            audio_format: Audio format string.
            quality_tier: Desired quality tier.

        Returns:
            StreamResult with stream_data and session_type.
        """
        try:
            quality_str = (
                "HI_RES_LOSSLESS"
                if audio_format == "flac_hires"
                else self._quality_parse[quality_tier]
            )
            stream_data = await self._api.get_stream_url(track_id, quality_str)
            return StreamResult(stream_data=stream_data, session_type=None)
        except Exception as e:
            error = str(e)
            if "Asset is not ready for playback" in error:
                error = f"Track [{track_id}] is not available in your region"
            return StreamResult(stream_data=None, session_type=error)

    def parse_manifest(
        self,
        stream_data: dict[str, Any],
        fallback_codec: CodecEnum = CodecEnum.FLAC,
    ) -> ManifestResult:
        """Parse stream manifest and extract audio track information.

        Args:
            stream_data: Stream data containing manifest.
            fallback_codec: Codec to use if parsing fails.

        Returns:
            ManifestResult with audio_track, codec, and download_data.
        """
        manifest_type = stream_data.get("manifestMimeType", "")
        manifest_dict: dict[str, Any] = {}
        audio_track: AudioTrack | None = None
        track_codec = fallback_codec

        if manifest_type == "application/dash+xml":
            manifest_bytes = base64.b64decode(stream_data["manifest"])
            audio_tracks = self.parse_mpd(manifest_bytes)
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

        return ManifestResult(
            audio_track=audio_track,
            codec=track_codec,
            download_data=manifest_dict,
        )

    async def process_stream_data(
        self,
        stream_data: dict[str, Any] | None,
        track_id: str,
        codec_options: CodecOptions,
    ) -> ManifestResult:
        """Process stream data and handle codec restrictions.

        Args:
            stream_data: Stream data dictionary.
            track_id: Track identifier.
            codec_options: Codec preference options.

        Returns:
            ManifestResult with audio_track, codec, and download_data.
        """
        if not stream_data:
            return ManifestResult(
                audio_track=None, codec=CodecEnum.FLAC, download_data=None
            )

        manifest = self.parse_manifest(stream_data)

        # Handle proprietary codec restrictions
        if (
            not manifest.codec.spatial
            and not codec_options.proprietary_codecs
            and manifest.codec.proprietary
        ):
            stream_data = await self._api.get_stream_url(track_id, "LOSSLESS")
            manifest = self.parse_manifest(stream_data, CodecEnum.FLAC)

        if manifest.audio_track:
            download_data: dict[str, Any] = {"audio_track": manifest.audio_track}
        else:
            download_data = {
                "file_url": (manifest.download_data or {}).get("urls", [""])[0]
            }

        return ManifestResult(
            audio_track=manifest.audio_track,
            codec=manifest.codec,
            download_data=download_data,
        )

    def calculate_audio_specs(
        self,
        track_codec: CodecEnum,
        stream_data: dict[str, Any] | None,
        audio_track: AudioTrack | None,
    ) -> AudioSpecs:
        """Calculate bit depth, sample rate, and bitrate.

        Args:
            track_codec: Track codec.
            stream_data: Stream data dictionary.
            audio_track: Audio track information.

        Returns:
            AudioSpecs with bit_depth, sample_rate, and bitrate.
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

        return AudioSpecs(
            bit_depth=bit_depth,
            sample_rate=sample_rate,
            bitrate=bitrate,
        )

    # ------------------------------------------------------------------
    # MPD parsing
    # ------------------------------------------------------------------

    def parse_mpd(self, xml_data: bytes) -> list[AudioTrack]:
        """Parse MPEG-DASH MPD manifest.

        Args:
            xml_data: Raw XML manifest data.

        Returns:
            List of AudioTrack objects.
        """
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

    def parse_codec(self, codec_str: str) -> CodecEnum:
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

    def _build_audio_track(self, rep: Any, seg_template: Any) -> AudioTrack | None:
        """Build AudioTrack from representation.

        Args:
            rep: Representation XML element.
            seg_template: SegmentTemplate XML element.

        Returns:
            AudioTrack object or None if invalid.
        """
        if seg_template is None:
            return None

        codec_str = str(rep.get("codecs") or "")
        codec = self.parse_codec(codec_str)

        track_urls = [str(seg_template.get("initialization") or "")]
        start_number = int(str(seg_template.get("startNumber") or "1"))

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

    @staticmethod
    def _parse_segment_timeline(seg_timeline: Any) -> list[int]:
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

    @staticmethod
    def _generate_segment_urls(
        media_template: str,
        seg_num_list: list[int],
        start_number: int,
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
