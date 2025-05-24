import datetime
import hashlib
import logging as log
import os
import pathlib
from enum import IntFlag
from typing import Any

import orjson

import vscoffline.vscsync.models as sync_models

PLATFORMS = [
    "win32",
    "linux",
    "linux-deb",
    "linux-rpm",
    "darwin",
    "darwin-universal",
    "linux-snap",
    "server-linux",
    "server-linux-legacy",
    "server-linux-alpine",
    "cli-alpine",
]
ARCHITECTURES = ["", "x64", "arm64", "armhf"]
BUILDTYPES = ["", "archive", "user", "web"]
QUALITIES = ["stable", "insider"]

URL_BINUPDATES = "https://update.code.visualstudio.com/api/update/"
URL_RECOMMENDATIONS = "https://main.vscode-cdn.net/extensions/workspaceRecommendations.json.gz"
URL_MARKETPLACEQUERY = "https://marketplace.visualstudio.com/_apis/public/gallery/extensionquery"
URL_MALICIOUS = "https://main.vscode-cdn.net/extensions/marketplace.json"

URLROOT = "https://update.code.visualstudio.com"
ARTIFACTS = "/artifacts/"
ARTIFACTS_INSTALLERS = "/artifacts/installers"
ARTIFACTS_EXTENSIONS = "/artifacts/extensions"
ARTIFACT_RECOMMENDATION = "/artifacts/recommendations.json"
ARTIFACT_MALICIOUS = "/artifacts/malicious.json"

TIMEOUT = 12


class QueryFlags(IntFlag):
    __no_flags_name__ = "NoneDefined"
    NoneDefined = 0x0
    IncludeVersions = 0x1
    IncludeFiles = 0x2
    IncludeCategoryAndTags = 0x4
    IncludeSharedAccounts = 0x8
    IncludeVersionProperties = 0x10
    ExcludeNonValidated = 0x20
    IncludeInstallationTargets = 0x40
    IncludeAssetUri = 0x80
    IncludeStatistics = 0x100
    IncludeLatestVersionOnly = 0x200
    Unpublished = 0x1000


DEFAULT_QUERY_FLAGS = (
    QueryFlags.IncludeFiles
    | QueryFlags.IncludeVersionProperties
    | QueryFlags.IncludeAssetUri
    | QueryFlags.IncludeStatistics
    | QueryFlags.IncludeLatestVersionOnly
)

RELEASE_QUERY_FLAGS = (
    QueryFlags.IncludeFiles
    | QueryFlags.IncludeVersionProperties
    | QueryFlags.IncludeAssetUri
    | QueryFlags.IncludeStatistics
    | QueryFlags.IncludeVersions
)


class FilterType(IntFlag):
    __no_flags_name__ = "Target"
    Tag = 1
    ExtensionId = 4
    Category = 5
    ExtensionName = 7
    Target = 8
    Featured = 9
    SearchText = 10
    ExcludeWithFlags = 12
    UndefinedType = 14


class SortBy(IntFlag):
    __no_flags_name__ = "NoneOrRelevance"
    NoneOrRelevance = 0
    LastUpdatedDate = 1
    Title = 2
    PublisherName = 3
    InstallCount = 4
    PublishedDate = 5
    AverageRating = 6
    WeightedRating = 12


class SortOrder(IntFlag):
    __no_flags_name__ = "Default"
    Default = 0
    Ascending = 1
    Descending = 2


def hash_file_and_check(filepath: pathlib.Path, expectedchecksum: str) -> bool:
    """
    Hashes a file and checks for the expected checksum.

    Checksum is sha256 default implementation.
    """
    h = hashlib.sha256()
    with filepath.open("rb") as fl:
        for chunk in iter(lambda: fl.read(4096), b""):
            h.update(chunk)
    return expectedchecksum == h.hexdigest()


def load_json(filepath: pathlib.Path) -> list[Any] | dict[str, Any]:
    result = []
    if not filepath.exists():
        log.debug(f"Unable to load json from {filepath.absolute()}. Does not exist.")
        return result
    elif filepath.is_dir():
        log.debug(f"Cannot load json at path {filepath.absolute()}. It is a directory")
        return result

    with open(filepath, "rb") as fp:
        try:
            result = orjson.loads(fp.read())
            if not result:
                return []
        except orjson.JSONDecodeError as err:
            log.debug(f"JSONDecodeError while processing {filepath.absolute()} \n error: {str(err)}")
            return []
    return result


def magic_json_encoder(obj: Any) -> Any:
    o_dict = dict()
    try:
        o_dict = {key: getattr(obj, key, None) for key in obj.__slots__}
    except AttributeError:
        pass
    try:
        o_dict = obj.__dict__
    except AttributeError:
        pass
    if isinstance(obj, sync_models.VSCExtensionVersionDefinition) and "targetPlatform" in o_dict:
        del o_dict["targetPlatform"]
    if o_dict:
        return o_dict
    raise TypeError(f"{type(obj)} is not serializable")


def write_json(filepath: pathlib.Path, content: Any) -> None:
    with open(filepath, "wb") as outfile:
        outfile.write(
            orjson.dumps(
                content,
                option=orjson.OPT_NAIVE_UTC | orjson.OPT_INDENT_2,
                default=magic_json_encoder,
            )
        )


def first_file(filepath: pathlib.Path, pattern: str, reverse: bool = False) -> pathlib.Path | bool:
    # 3 cases:
    # no results
    # only one result - order doesn't matter
    # more than 1 - sort
    results = [*filepath.glob(pattern)]
    if not results:
        return False
    elif len(results) >= 1 and reverse:
        results.sort(reverse=True)
    return results[0]


def folders_in_folder(filepath: str | pathlib.Path) -> list[os.DirEntry]:
    return sorted(
        (f for f in os.scandir(filepath) if f.is_dir()),
        key=lambda f: f.name,
        reverse=True,
    )


def files_in_folder(filepath: str | pathlib.Path) -> list[os.DirEntry]:
    return sorted(
        (f for f in os.scandir(filepath) if f.is_file()),
        key=lambda f: f.name,
        reverse=True,
    )


def seconds_to_human_time(seconds: int) -> str:
    return str(datetime.timedelta(seconds=seconds))


def from_json_datetime(jsondate: str) -> datetime.datetime:
    return datetime.datetime.strptime(jsondate, "%Y-%m-%dT%H:%M:%S.%fZ")


def validate_platform(platform: str) -> bool:
    return platform in PLATFORMS


def validate_architecture(arch: str) -> bool:
    return arch in ARCHITECTURES


def validate_buildtype(buildtype: str) -> bool:
    return buildtype in BUILDTYPES


def validate_quality(quality: str) -> bool:
    return quality in QUALITIES
