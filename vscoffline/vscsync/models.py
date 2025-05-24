"""
Models used in vscsync
"""

import pathlib
from dataclasses import dataclass, field, fields
from typing import Any

from pytimeparse.timeparse import timeparse


@dataclass(slots=True)
class File:
    assetType: str
    source: str

    @staticmethod
    def from_dict(input_dict: dict[str, Any]) -> "File":
        return File(**{k: str(v) for k, v in input_dict.items() if k in {"assetType", "source"}})


@dataclass(slots=True)
class Property:
    key: str
    value: str

    @staticmethod
    def from_dict(input_dict: dict[str, Any]) -> "Property":
        return Property(**{k: str(v) for k, v in input_dict.items() if k in {"key", "value"}})


@dataclass(slots=True)
class VSCExtensionVersionDefinition:
    version: str
    flags: str
    lastUpdated: str
    files: list[File]
    properties: list[Property]
    assetUri: str
    fallbackAssetUri: str
    targetPlatform: str | None = None

    def __repr__(self):
        strs = f"<{self.__class__.__name__}> {self.version} ({self.lastUpdated}) - Version: {self.version}"
        return strs

    @staticmethod
    def from_dict(obj: dict[str, Any]) -> "VSCExtensionVersionDefinition":
        # we do this one the long way due to the changes with files & properties
        return VSCExtensionVersionDefinition(
            str(obj.get("version")),
            str(obj.get("flags")),
            str(obj.get("lastUpdated")),
            [File.from_dict(y) for y in obj.get("files", [])],
            [
                Property.from_dict(y) for y in obj.get("properties", [])
            ],  # older versions do not have properties so we need to set to empty array
            str(obj.get("assetUri")),
            str(obj.get("fallbackAssetUri")),
            obj.get("targetPlatform", None),
        )

    def isprerelease(self) -> bool:
        for property in self.properties:
            if property.key == "Microsoft.VisualStudio.Code.PreRelease" and property.value == "true":
                return True
        return False


@dataclass(slots=True)
class VSCSyncConfig:
    """
    A config class for VSCSync to help improve readability instead of using a argparse.Namespace object
    """

    sync: bool
    syncall: bool
    artifactdir: pathlib.Path = pathlib.Path("../artifacts")
    checkbinaries: bool = False
    checkinsider: bool = False
    checkextensions: bool = False
    checkspecified: bool = False
    extensionname: str = ""
    extensionsearch: str = ""
    prerelease: bool = False
    updatebinaries: bool = False
    updateextensions: bool = False
    updatemalicious: bool = False
    skipbinaries: bool = False
    version: str = "1.73.1"
    totalrecommended: int = 500
    frequency: str | int | float | None = None
    artifactdir_installers: pathlib.Path = field(init=False)
    artifactdir_extensions: pathlib.Path = field(init=False)

    def __post_init__(self) -> None:
        """
        Various dependency resolutions and post field inits for artifactdir etc
        """
        if isinstance(self.artifactdir, str):
            self.artifactdir = pathlib.Path(self.artifactdir)

        # add remaining subpaths for artifactdir
        self.artifactdir_installers = self.artifactdir.joinpath("installers")
        self.artifactdir_extensions = self.artifactdir.joinpath("extensions")

        # overwrite sync args based on whether we're told to do everything or not
        if self.sync or self.syncall:
            self.checkbinaries = True
            self.checkextensions = True
            self.updatebinaries = True
            self.updateextensions = True
            self.updatemalicious = True
            self.checkspecified = True
            if not self.frequency:
                self.frequency = "12h"

        if self.syncall:
            self.extensionsearch = "*"
            self.checkinsider = True

        if self.updatebinaries:
            self.checkbinaries = True

        if self.frequency:
            self.frequency = timeparse(self.frequency)

    @classmethod
    def from_dict(cls, input_dict: dict[str, Any]) -> "VSCSyncConfig":
        cls_fields = {f.name for f in fields(cls)}
        return VSCSyncConfig(**{k: v for k, v in input_dict.items() if k in cls_fields})
