import asyncio
import logging as log
import time
from typing import Any
from packaging.version import Version

import anyio
from pydantic import BaseModel

import vscoffline.utils as utils
import vscoffline.vscgallery.async_utils as autils

STATIC_STAT_BUILDER = {"averagerating": 0, "install": 0, "weightedRating": 0}


class ExtensionQuery(BaseModel):
    filters: list[dict[str, Any]]
    flags: str | int
    assetTypes: list[Any]


class VSCDirectoryBrowse:
    __slots__ = ["root"]

    def __init__(self, root: anyio.Path) -> None:
        if not isinstance(root, anyio.Path):
            self.root = anyio.Path(root)
        self.root = root

    async def path_valid(self, path: str) -> anyio.Path | bool:
        """
        path_valid: determine if the requested path is valid compred to the
        root path provided by the application - protecting somewhat against
        traversal attacks (ie: browse?path=../../etc/passwd)

        :param path: the requested path
        :type path: str
        :return: Either the path to return content for, or False if an invalid path
        :rtype: Path | bool
        """
        requested_path = self.root.joinpath(path)
        # Check the path requested
        # used os.path.commonpath before but we know the check we want to perform here
        # and removes an `os` import (likely imported eagerly in one of our imports, but we're here now)
        if not (str(await requested_path.absolute())).startswith(str(await self.root.absolute())):
            return False
        return requested_path

    @staticmethod
    async def simple_dir_browse_response(path: anyio.Path) -> str:
        """
        simple_dir_browse_response

        Generate browse paths in html based on a[n] (async) path.iterdir()
        for files and folders.

        :param path: The input path to generate html for.
        :type path: anyio.Path
        :return: Response html of the paths found, formatted for file downloads & browsing as required.
        :rtype: str
        """
        folder_list: list[str] = []
        files_list: list[str] = []
        async for item in path.iterdir():
            if await item.is_dir():
                folder_list.append(f'd <a href="/browse?path={await item.absolute()}">{item.name}</a><br />')
            elif await item.is_file():
                folder_list.append(f'f <a href="{await item.absolute()}">{item.name}</a><br />')
        return "\n".join(folder_list) + "\n".join(files_list)

class VSCGallery:
    __slots__ = [
        "extensions",
        "interval",
        "artifact_path",
        "installers_path",
        "extensions_path",
    ]

    def __init__(
        self,
        artifact_path: anyio.Path,
        installers_path: anyio.Path,
        extensions_path: anyio.Path,
        interval: int = 3600,
    ) -> None:
        self.extensions: dict[str, Any] = {}
        self.interval: int = interval
        self.artifact_path = artifact_path
        self.installers_path = installers_path
        self.extensions_path = extensions_path

    async def update_state_watcher(self) -> None:
        while True:
            await self.update_state()
            # can't use log here - doesn't show up due to not in fastapi logger context
            print(f"Finished extension check. Will check again in {self.interval} seconds")
            await asyncio.sleep(self.interval)

    async def update_state(self):
        start = time.time()
        # Load each extension
        # we use scandir here since it will provide the `is_dir` subfunction for filtering,
        # while being faster than a glob
        # still, try to keep to pathlib where we can for keeping it the same
        for extensiondir in [d async for d in self.extensions_path.glob("./*/") if await d.is_dir()]:
            # Load the latest version of each extension
            latest_path = extensiondir.joinpath("latest.json")

            latest = await autils.async_load_json(latest_path)

            if not latest or not isinstance(latest, dict):
                log.debug(f"Tried to load invalid manifest json {latest_path}")
                continue

            latest = await self.process_loaded_extension(latest, extensiondir)

            if not latest:
                log.debug(f"Unable to determine latest version {latest_path}")
                continue

            # Determine the latest version
            try:
                latestversion = latest["versions"][0]
            except IndexError:
                log.warning(f"Can't find latest version. Ignoring. Path: {await latest_path.absolute()}")
                continue

            # Find other versions
            async for ver_path in extensiondir.glob("./*/extension.json"):
                vers = await autils.async_load_json(ver_path)

                if not vers or not isinstance(vers, dict):
                    log.debug(f"Tried to load invalid version manifest json {await ver_path.absolute()}")
                    continue
                vers = await self.process_loaded_extension(vers, extensiondir)

                # If this extension.json is actually the latest version, then ignore it
                if not vers or latestversion == vers["versions"][0]:
                    continue

                # Append this other possible version
                latest["versions"].append(vers["versions"][0])

            # Sort versions
            latest["versions"] = sorted(latest["versions"], key=lambda k: Version(k["version"]), reverse=True)

            # Save the extension in the cache
            self.extensions[latest["identity"]] = latest
        log.info(f"Loaded {len(self.extensions)} extensions in {time.time() - start}")

    @staticmethod
    async def process_loaded_extension(extension: dict[str, Any], extensiondir: anyio.Path) -> dict[str, Any]:
        # Repoint asset urls
        for version in extension["versions"]:
            if "targetPlatform" in version and version["targetPlatform"]:
                to_join = str(await extensiondir.joinpath(version["version"], version["targetPlatform"]).absolute())
                asseturi = utils.URLROOT + to_join
            else:
                to_join = str(await extensiondir.joinpath(version["version"]).absolute())
                asseturi = utils.URLROOT + to_join

            version["assetUri"] = version["fallbackAssetUri"] = asseturi
            for asset in version["files"]:
                asset["source"] = f"""{asseturi}/{asset["assetType"]}"""

        # Map statistics for later lookup
        stats = STATIC_STAT_BUILDER.copy()
        if "statistics" not in extension or not extension["statistics"]:
            log.info(
                f"""Statistics are missing from extension {extension["identity"]} in {extensiondir}, generating."""
            )
        else:
            stats.update({stat["statisticName"]: stat["value"] for stat in extension["statistics"]})
        extension["stats"] = stats
        return extension

    @staticmethod
    def _sort(result: list[dict[str, Any]], sortby: int, sortorder: int) -> None:
        # NOTE: modifies result in place
        rev = sortorder == utils.SortOrder.Ascending

        if sortby == utils.SortBy.PublisherName:
            rev = not rev
            result.sort(key=lambda k: k["publisher"]["publisherName"], reverse=rev)

        elif sortby == utils.SortBy.InstallCount:
            result.sort(key=lambda k: k["stats"]["install"], reverse=rev)

        elif sortby == utils.SortBy.AverageRating:
            result.sort(key=lambda k: k["stats"]["averagerating"], reverse=rev)

        elif sortby == utils.SortBy.WeightedRating:
            result.sort(key=lambda k: k["stats"]["weightedRating"], reverse=rev)

        elif sortby == utils.SortBy.LastUpdatedDate:
            result.sort(key=lambda k: utils.from_json_datetime(k["lastUpdated"]), reverse=rev)

        elif sortby == utils.SortBy.PublishedDate:
            result.sort(key=lambda k: utils.from_json_datetime(k["publishedDate"]), reverse=rev)
        else:
            rev = not rev
            result.sort(key=lambda k: k["displayName"], reverse=rev)

    def _apply_criteria(self, criteria: list[dict[str, Any]]):
        # `self.extensions` may be modified by the update thread while this
        # function is executing so we need to operate on a copy
        extensions = self.extensions.copy()
        result = []

        for crit in criteria:
            if "filterType" not in crit or "value" not in crit:
                continue
            ft = utils.FilterType(crit["filterType"])
            val = crit["value"].lower()

            if ft == utils.FilterType.ExtensionId:
                for name in extensions:
                    if val == extensions[name]["extensionId"]:
                        result.append(extensions[name])

            elif ft == utils.FilterType.ExtensionName:
                for name in extensions:
                    if name.lower() == val:
                        result.append(extensions[name])

            elif ft == utils.FilterType.SearchText:
                for name in extensions:
                    # Search in extension name, display name and short description
                    if val in name.lower():
                        result.append(extensions[name])
                    elif "displayName" in extensions[name] and val in extensions[name]["displayName"].lower():
                        result.append(extensions[name])
                    elif (
                        "shortDescription" in extensions[name] and val in extensions[name]["shortDescription"].lower()
                    ):
                        result.append(extensions[name])

            elif ft == utils.FilterType.Tag or ft == utils.FilterType.Category or ft == utils.FilterType.Featured:
                # ?? Tags
                log.info(f"Not implemented filter type {ft} for {val}")
                continue

            elif ft == utils.FilterType.Target or ft == utils.FilterType.ExcludeWithFlags:
                # ExcludeWithFlags: Typically this ignores Unpublished Flag (4096) extensions
                # Target: Ignore the product, typically Visual Studio Code. If it's custom, then let it connect here
                continue

            else:
                log.warning(f"Undefined filter type {crit}")

        # Handle popular / recommended
        if len(result) <= 0 and len(criteria) <= 2:
            log.info(f"Search criteria {criteria}")
            result = [ext for ext in extensions.values() if "recommended" in ext and ext["recommended"]]

        return result

    @staticmethod
    def _build_response(resultingExtensions: list[dict[str, Any]]) -> dict[str, Any]:
        return {
            "results": [
                {
                    "extensions": resultingExtensions,
                    "pagingToken": None,
                    "resultMetadata": [
                        {
                            "metadataType": "ResultCount",
                            "metadataItems": [
                                {
                                    "name": "TotalCount",
                                    "count": len(resultingExtensions),
                                }
                            ],
                        }
                    ],
                }
            ]
        }
