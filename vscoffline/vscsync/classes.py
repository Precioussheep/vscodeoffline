import datetime
import itertools
import json
import pathlib
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Union

import requests
from logzero import logger as log

import vscoffline.vscsync.models as sync_models
from vscoffline import utils


class VSCUpdateDefinition:

    __slots__ = [
        "identity",
        "platform",
        "architecture",
        "buildtype",
        "quality",
        "updateurl",
        "name",
        "version",
        "productVersion",
        "hash",
        "timestamp",
        "sha256hash",
        "supportsFastUpdate",
        "checkedForUpdate",
    ]

    def __init__(
        self,
        platform: str,
        architecture: str,
        buildtype: str,
        quality: str,
        auto_check_update: bool = False,
    ):

        if not utils.validate_platform(platform):
            raise ValueError(f"Platform {platform} invalid or not implemented")

        if not utils.validate_architecture(architecture):
            raise ValueError(f"Architecture {architecture} invalid or not implemented")

        if not utils.validate_buildtype(buildtype):
            raise ValueError(f"Buildtype {buildtype} invalid or not implemented")

        if not utils.validate_quality(quality):
            raise ValueError(f"Quality {quality} invalid or not implemented")

        self.identity = platform

        if architecture:
            self.identity += f"-{architecture}"
        if buildtype:
            self.identity += f"-{buildtype}"

        self.platform: str = platform
        self.architecture: str = architecture
        self.buildtype: str = buildtype
        self.quality: str = quality

        # some minimal defaults so if download_update is called before check_for_update,
        # errors will raise correctly.
        # we don't define everything here because the use of `__slots__` above has already created structure for it,
        # meaning we don't need a bunch of `None` values floating around
        self.checkedForUpdate: bool = False
        self.updateurl: Optional[str] = None

        if auto_check_update:
            self.check_for_update()

    def check_for_update(self, old_commit_id: str = "7c4205b5c6e52a53b81c69d2b2dc8a627abaa0ba") -> bool:
        """
        Populate Class data for particular build based on old commit version. Defaults to old commit
        to look for latest, if available.
        """
        # its pretty unlikely for self.identity & self.quality not to exist
        # since they must be passed in class creation.
        url = f"{utils.URL_BINUPDATES}{self.identity}/{self.quality}/{old_commit_id}"

        log.debug(f"Update url {url}")
        result = requests.get(url, allow_redirects=True, timeout=utils.TIMEOUT)
        self.checkedForUpdate = True

        if result.status_code == 204:
            # No update available
            log.debug(f"No update available for {self}. Returning")
            return False
        elif result.status_code != 200:
            # Unhandled response from API
            log.warning(f"Update url failed {url}. Unhandled status code {result.status_code}")
            return False

        try:
            jresult = result.json()
        except Exception as err:
            raise ValueError("Unable to decode response from update check. Failing.") from err

        self.updateurl = jresult["url"]
        self.name = jresult["name"]
        self.version = jresult["version"]
        self.productVersion = jresult["productVersion"]
        self.hash = jresult["hash"]
        self.timestamp = jresult["timestamp"]
        self.sha256hash = jresult["sha256hash"]

        if "supportsFastUpdate" in jresult:
            self.supportsFastUpdate = jresult["supportsFastUpdate"]
        else:
            self.supportsFastUpdate = False

        return bool(self.updateurl)

    def download_update(self, destination: pathlib.Path) -> Optional[bool]:
        if not self.checkedForUpdate:
            log.warning("Cannot download update if the update definition has not been downloaded")
            return
        if not self.updateurl:
            log.warning("Cannot download update if there is no url to download from")
            return

        destination_path = pathlib.Path(destination, self.identity, self.quality)
        destination_path.mkdir(parents=True, exist_ok=True)

        suffix = pathlib.Path(self.updateurl).suffix
        if ".gz" in suffix:
            suffix = "".join(pathlib.Path(self.updateurl).suffixes)
        destfile = destination_path.joinpath(f"vscode-{self.name}{suffix}")

        if destfile.exists() and utils.hash_file_and_check(destfile, self.sha256hash):
            log.debug(f"Previously downloaded {self}")
        else:
            log.info(f"Downloading {self} to {destfile}")
            result = requests.get(self.updateurl, allow_redirects=True, timeout=utils.TIMEOUT)
            with open(destfile, "wb") as outfile:
                outfile.write(result.content)
            if not utils.hash_file_and_check(destfile, self.sha256hash):
                log.warning(f"HASH MISMATCH for {self} at {destfile} expected {self.sha256hash}. Removing local file.")
                destfile.unlink(missing_ok=True)
                return False
            log.debug(f"Hash ok for {self} with {self.sha256hash}")
        return True

    def save_state(self, destination: pathlib.Path) -> None:
        destination_path = pathlib.Path(destination, self.identity)
        destination_path.mkdir(parents=True, exist_ok=True)
        # Write version details blob as latest
        utils.write_json(destination_path.joinpath(self.quality, "latest.json"), self)
        # Write version details blob as the commit id
        if self.version:
            utils.write_json(destination_path.joinpath(self.quality, f"{self.version}.json"), self)

    def __repr__(self):
        strs = f"<{self.__class__.__name__}> {self.quality}/{self.identity}"
        if self.updateurl:
            strs += f" - Version: {self.name} ({self.version})"
        elif self.checkedForUpdate:
            strs += f" - Latest version not available"
        return strs


class VSCExtensionDefinition:

    __slots__ = ["identity", "extensionId", "recommended", "versions"]

    def __init__(self, identity: str, raw: Optional[Dict[str, Any]] = None):
        self.identity: str = identity
        self.extensionId: Optional[str] = None
        self.recommended: bool = False
        self.versions: List[sync_models.VSCExtensionVersionDefinition] = []

        # process raw input from api call (if any)
        if not raw:
            return
        if "extensionId" in raw:
            self.extensionId = raw["extensionId"]
        if "versions" in raw:
            self.versions = [sync_models.VSCExtensionVersionDefinition.from_dict(ver) for ver in raw["versions"]]

    def __repr__(self):
        strs = f"<{self.__class__.__name__}> {self.identity} ({self.extensionId}) - Version: {self.version()}"
        return strs

    def download_assets(self, destination: pathlib.Path) -> None:
        for version in self.versions:
            targetplatform = version.targetPlatform or ""
            ver_destination = pathlib.Path(destination, self.identity, version.version, targetplatform)
            for file in version.files:
                url = file.source
                if not url:
                    log.warning(
                        f"download_assets() cannot download update as asset url is missing. Missing file info: \n{file}"
                    )
                    continue
                asset = file.assetType
                destfile = ver_destination.joinpath(f"{asset}")
                destfile.parent.mkdir(parents=True, exist_ok=True)
                log.debug(f"Downloading {self.identity} {asset} to {destfile}")
                result = requests.get(url, allow_redirects=True, timeout=utils.TIMEOUT)
                try:
                    result.raise_for_status()
                except requests.HTTPError as err:
                    log.info(
                        f"Download request for {self.identity} - {version.version} failed with detail: {str(err)} \n Response body: {result.text}"
                    )
                    continue
                with open(destfile, "wb") as dest:
                    dest.write(result.content)
                log.debug(f"Finished Downloading {self.identity} {asset} to {destfile}")

    def process_embedded_extensions(
        self, destination: Union[str, pathlib.Path], mp: "VSCMarketplace"
    ) -> List["VSCExtensionDefinition"]:
        """
        Check an extension's Manifest for an extension pack (e.g. more extensions to download)
        """
        bonusextensions: List[VSCExtensionDefinition] = []
        for version in self.versions:
            targetplatform = version.targetPlatform or ""
            manifestpath = pathlib.Path(
                destination, self.identity, version.version, targetplatform, "Microsoft.VisualStudio.Code.Manifest"
            )
            manifest = utils.load_json(manifestpath)
            if manifest and "extensionPack" in manifest:
                for extname in manifest["extensionPack"]:
                    bonusextension = mp.search_by_extension_name(extname)
                    if bonusextension:
                        bonusextensions.append(bonusextension)
        return bonusextensions

    def save_state(self, destination: Union[str, pathlib.Path]) -> None:
        destination_path = pathlib.Path(destination, self.identity)
        destination_path.mkdir(parents=True, exist_ok=True)
        utils.write_json(destination_path.joinpath("latest.json"), self)
        # Save in the version folder
        for version in self.versions:
            utils.write_json(destination_path.joinpath(version.version, "extension.json"), self)

    def isprerelease(self) -> bool:
        # we assume if _any_ is pre-release, then _all_ are pre-release.
        # previously this only checked the first version. This will check all versions
        for ver in self.versions:
            for property in ver.properties:
                if property.key == "Microsoft.VisualStudio.Code.PreRelease" and property.value == "true":
                    return True
        return False

    def get_latest_release_versions(self) -> List[sync_models.VSCExtensionVersionDefinition]:
        if not self.versions:
            return []
        if len(self.versions) == 1:
            return self.versions

        release_versions = [ver for ver in self.versions if not ver.isprerelease()]
        if not release_versions:
            return []

        release_versions.sort(reverse=True, key=lambda x: x.lastUpdated)
        latest_version = release_versions[0].version
        return [ver for ver in release_versions if ver.version == latest_version]

    def version(self) -> str:
        if not self.versions:
            return ""
        elif len(self.versions) == 1:
            return self.versions[0]["version"]

        return ";".join(map(lambda x: x.version, self.versions))

    def set_recommended(self) -> None:
        self.recommended = True


class VSCMarketplace:

    __slots__ = [
        "insider",
        "prerelease",
        "version",
        "_headers",
    ]

    def __init__(self, insider: bool, prerelease: bool, version: str) -> None:
        self.insider = insider
        self.prerelease = prerelease
        self.version = version

        # generate headers for communicating with marketplace
        if self.insider:
            insider = "-insider"
        else:
            insider = ""
        self._headers = {
            "content-type": "application/json",
            "accept": "application/json;api-version=3.0-preview.1",
            "accept-encoding": "gzip, deflate, br",
            "User-Agent": f"VSCode {self.version}{insider}",
            "x-market-client-Id": f"VSCode {self.version}{insider}",
            "x-market-user-Id": str(uuid.uuid4()),
        }
        del insider

    def __repr__(self):
        strs = f"<{self.__class__.__name__}>"
        return strs

    def get_specified(
        self, specifiedpath: pathlib.Path, include_pre_release: bool = False
    ) -> List[VSCExtensionDefinition]:

        if not specifiedpath.exists():
            specifiedpath.parent.mkdir(parents=True, exist_ok=True)
            utils.write_json(specifiedpath, {"extensions": []})
            log.info(f"Created empty list of custom extensions to mirror at {specifiedpath.absolute()}")
            return

        specified_extensions = utils.load_json(specifiedpath)
        if not specified_extensions:
            log.warning(f"Empty File Loaded for Specified Extensions. Ignoring")
            return
        if "extensions" not in specified_extensions:
            log.warning(
                f"""
                Malformed json found. Ignoring
                Expected: {"extensions": ["extension_name_1", "extension_name_2", ...]}
                Found: {specified_extensions}.
                """
            )
            return

        found_specified_extensions = []
        for package_name in specified_extensions:
            extension = self.search_by_extension_name(package_name, include_pre_release)
            if extension:
                log.info(f"Adding extension to mirror: {package_name}")
                found_specified_extensions.append(extension)
            else:
                log.debug(
                    f"get_specified failed finding an extension by name for {package_name}. This extension has likely been removed."
                )
        return found_specified_extensions

    def search_by_extension_name(
        self, extensionname: str, include_pre_release: bool = False
    ) -> Union[bool, VSCExtensionDefinition]:
        # adjust query flags based on whether its pre-release or not
        if self.prerelease:
            releaseQueryFlags = 0
        else:
            releaseQueryFlags = (
                utils.QueryFlags.IncludeFiles
                | utils.QueryFlags.IncludeVersionProperties
                | utils.QueryFlags.IncludeAssetUri
                | utils.QueryFlags.IncludeStatistics
                | utils.QueryFlags.IncludeStatistics
                | utils.QueryFlags.IncludeVersions
            )
        query_results = self._query_marketplace(
            utils.FilterType.ExtensionName, extensionname, queryFlags=releaseQueryFlags
        )
        if not query_results or len(query_results) > 1:
            return False

        result = query_results[0]
        if not include_pre_release:
            result.versions = result.get_latest_release_versions()
        return result

    def search_by_text(self, searchtext: str) -> List[VSCExtensionDefinition]:
        if searchtext == "*":
            searchtext = ""

        return self._query_marketplace(utils.FilterType.SearchText, searchtext)

    def search_top_n(self, n: int = 200) -> List[VSCExtensionDefinition]:
        log.info(f"Searching for top {n} recommended extensions")
        return self._query_marketplace(
            utils.FilterType.SearchText,
            "",
            limit=n,
            sortOrder=utils.SortOrder.Descending,
            sortBy=utils.SortBy.InstallCount,
        )

    def search_release_by_extension_id(self, extensionid) -> Union[bool, VSCExtensionDefinition]:
        log.debug(f"Searching for release candidate by extensionId: {extensionid}")
        releaseQueryFlags = (
            utils.QueryFlags.IncludeFiles
            | utils.QueryFlags.IncludeVersionProperties
            | utils.QueryFlags.IncludeAssetUri
            | utils.QueryFlags.IncludeStatistics
            | utils.QueryFlags.IncludeStatistics
            | utils.QueryFlags.IncludeVersions
        )
        result = self._query_marketplace(utils.FilterType.ExtensionId, extensionid, queryFlags=releaseQueryFlags)
        if result and len(result) == 1:
            return result[0]
        else:
            log.warning(f"search_release_by_extension_id failed {extensionid}")
            return False

    def get_recommendations(self, destination: pathlib.Path, totalrecommended: int) -> List[VSCExtensionDefinition]:
        recommendations = self.search_top_n(totalrecommended)
        recommended_old = self.get_recommendations_old(destination)

        for extension in recommendations:
            # If the extension has already been found then prevent it from being collected again when processing the old recommendation list
            if extension.identity in recommended_old:
                recommended_old.remove(extension.identity)

        for packagename in recommended_old:
            extension = self.search_by_extension_name(packagename)
            if extension:
                recommendations.append(extension)
            else:
                log.debug(
                    f"get_recommendations failed finding a recommended extension by name for {packagename}. This extension has likely been removed."
                )

        for recommendation in recommendations:
            recommendation.set_recommended()
            #  If the found extension is a prerelease version search for the next available release version
            if not self.prerelease and recommendation.isprerelease():
                extension = self.search_release_by_extension_id(recommendation.extensionId)
                if extension:
                    recommendation.versions = extension.get_latest_release_versions()
        return recommendations

    def get_recommendations_old(self, destination: pathlib.Path) -> Union[bool, Set[str]]:
        result = requests.get(utils.URL_RECOMMENDATIONS, allow_redirects=True, timeout=utils.TIMEOUT)
        if result.status_code != 200:
            log.warning(
                f"get_recommendations failed accessing url {utils.URL_RECOMMENDATIONS}, unhandled status code {result.status_code}"
            )
            return False
        try:
            jresult = result.json()
        except requests.exceptions.JSONDecodeError as err:
            log.warning(f"Failed to decode json from recommendations URL. Response body: {result.text}")
            return False

        utils.write_json(destination.joinpath("recommendations.json"), jresult)

        # To SET to remove duplicates
        packages: Set[str] = set()
        for recommendation in jresult["workspaceRecommendations"]:
            packages.update(recommendation["recommendations"])

        return packages

    def get_malicious(
        self, destination: pathlib.Path, extensions: Optional[Dict[str, VSCExtensionDefinition]] = None
    ) -> None:
        result = requests.get(utils.URL_MALICIOUS, allow_redirects=True, timeout=utils.TIMEOUT)
        if result.status_code != 200:
            log.warning(
                f"get_malicious failed accessing url {utils.URL_MALICIOUS}, unhandled status code {result.status_code}"
            )
            return False
        # Remove random utf-8 nbsp from server response
        stripped = result.content.decode("utf-8", "ignore").replace("\xa0", "")
        jresult = json.loads(stripped)
        utils.write_json(destination.joinpath("malicious.json"), jresult)

        if not extensions:
            return

        for malicious in jresult["malicious"]:
            log.debug(f"Malicious extension {malicious}")
            if malicious in extensions.keys():
                log.warning(f"Preventing malicious extension {malicious} from being downloaded")
                del extensions[malicious]

    def _build_query(
        self,
        filtertype: int,
        filtervalue: str,
        pageNumber: int,
        pageSize: int,
        queryFlags: int = 0,
        sortBy: int = utils.SortBy.NoneOrRelevance,
        sortOrder: int = utils.SortOrder.Default,
    ) -> Dict[str, Any]:
        if queryFlags == 0:
            queryFlags = utils.DEFAULT_QUERY_FLAGS
        payload = {
            "assetTypes": [],
            "filters": [self._build_query_filter(filtertype, filtervalue, pageNumber, pageSize, sortBy, sortOrder)],
            "flags": int(queryFlags),
        }
        return payload

    def _build_query_filter(
        self,
        filtertype: int,
        filtervalue: str,
        pageNumber: int,
        pageSize: int,
        sortBy: int = utils.SortBy.NoneOrRelevance,
        sortOrder: int = utils.SortOrder.Default,
    ) -> Dict[str, Any]:
        result = {
            "pageNumber": pageNumber,
            "pageSize": pageSize,
            "sortBy": sortBy,
            "sortOrder": sortOrder,
            "criteria": [
                self._build_query_filter_criteria(utils.FilterType.Target, "Microsoft.VisualStudio.Code"),
                self._build_query_filter_criteria(
                    utils.FilterType.ExcludeWithFlags, str(int(utils.QueryFlags.Unpublished))
                ),
            ],
        }

        if filtervalue != "":
            result["criteria"].append(self._build_query_filter_criteria(filtertype, filtervalue))

        return result

    @staticmethod
    def _build_query_filter_criteria(filtertype: Union[int, float], queryvalue: str) -> Dict[str, Union[str, int]]:
        return {"filterType": int(filtertype), "value": queryvalue}

    def _query_marketplace(
        self,
        filtertype: int,
        filtervalue: str,
        pageNumber: int = 0,
        pageSize: int = 500,
        limit: int = 0,
        sortBy: int = utils.SortBy.NoneOrRelevance,
        sortOrder: int = utils.SortOrder.Default,
        queryFlags: int = 0,
    ) -> List[VSCExtensionDefinition]:
        extensions = {}
        total = 0
        count = 0

        if 0 < limit < pageSize:
            pageSize = limit

        while count <= total:
            pageNumber = pageNumber + 1
            query = self._build_query(filtertype, filtervalue, pageNumber, pageSize, queryFlags, sortBy, sortOrder)
            result = None
            for i in range(10):
                if i > 0:
                    log.info("Retrying pull page %d attempt %d." % (pageNumber, i + 1))
                try:
                    result = requests.post(
                        utils.URL_MARKETPLACEQUERY,
                        headers=self._headers,
                        json=query,
                        allow_redirects=True,
                        timeout=utils.TIMEOUT,
                    )
                    if result:
                        break
                except requests.exceptions.ProxyError:
                    log.info("ProxyError: Retrying.")
                except requests.exceptions.ReadTimeout:
                    log.info("ReadTimeout: Retrying.")
            if not result:
                log.info("Failed 10 attempts to query marketplace. Giving up.")
                break
            try:
                jresult = result.json()
            except Exception as err:
                log.info("Failed parsing json from marketplace api query")
                continue

            count = count + pageSize

            if "results" not in jresult:
                log.info("No results in marketplace return query.")
                continue

            for jres in jresult["results"]:
                for extension in jres["extensions"]:
                    identity = f"""{extension["publisher"]["publisherName"]}.{extension["extensionName"]}"""
                    mpd = VSCExtensionDefinition(identity=identity, raw=extension)
                    extensions[identity] = mpd

                if "resultMetadata" in jres:
                    for resmd in jres["resultMetadata"]:
                        if "ResultCount" in resmd["metadataType"]:
                            total = resmd["metadataItems"][0]["count"]

            if limit > 0 and count >= limit:
                break

        return list(extensions.values())


# ---------------------------------------------------------------------------------------------------------------------
# Util functions that don't fit to a class


def get_latest_versions(insider: bool = False) -> Dict[str, VSCUpdateDefinition]:
    """
    Get the latest versions for all known build types (or at least the ones we care about)
    for VSCode

    :param insider: Whether to check for insider builds or not
    """
    versions: Dict[str, str] = {}
    # Cartesian product rather than a 4-deep `for` loop
    all_vsc_types = itertools.product(utils.PLATFORMS, utils.ARCHITECTURES, utils.BUILDTYPES, utils.QUALITIES)
    for platform, arch, buildtype, quality in all_vsc_types:
        # TODO: put the exceptions elsewhere
        if quality == "insider" and not insider:
            continue
        if platform == "win32" and arch == "ia32":
            continue
        if platform == "darwin" and (arch or buildtype):
            continue
        if "linux" in platform and (arch == "" or buildtype):
            continue
        ver = VSCUpdateDefinition(platform, arch, buildtype, quality, auto_check_update=True)
        log.info(ver)
        versions[f"{ver.identity}-{ver.quality}"] = ver
    return versions


def signal_updated(artifactdir: pathlib.Path) -> None:
    artifactdir.mkdir(parents=True, exist_ok=True)
    signalpath = pathlib.Path(artifactdir, "updated.json")
    result = {"updated": datetime.datetime.utcnow()}
    utils.write_json(signalpath, result)
