import os
import pathlib
import time
import urllib.parse
from threading import Event, Thread
from typing import Any, Dict, List, Union
from wsgiref import simple_server

import falcon
from logzero import logger as log

import vscoffline.utils as utils

# -----------------------------------------------------------------------------
# STATIC VARIABLES

ARTIFACTS_ASPATH = pathlib.Path(utils.ARTIFACTS)
ARTIFACTS_INSTALLERS_ASPATH = pathlib.Path(utils.ARTIFACTS_INSTALLERS)
ARTIFACTS_EXTENSIONS_ASPATH = pathlib.Path(utils.ARTIFACTS_EXTENSIONS)
ARTIFACT_RECOMMENDATION_ASPATH = pathlib.Path(utils.ARTIFACT_RECOMMENDATION)
ARTIFACT_MALICIOUS_ASPATH = pathlib.Path(utils.ARTIFACT_MALICIOUS)

STATIC_STAT_BUILDER = {"averagerating": 0, "install": 0, "weightedRating": 0}

# TODO: Fix so it doesn't read from static location.
with open("/opt/vscoffline/vscgallery/content/browse.html", "r") as f:
    STATIC_BROWSE_HTML = f.read()

with open("/opt/vscoffline/vscgallery/content/index.html", "r") as f:
    STATIC_INDEX_HTML = f.read()

# -----------------------------------------------------------------------------
# begin obj creation for handling falcon requests


class VSCUpdater:
    @staticmethod
    def on_get(_: falcon.Request, resp: falcon.Response, platform: str, buildquality: str, commitid: str) -> None:
        update_dir = ARTIFACTS_INSTALLERS_ASPATH.joinpath(platform, buildquality)
        if not update_dir.exists():
            log.warning(
                f"Update build directory does not exist at {update_dir.absolute()}. Check sync or sync configuration."
            )
            resp.status = falcon.HTTP_500
            return

        latest_path = update_dir.joinpath("latest.json")
        latest = utils.load_json(latest_path)

        if not latest:
            resp.text = "Unable to load latest.json"
            log.warning(f"Unable to load latest.json for platform {platform} and buildquality {buildquality}")
            resp.status = falcon.HTTP_500
            return

        if latest["version"] == commitid:
            # No update available
            log.debug(f"Client {platform}, Quality {buildquality}. No Update available.")
            resp.status = falcon.HTTP_204
            return

        update_path = utils.first_file(update_dir, f"vscode-{latest['name']}.*")
        if not update_path:
            resp.text = "Unable to find update payload"
            log.warning(f"""Unable to find update payload from {update_dir}/vscode-{latest['name']}.*""")
            resp.status = falcon.HTTP_404
            return

        if not utils.hash_file_and_check(update_path, latest["sha256hash"]):
            resp.text = "Update payload hash mismatch"
            log.warning(f"Update payload hash mismatch {update_path}")
            resp.status = falcon.HTTP_403
            return

        # Url to get update
        latest["url"] = urllib.parse.urljoin(utils.URLROOT, str(update_path.absolute()))
        log.debug(f"Client {platform}, Quality {buildquality}. Providing update {update_path}")
        resp.status = falcon.HTTP_200
        resp.media = latest


class VSCBinaryFromCommitId:
    @staticmethod
    def on_get(_: falcon.Request, resp: falcon.Response, commitid: str, platform: str, buildquality: str) -> None:
        update_dir = ARTIFACTS_INSTALLERS_ASPATH.joinpath(platform, buildquality)
        if not update_dir.exists():
            log.warning(
                f"Update build directory does not exist at {update_dir.absolute()}. Check sync or sync configuration."
            )
            resp.status = falcon.HTTP_500
            return

        json_path = update_dir.joinpath(f"{commitid}.json")

        update_json = utils.load_json(json_path)
        if not update_json:
            resp.text = f"Unable to load {json_path.absolute()}"
            log.warning(resp.text)
            resp.status = falcon.HTTP_500
            return

        update_path = utils.first_file(update_dir, f"vscode-{update_json['name']}.*")
        if not update_path:
            resp.text = f"""Unable to find update payload from {update_dir}/vscode-{update_json['name']}.*"""
            log.warning(resp.text)
            resp.status = falcon.HTTP_404
            return

        if not utils.hash_file_and_check(update_path, update_json["sha256hash"]):
            resp.text = f"Update payload hash mismatch {update_path}"
            log.warning(resp.text)
            resp.status = falcon.HTTP_403
            return

        # Url for the client to fetch the update
        resp.set_header("Location", urllib.parse.urljoin(utils.URLROOT, str(update_path.absolute())))
        resp.status = falcon.HTTP_302


class VSCRecommendations:
    @staticmethod
    def on_get(_: falcon.Request, resp: falcon.Response) -> None:
        if not ARTIFACT_RECOMMENDATION_ASPATH.exists():
            resp.status = falcon.HTTP_404
            return
        resp.status = falcon.HTTP_200
        resp.content_type = "application/octet-stream"
        resp.stream = open(ARTIFACT_RECOMMENDATION_ASPATH, "rb")


class VSCMalicious:
    @staticmethod
    def on_get(_: falcon.Request, resp: falcon.Response) -> None:
        if not ARTIFACT_MALICIOUS_ASPATH.exists():
            resp.status = falcon.HTTP_404
            return
        resp.status = falcon.HTTP_200
        resp.content_type = "application/octet-stream"
        resp.stream = open(ARTIFACT_MALICIOUS_ASPATH, "rb")


class VSCGallery:

    __slots__ = ["extensions", "interval", "loaded", "update_worker"]

    def __init__(self, interval: int = 3600) -> None:
        self.extensions: Dict[str, Any] = {}
        self.interval: int = interval
        self.loaded: Event = Event()
        self.update_worker: Thread = Thread(target=self.update_state_loop, args=())
        self.update_worker.daemon = True
        self.update_worker.start()

    def update_state(self):
        start = time.time()
        # Load each extension
        # we use scandir here since it will provide the `is_dir` subfunction for filtering,
        # while being faster than a glob
        # still, try to keep to pathlib where we can for keeping it the same
        for extensiondir in filter(lambda d: d.is_dir(), os.scandir(ARTIFACTS_EXTENSIONS_ASPATH)):
            # Load the latest version of each extension
            latest_path = os.path.join(extensiondir, "latest.json")
            latest = utils.load_json(latest_path)

            if not latest:
                log.debug(f"Tried to load invalid manifest json {latest_path}")
                continue

            latest = self.process_loaded_extension(latest, extensiondir)

            if not latest:
                log.debug(f"Unable to determine latest version {latest_path}")
                continue

            # Determine the latest version
            latestversion = latest["versions"][0]

            # Find other versions
            for ver_path in pathlib.Path(extensiondir).glob("./*/extension.json"):
                vers = utils.load_json(ver_path)

                if not vers:
                    log.debug(f"Tried to load invalid version manifest json {ver_path.absolute()}")
                    continue
                vers = self.process_loaded_extension(vers, extensiondir)

                # If this extension.json is actually the latest version, then ignore it
                if not vers or latestversion == vers["versions"][0]:
                    continue

                # Append this other possible version
                latest["versions"].append(vers["versions"][0])

            # Sort versions
            latest["versions"] = sorted(latest["versions"], key=lambda k: k["version"], reverse=True)

            # Save the extension in the cache
            self.extensions[latest["identity"]] = latest
        log.info(f"Loaded {len(self.extensions)} extensions in {time.time() - start}")

    @staticmethod
    def process_loaded_extension(extension: Dict[str, Any], extensiondir: str) -> Dict[str, Any]:
        # Repoint asset urls
        for version in extension["versions"]:
            if "targetPlatform" in version and version["targetPlatform"]:
                asseturi = utils.URLROOT + os.path.join(extensiondir, version["version"], version["targetPlatform"])
            else:
                asseturi = utils.URLROOT + os.path.join(extensiondir, version["version"])

            version["assetUri"] = version["fallbackAssetUri"] = asseturi
            for asset in version["files"]:
                asset["source"] = f"""{asseturi}/{asset['assetType']}"""

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

    def update_state_loop(self):
        while True:
            self.update_state()
            self.loaded.set()
            log.info(f"Checking for updates in {utils.seconds_to_human_time(self.interval)}")
            time.sleep(self.interval)

    def on_post(self, req: falcon.Request, resp: falcon.Response) -> None:
        if "filters" not in req.media or "criteria" not in req.media["filters"][0] or "flags" not in req.media:
            log.warning(f"Post missing critical components. Raw post {req.media}")
            resp.status = falcon.HTTP_404
            return

        sortby = utils.SortBy.NoneOrRelevance
        sortorder = utils.SortOrder.Default
        criteria = req.media["filters"][0]["criteria"]

        if req.media["filters"][0]["sortOrder"]:
            sortorder = utils.SortOrder(req.media["filters"][0]["sortOrder"])

        if req.media["filters"][0]["sortBy"]:
            sortby = utils.SortBy(req.media["filters"][0]["sortBy"])

        # If no order specified, default to InstallCount (e.g. popular first)
        if sortby == utils.SortBy.NoneOrRelevance:
            sortby = utils.SortBy.InstallCount
            sortorder = utils.SortOrder.Descending

        result = self._apply_criteria(criteria)
        self._sort(result, sortby, sortorder)
        resp.media = self._build_response(result)
        resp.status = falcon.HTTP_200

    @staticmethod
    def _sort(result: List[Dict[str, Any]], sortby: int, sortorder: int) -> None:
        # NOTE: modifies result in place
        rev = not sortorder == utils.SortOrder.Ascending

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

    def _apply_criteria(self, criteria: List[Dict[str, Any]]):
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
    def _build_response(resultingExtensions: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "results": [
                {
                    "extensions": resultingExtensions,
                    "pagingToken": None,
                    "resultMetadata": [
                        {
                            "metadataType": "ResultCount",
                            "metadataItems": [{"name": "TotalCount", "count": len(resultingExtensions)}],
                        }
                    ],
                }
            ]
        }


class VSCIndex:
    @staticmethod
    def on_get(_: falcon.Request, resp: falcon.Response) -> None:
        # TODO: Fix so it doesn't read from static location.
        resp.content_type = "text/html"
        resp.text = STATIC_INDEX_HTML
        resp.status = falcon.HTTP_200


class VSCDirectoryBrowse:

    __slots__ = ["root"]

    def __init__(self, root: pathlib.Path) -> None:
        if not isinstance(root, pathlib.Path):
            self.root = pathlib.Path(root)
        self.root = root

    def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        requested_path = self.root.joinpath(req.get_param("path", required=True))
        # Check the path requested
        if os.path.commonpath((requested_path.absolute(), self.root.absolute())) != str(self.root.absolute()):
            resp.status = falcon.HTTP_403
            return
        resp.content_type = "text/html"
        # Load template and replace variables
        resp.text = STATIC_BROWSE_HTML.replace("{PATH}", str(requested_path.absolute())).replace(
            "{CONTENT}", self.simple_dir_browse_response(requested_path)
        )
        resp.status = falcon.HTTP_200

    @staticmethod
    def simple_dir_browse_response(path: pathlib.Path) -> str:
        response = ""
        for item in utils.folders_in_folder(path):
            response += f'd <a href="/browse?path={item.path}">{item.name}</a><br />'
        for item in utils.files_in_folder(path):
            response += f'f <a href="{item.path}">{item.name}</a><br />'
        return response


if not ARTIFACTS_ASPATH.exists():
    log.warning(f"Artifact directory missing {utils.ARTIFACTS}. Cannot proceed.")
    exit(-1)

if not ARTIFACTS_INSTALLERS_ASPATH.exists():
    log.warning(f"Installer artifact directory missing {utils.ARTIFACTS_INSTALLERS}. Cannot proceed.")
    exit(-1)

if not ARTIFACTS_EXTENSIONS_ASPATH.exists():
    log.warning(f"Extensions artifact directory missing {utils.ARTIFACTS_EXTENSIONS}. Cannot proceed.")
    exit(-1)

gallery = VSCGallery()

application = falcon.App(cors_enable=True)
application.add_route("/api/update/{platform}/{buildquality}/{commitid}", VSCUpdater())
application.add_route("/commit:{commitid}/{platform}/{buildquality}", VSCBinaryFromCommitId())
application.add_route("/extensions/workspaceRecommendations.json.gz", VSCRecommendations())  # Why no compress??
application.add_route("/extensions/marketplace.json", VSCMalicious())
application.add_route("/_apis/public/gallery/extensionquery", gallery)
application.add_route("/browse", VSCDirectoryBrowse(ARTIFACTS_ASPATH))
application.add_route("/", VSCIndex())
application.add_static_route("/artifacts/", "/artifacts/")

if __name__ == "__main__":
    httpd = simple_server.make_server("0.0.0.0", 5000, application)
    httpd.serve_forever()
