import os
import pathlib
import sys
import time
import urllib.parse
from threading import Event, Thread
from wsgiref import simple_server
from typing import Dict, Any, List, Tuple, Union

import falcon
from logzero import logger as log
from watchdog.events import FileSystemEventHandler, DirModifiedEvent, FileModifiedEvent
from watchdog.observers.polling import PollingObserver

import vscoffline.utils as utils

# -----------------------------------------------------------------------------
# Rather than doing pathlib resolution on every request,
# we do it once globally to keep the objects in memory.
ARTIFACTS_ASPATH = pathlib.Path(utils.ARTIFACTS)
ARTIFACTS_INSTALLERS_ASPATH = pathlib.Path(utils.ARTIFACTS_INSTALLERS)
ARTIFACTS_EXTENSIONS_ASPATH = pathlib.Path(utils.ARTIFACTS_EXTENSIONS)
ARTIFACT_RECOMMENDATION_ASPATH = pathlib.Path(utils.ARTIFACT_RECOMMENDATION)
ARTIFACT_MALICIOUS_ASPATH = pathlib.Path(utils.ARTIFACT_MALICIOUS)

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
        with open(ARTIFACT_RECOMMENDATION_ASPATH, "r") as f:
            resp.text = f.read()


class VSCMalicious:
    @staticmethod
    def on_get(_: falcon.Request, resp: falcon.Response) -> None:
        if not ARTIFACT_MALICIOUS_ASPATH.exists():
            resp.status = falcon.HTTP_404
            return
        resp.status = falcon.HTTP_200
        resp.content_type = "application/octet-stream"
        with open(ARTIFACT_MALICIOUS_ASPATH, "r") as f:
            resp.text = f.read()


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
        # Load each extension
        for extensiondir in ARTIFACTS_EXTENSIONS_ASPATH.glob("/*/"):

            # Load the latest version of each extension
            latestpath = extensiondir.joinpath("latest.json")
            latest = utils.load_json(latestpath)

            if not latest:
                log.debug(f"Tried to load invalid manifest json {latestpath.absolute()}")
                continue

            latest = self.process_loaded_extension(latest, extensiondir)

            if not latest:
                log.debug(f"Unable to determine latest version {latestpath.absolute()}")
                continue

            # Determine the latest version
            latestversion = latest["versions"][0]

            # Find other versions
            for versionpath in extensiondir.glob("/*/extension.json"):
                vers = utils.load_json(versionpath)

                if not vers:
                    log.debug(f"Tried to load invalid version manifest json {versionpath.absolute()}")
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
            name = latest["identity"]
            self.extensions[name] = latest

        log.info(f"Loaded {len(self.extensions)} extensions")

    def process_loaded_extension(self, extension: Dict[str:Any], extensiondir: pathlib.Path) -> Dict[str, Any]:
        name = extension["identity"]

        # Repoint asset urls
        for version in extension["versions"]:
            if "targetPlatform" in version:
                to_join: Tuple[str] = (version["version"], version["targetPlatform"])
            else:
                to_join: Tuple[str] = (version["version"],)
            asseturi = urllib.parse.urljoin(utils.URLROOT, str(extensiondir.joinpath(*to_join).absolute()))

            version["assetUri"] = version["fallbackAssetUri"] = asseturi
            for asset in version["files"]:
                asset["source"] = urllib.parse.urljoin(asseturi, asset["assetType"])

        # Map statistics for later lookup
        stats = {"averagerating": 0, "install": 0, "weightedRating": 0}
        if "statistics" not in extension or not extension["statistics"]:
            log.info(f"Statistics are missing from extension {name} in {extensiondir.absolute()}, generating.")
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
        rev = sortorder == utils.SortOrder.Ascending

        if sortby == utils.SortBy.PublisherName:
            rev = not rev
            sort_lambda = lambda k: k["publisher"]["publisherName"]
        elif sortby == utils.SortBy.InstallCount:
            sort_lambda = lambda k: k["stats"]["install"]
        elif sortby == utils.SortBy.AverageRating:
            sort_lambda = lambda k: k["stats"]["averagerating"]
        elif sortby == utils.SortBy.WeightedRating:
            sort_lambda = lambda k: k["stats"]["weightedRating"]
        elif sortby == utils.SortBy.LastUpdatedDate:
            sort_lambda = lambda k: utils.from_json_datetime(k["lastUpdated"])
        elif sortby == utils.SortBy.PublishedDate:
            sort_lambda = lambda k: utils.from_json_datetime(k["publishedDate"])
        else:
            rev = not rev
            sort_lambda = lambda k: k["displayName"]

        result.sort(key=sort_lambda, reverse=rev)

    def _apply_criteria(self, criteria: List[Dict[str, Any]]):
        # `self.extensions` may be modified by the update thread while this
        # function is executing so we need to operate on a copy
        extensions = self.extensions.copy()
        result = []

        # ?? Tags
        not_implemented_filters = (utils.FilterType.Tag, utils.FilterType.Category, utils.FilterType.Featured)
        ignored_filters = (utils.FilterType.Target, utils.FilterType.ExcludeWithFlags)
        # ExcludeWithFlags: Typically this ignores Unpublished Flag (4096) extensions
        # Target: Ignore the product, typically Visual Studio Code. If it's custom, then let it connect here

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

            elif ft in not_implemented_filters:
                log.info(f"Not implemented filter type {ft} for {val}")
                continue

            elif ft in ignored_filters:
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
        with open("/opt/vscoffline/vscgallery/content/index.html", "r") as f:
            resp.body = f.read()
        resp.status = falcon.HTTP_200


class VSCDirectoryBrowse:

    __slots__ = ["root"]

    def __init__(self, root: Union[str, pathlib.Path]) -> None:
        if isinstance(root, str):
            root: pathlib.Path = pathlib.Path(root)
        self.root = root

    def on_get(self, req: falcon.Request, resp: falcon.Response) -> None:
        requested_path = self.root.joinpath(req.get_param("path", required=True))
        # Check the path requested
        if os.path.commonpath((requested_path.absolute(), self.root.absolute())) != str(self.root.absolute()):
            resp.status = falcon.HTTP_403
            return
        resp.content_type = "text/html"
        # Load template and replace variables
        # TODO: Fix so it doesn't read from static location.
        with open("/opt/vscoffline/vscgallery/content/browse.html", "r") as f:
            resp.body = f.read()
        resp.body = resp.body.replace("{PATH}", str(requested_path.absolute()))
        resp.body = resp.body.replace("{CONTENT}", self.simple_dir_browse_response(requested_path))
        resp.status = falcon.HTTP_200

    @staticmethod
    def simple_dir_browse_response(path: pathlib.Path) -> str:
        response = ""
        for item in utils.folders_in_folder(path):
            response += f'd <a href="/browse?path={str(item.absolute())}">{item.name}</a><br />'
        for item in utils.files_in_folder(path):
            response += f'f <a href="{str(item.absolute())}">{item.name}</a><br />'
        return response


class ArtifactChangedHandler(FileSystemEventHandler):

    __slots__ = ["gallery"]

    def __init__(self, gallery: VSCGallery) -> None:
        self.gallery = gallery

    def on_modified(self, event: Union[DirModifiedEvent, FileModifiedEvent]) -> None:
        if "updated.json" in event.src_path:
            log.info("Detected updated.json change, updating extension gallery")
            self.gallery.update_state()


if not ARTIFACTS_ASPATH.exists():
    log.warning(f"Artifact directory missing {utils.ARTIFACTS}. Cannot proceed.")
    sys.exit(-1)

if not ARTIFACTS_INSTALLERS_ASPATH.exists():
    log.warning(f"Installer artifact directory missing {utils.ARTIFACTS_INSTALLERS}. Cannot proceed.")
    sys.exit(-1)

if not ARTIFACTS_EXTENSIONS_ASPATH.exists():
    log.warning(f"Extensions artifact directory missing {utils.ARTIFACTS_EXTENSIONS}. Cannot proceed.")
    sys.exit(-1)

vscgallery = VSCGallery()

# log.debug('Waiting for gallery cache to load')
# vscgallery.loaded.wait()

observer = PollingObserver()
observer.schedule(ArtifactChangedHandler(vscgallery), "/artifacts/", recursive=False)
observer.start()

application = falcon.App(cors_enable=True)
application.add_route("/api/update/{platform}/{buildquality}/{commitid}", VSCUpdater())
application.add_route("/commit:{commitid}/{platform}/{buildquality}", VSCBinaryFromCommitId())
application.add_route("/extensions/workspaceRecommendations.json.gz", VSCRecommendations())  # Why no compress??
application.add_route("/extensions/marketplace.json", VSCMalicious())
application.add_route("/_apis/public/gallery/extensionquery", vscgallery)
application.add_route("/browse", VSCDirectoryBrowse(ARTIFACTS_ASPATH))
application.add_route("/", VSCIndex())
application.add_static_route("/artifacts/", "/artifacts/")

if __name__ == "__main__":
    httpd = simple_server.make_server("0.0.0.0", 5000, application)
    httpd.serve_forever()
