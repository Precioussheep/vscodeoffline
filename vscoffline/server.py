import asyncio
import pathlib
import logging as log
import urllib.parse

import aiopath
import fastapi
from fastapi.middleware.cors import CORSMiddleware
from fastapi.openapi.docs import get_redoc_html, get_swagger_ui_html
from fastapi.responses import (
    FileResponse,
    HTMLResponse,
    ORJSONResponse,
    RedirectResponse,
)
from fastapi.staticfiles import StaticFiles

import vscoffline.utils as utils
import vscoffline.vscgallery.async_utils as autils
import vscoffline.vscgallery.gallery as gallery

# -----------------------------------------------------------------------------
# STATIC VARIABLES

if not pathlib.Path(utils.ARTIFACTS).exists():
    log.warning(f"Artifact directory missing {utils.ARTIFACTS}. Cannot proceed.")
    exit(-1)

if not pathlib.Path(utils.ARTIFACTS_INSTALLERS).exists():
    log.warning(f"Installer artifact directory missing {utils.ARTIFACTS_INSTALLERS}. Cannot proceed.")
    exit(-1)

if not pathlib.Path(utils.ARTIFACTS_EXTENSIONS).exists():
    log.warning(f"Extensions artifact directory missing {utils.ARTIFACTS_EXTENSIONS}. Cannot proceed.")
    exit(-1)

ARTIFACTS_ASPATH = aiopath.AsyncPath(utils.ARTIFACTS)
ARTIFACTS_INSTALLERS_ASPATH = aiopath.AsyncPath(utils.ARTIFACTS_INSTALLERS)
ARTIFACTS_EXTENSIONS_ASPATH = aiopath.AsyncPath(utils.ARTIFACTS_EXTENSIONS)
ARTIFACT_RECOMMENDATION_ASPATH = aiopath.AsyncPath(utils.ARTIFACT_RECOMMENDATION)
ARTIFACT_MALICIOUS_ASPATH = aiopath.AsyncPath(utils.ARTIFACT_MALICIOUS)

# TODO: Don't read from static location
with open("./vscgallery/content/index.html", "r") as f:
    STATIC_INDEX_HTML = f.read()

# TODO: Don't read from static location
with open("./vscgallery/content/browse.html", "r") as f:
    STATIC_BROWSE_HTML = f.read()


VSCGALLERY = gallery.VSCGallery(ARTIFACTS_ASPATH, ARTIFACTS_INSTALLERS_ASPATH, ARTIFACTS_EXTENSIONS_ASPATH)
asyncio.create_task(VSCGALLERY.update_state_watcher())

VSCBROWSE = gallery.VSCDirectoryBrowse(ARTIFACTS_ASPATH)

# -----------------------------------------------------------------------------
# begin fastapi obj definitions

app = fastapi.FastAPI(title="VSCOffline Server", version="development", docs_url=None, redoc_url=None)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# optional offline redoc/swagger docs rehosting for api
if pathlib.Path("/static").is_dir():
    app.mount("/static", StaticFiles(directory="/static"), name="static")

    @app.get("/docs", include_in_schema=False)
    def airgapped_swagger():
        return get_swagger_ui_html(
            openapi_url=str(app.openapi_url),
            title=f"{app.title} - Swagger UI",
            swagger_js_url="/static/swagger-ui-bundle.js",
            swagger_css_url="/static/swagger-ui.css",
            swagger_favicon_url="/static/favicon.png",
        )

    @app.get("/redoc", include_in_schema=False)
    def airgapped_redoc():
        return get_redoc_html(
            openapi_url=str(app.openapi_url),
            title=f"{app.title} - Redoc",
            redoc_js_url="/static/redoc.standalone.js",
            redoc_favicon_url="/static/favicon.png",
        )


# mount artifacts for serving
app.mount("/artifacts", StaticFiles(directory="/artifacts/", html=True), name="artifacts")


@app.get("/api/update/{platform}/{buildquality}/{commitid}")
async def get_update_request(platform: str, buildquality: str, commitid: str):
    update_dir: aiopath.AsyncPath = ARTIFACTS_INSTALLERS_ASPATH.joinpath(platform, buildquality)
    if not await update_dir.exists():
        log.warning(
            f"Update build directory does not exist at {await update_dir.absolute()}. Check sync or sync configuration."
        )
        raise fastapi.HTTPException(500, "Server Error - update build directory does not exist")

    latest_path = update_dir.joinpath("latest.json")
    latest = await autils.async_load_json(latest_path)

    if not latest or not isinstance(latest, dict):
        raise fastapi.HTTPException(500, "Unable to load latest.json")

    if latest["version"] == commitid:
        # No update available
        log.debug(f"Client {platform}, Quality {buildquality}. No Update available.")
        return fastapi.Response(status_code=204)

    update_path = await autils.async_first_file(update_dir, f"vscode-{latest['name']}.*")
    if not update_path:
        log.warning(f"""Unable to find update payload from {update_dir}/vscode-{latest["name"]}.*""")
        raise fastapi.HTTPException(404, "Unable to find update payload")

    if not await autils.async_hash_file_and_check(update_path, latest["sha256hash"]):
        log.warning(f"Update payload hash mismatch {update_path}")
        raise fastapi.HTTPException(403, "Update payload hash mismatch")

    # Url to get update
    log.debug(f"Client {platform}, Quality {buildquality}. Providing update {update_path}")
    latest["url"] = urllib.parse.urljoin(utils.URLROOT, str(await update_path.absolute()))
    return ORJSONResponse(latest)


@app.get("/commit:{commitid}/{platform}/{buildquality}")
async def get_binary_from_commit_id(commitid: str, platform: str, buildquality: str):
    update_dir = ARTIFACTS_INSTALLERS_ASPATH.joinpath(platform, buildquality)
    if not await update_dir.exists():
        log.warning(
            f"Update build directory does not exist at {await update_dir.absolute()}. Check sync or sync configuration."
        )
        raise fastapi.HTTPException(500, "Server Error - update build directory does not exist")

    json_path = update_dir.joinpath(f"{commitid}.json")

    update_json = await autils.async_load_json(json_path)
    if not update_json or not isinstance(update_json, dict):
        log.warning(f"Unable to load {await json_path.absolute()}")
        raise fastapi.HTTPException(500, f"Unable to load {await json_path.absolute()}")

    update_path = await autils.async_first_file(update_dir, f"vscode-{update_json['name']}.*")
    if not update_path:
        log.warning(f"""Unable to find update payload from {update_dir}/vscode-{update_json["name"]}.*""")
        raise fastapi.HTTPException(
            404,
            f"""Unable to find update payload from {update_dir}/vscode-{update_json["name"]}.*""",
        )

    if not await autils.async_hash_file_and_check(update_path, update_json["sha256hash"]):
        log.warning(f"Update payload hash mismatch {update_path}")
        raise fastapi.HTTPException(403, f"Update payload hash mismatch {update_path}")

    return RedirectResponse(urllib.parse.urljoin(utils.URLROOT, str(await update_path.absolute())))


@app.get("/extensions/workspaceRecommendations.json.gz")  # Why no compress??
async def get_recommendations():
    if not await ARTIFACT_RECOMMENDATION_ASPATH.exists():
        raise fastapi.HTTPException(404, "Not Found")

    return FileResponse(ARTIFACT_MALICIOUS_ASPATH)


@app.get("/extensions/marketplace.json")
async def get_malicious():
    if not await ARTIFACT_MALICIOUS_ASPATH.exists():
        raise fastapi.HTTPException(404, "Not Found")

    return FileResponse(ARTIFACT_MALICIOUS_ASPATH)


@app.post("/_apis/public/gallery/extensionquery")
async def get_extension_query(ext_query: gallery.ExtensionQuery):
    sortby = utils.SortBy.NoneOrRelevance
    sortorder = utils.SortOrder.Default
    criteria = ext_query.filters[0]["criteria"]

    if q_sr := ext_query.filters[0].get("sortOrder"):
        sortorder = utils.SortOrder(q_sr)

    if q_sb := ext_query.filters[0].get("sortBy"):
        sortby = utils.SortBy(q_sb)

    # If no order specified, default to InstallCount (e.g. popular first)
    if sortby == utils.SortBy.NoneOrRelevance:
        sortby = utils.SortBy.InstallCount
        sortorder = utils.SortOrder.Descending

    result = VSCGALLERY._apply_criteria(criteria)
    VSCGALLERY._sort(result, sortby, sortorder)
    return ORJSONResponse(VSCGALLERY._build_response(result))


@app.get("/", include_in_schema=False)
async def get_index():
    return HTMLResponse(STATIC_INDEX_HTML)


@app.get("/browse", include_in_schema=False)
async def get_browse(path: str = ""):
    possible_path = await VSCBROWSE.path_valid(path)
    if not isinstance(possible_path, aiopath.AsyncPath):
        raise fastapi.HTTPException(403)

    resp_text = STATIC_BROWSE_HTML.replace("{PATH}", str(await possible_path.absolute())).replace(
        "{CONTENT}", await VSCBROWSE.simple_dir_browse_response(possible_path)
    )

    return HTMLResponse(resp_text)
