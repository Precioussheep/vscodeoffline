"""
A collection of async utils for fastapi
"""

import hashlib
from typing import Any

import aiofiles
import aiopath
import orjson
from logzero import logger as log


async def async_load_json(filepath: aiopath.AsyncPath) -> list[Any] | dict[str, Any]:
    # technically this could be just filepath = pathlib.Path(filepath)
    # because wrapping a path will still return the same path
    result = []
    if not await filepath.exists():
        log.debug(f"Unable to load json from {await filepath.absolute()}. Does not exist.")
        return result
    elif await filepath.is_dir():
        log.debug(f"Cannot load json at path {await filepath.absolute()}. It is a directory")
        return result

    async with aiofiles.open(filepath, "rb") as fp:
        try:
            result = orjson.loads(await fp.read())
            if not result:
                return []
        except orjson.JSONDecodeError as err:
            log.debug(f"JSONDecodeError while processing {await filepath.absolute()} \n error: {str(err)}")
            return []
    return result


async def async_first_file(
    filepath: aiopath.AsyncPath, pattern: str, reverse: bool = False
) -> aiopath.AsyncPath | None:
    # 3 cases:
    # no results
    # only one result - order doesn't matter
    # more than 1 - sort
    results = [path async for path in filepath.glob(pattern)]
    if not results:
        return None
    elif len(results) >= 1 and reverse:
        results.sort(reverse=True)
    return results[0]


async def async_hash_file_and_check(filepath: aiopath.AsyncPath, expectedchecksum: str) -> bool:
    """
    Hashes a file and checks for the expected checksum.

    Checksum is sha256 default implementation.
    """
    h = hashlib.sha256()
    with open(filepath, "rb") as fp:
        for chunk in iter(lambda: fp.read(4096), b""):
            h.update(chunk)
    return expectedchecksum == h.hexdigest()


# slow due to pathlib rather than os.scandir
async def async_folders_in_folder(
    filepath: aiopath.AsyncPath,
) -> list[aiopath.AsyncPath]:
    return [d async for d in filepath.iterdir() if await d.is_dir()]


# slow due to pathlib rather than os.scandir
async def async_files_in_folder(filepath: aiopath.AsyncPath) -> list[aiopath.AsyncPath]:
    return [f async for f in filepath.iterdir() if await f.is_file()]
