"""
A collection of async utils for fastapi
"""

import hashlib
import logging as log
from typing import Any

import anyio
import orjson


async def async_load_json(filepath: anyio.Path) -> list[Any] | dict[str, Any]:
    # technically this could be just filepath = pathlib.Path(filepath)
    # because wrapping a path will still return the same path
    result = []
    if not await filepath.exists():
        log.debug(f"Unable to load json from {await filepath.absolute()}. Does not exist.")
        return result
    elif await filepath.is_dir():
        log.debug(f"Cannot load json at path {await filepath.absolute()}. It is a directory")
        return result

    async with await anyio.open_file(filepath, "rb") as fl:
        try:
            result = orjson.loads(await fl.read())
            if not result:
                return []
        except orjson.JSONDecodeError as err:
            log.debug(f"JSONDecodeError while processing {await filepath.absolute()} \n error: {str(err)}")
            return []
    return result


async def async_first_file(filepath: anyio.Path, pattern: str, reverse: bool = False) -> anyio.Path | None:
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


async def async_hash_file_and_check(filepath: anyio.Path, expectedchecksum: str) -> bool:
    """
    Hashes a file and checks for the expected checksum.

    Checksum is sha256 default implementation.
    """
    h = hashlib.sha256()
    with open(filepath, "rb") as fp:
        for chunk in iter(lambda: fp.read(4096), b""):
            h.update(chunk)
    return expectedchecksum == h.hexdigest()
