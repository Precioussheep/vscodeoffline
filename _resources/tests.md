# A collection of minor tests used to try and validate functionality

TODO: Make into automated tests

## Test `--check-specified`

Test is designed to be runnable within the alpine deployment image of `sync.Dockerfile`

Checks if download for particular extension occurs. Does not do any file integrity/correctness checks

```sh
printf '{"extensions": ["ms-python.python"]}' > /artifacts/specified.json
python3 sync.py --update-extensions --check-specified
ver=$(python3 -c """import json; updated = json.load(open('/artifacts/extensions/ms-python.python/latest.json', 'r')); print(updated['versions'][0]['version'])""")

if [ -d /artifacts/extensions/ms-python.python/$ver ]; then printf "Latest Download Folder Found\n"; fi

if [ -f /artifacts/extensions/ms-python.python/$ver/Microsoft.VisualStudio.Services.VSIXPackage ]; then 
    printf "Package Found. Download considered successful\n"; 
fi
```

## Test `--extension-search`

Should get one result, looking something like: `<VSCExtensionDefinition> ms-python.python (<>) - Version: <>` where version is latest (**including pre-release**) version.

```sh
python3 sync.py --extension-search ms-python.python --debug
```

## Test `--check-recommended-extensions`

This can take a while, since currently `--check-recommended-extensions` does not provide any debug values for successful finds.
Therefore, we download the top 10 & see how it goes.

Note: there is currently an issue where it also gets old recommendations which can include packages that
no longer exist. Maybe recommendations should _only_ provide the top _N_ from the marketplace?

```sh
python3 sync.py --check-recommended-extensions  --total-recommended 10 --update-extensions --debug
```

## Test `--update-binaries`

One of the simpler tests

```sh
python3 sync.py --update-binaries --debug
```

## Test `--update-extensions`

This is tested in `--check-specified` and `--check-recommended-extension` above.
