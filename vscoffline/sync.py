import argparse
import logging
import pathlib
import time
import logging as log
from typing import Dict, List

import vscoffline.utils as utils
import vscoffline.vscsync.classes as vscsync_classes
from vscoffline.vscsync.models import VSCSyncConfig


def main(config_cls: VSCSyncConfig) -> None:
    did_something = False
    if not config_cls.skipbinaries:
        versions: Dict[str, vscsync_classes.VSCUpdateDefinition] = {}
        if config_cls.checkbinaries:
            log.info("Syncing VS Code Update Versions")
            versions = vscsync_classes.get_latest_versions(config_cls.checkinsider)
            did_something = True

        if config_cls.updatebinaries:
            log.info("Syncing VS Code Binaries")
            for idkey in versions.keys():
                if versions[idkey].updateurl:
                    result = versions[idkey].download_update(config_cls.artifactdir_installers)
                    # Only save the reference json if the download was successful
                    if result:
                        versions[idkey].save_state(config_cls.artifactdir_installers)
            did_something = True

    extensions: Dict[str, vscsync_classes.VSCExtensionDefinition] = {}
    mp = vscsync_classes.VSCMarketplace(config_cls.checkinsider, config_cls.prerelease, config_cls.version)

    if config_cls.checkspecified:
        log.info("Syncing VS Code Specified Extensions")
        specified_path = config_cls.artifactdir.joinpath("specified.json")
        specified_extensions = mp.get_specified(specified_path)
        if specified_extensions:
            for item in specified_extensions:
                log.debug(item)
                extensions[item.identity] = item
        did_something = True

    if config_cls.extensionsearch:
        log.info(f"Searching for VS Code Extension: {config_cls.extensionsearch}")
        results = mp.search_by_text(config_cls.extensionsearch)
        log.info(f"Found {len(results)} extensions")
        for item in results:
            log.debug(item)
            extensions[item.identity] = item
        did_something = True

    if config_cls.extensionname:
        log.info(f"Checking Specific VS Code Extension: {config_cls.extensionname}")
        result = mp.search_by_extension_name(config_cls.extensionname)
        if result:
            log.debug(result)
            extensions[result.identity] = result
        did_something = True

    if config_cls.checkextensions:
        log.info("Syncing VS Code Recommended Extensions")
        recommended = mp.get_recommendations(config_cls.artifactdir.absolute(), config_cls.totalrecommended)
        for item in recommended:
            extensions[item.identity] = item
        did_something = True

    if config_cls.updatemalicious:
        log.info("Syncing VS Code Malicious Extension List")
        mp.get_malicious(config_cls.artifactdir.absolute(), extensions)
        did_something = True

    # TODO: Look at multithreading if we're IO (instead of network) bound
    if config_cls.updateextensions:
        log.info(f"Checking and Downloading Updates for {len(extensions)} Extensions")
        count = 0
        bonus: List[vscsync_classes.VSCExtensionDefinition] = []
        for identity in extensions:
            log.debug(f"Fetching extension: {identity}")
            if count % 100 == 0:
                log.info(f"Progress {count}/{len(extensions)} ({count / len(extensions) * 100:.1f}%)")
            extensions[identity].download_assets(config_cls.artifactdir_extensions)
            bonus.extend(extensions[identity].process_embedded_extensions(config_cls.artifactdir_extensions, mp))
            extensions[identity].save_state(config_cls.artifactdir_extensions)
            count = count + 1

        for bonusextension in bonus:
            log.debug(f"Processing Embedded Extension: {bonusextension}")
            bonusextension.download_assets(config_cls.artifactdir_extensions)
            bonusextension.save_state(config_cls.artifactdir_extensions)
        did_something = True

    if did_something:
        log.info("Complete")
        vscsync_classes.signal_updated(config_cls.artifactdir)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Synchronises VSCode in an Offline Environment")
    parser.add_argument(
        "--sync",
        dest="sync",
        action="store_true",
        help="The basic-user sync. It includes stable binaries and typical extensions",
    )
    parser.add_argument(
        "--syncall",
        dest="syncall",
        action="store_true",
        help="The power-user sync. It includes all binaries and extensions ",
    )
    parser.add_argument(
        "--artifacts",
        dest="artifactdir",
        default="../artifacts/",
        help="Path to downloaded artifacts",
    )
    parser.add_argument(
        "--frequency",
        dest="frequency",
        default=None,
        help="The frequency to try and update (e.g. sleep for '12h' and try again",
    )

    # Arguments to tweak behaviour
    parser.add_argument(
        "--check-binaries",
        dest="checkbinaries",
        action="store_true",
        help="Check for updated binaries",
    )
    parser.add_argument(
        "--check-insider",
        dest="checkinsider",
        action="store_true",
        help="Check for updated insider binaries",
    )
    parser.add_argument(
        "--check-recommended-extensions",
        dest="checkextensions",
        action="store_true",
        help="Check for recommended extensions",
    )
    parser.add_argument(
        "--check-specified-extensions",
        dest="checkspecified",
        action="store_true",
        help="Check for extensions in <artifacts>/specified.json",
    )
    parser.add_argument(
        "--extension-name",
        dest="extensionname",
        help="Find a specific extension by name",
    )
    parser.add_argument(
        "--extension-search",
        dest="extensionsearch",
        help="Search for a set of extensions",
    )
    parser.add_argument(
        "--prerelease-extensions",
        dest="prerelease",
        action="store_true",
        help="Download prerelease extensions. Defaults to false.",
    )
    parser.add_argument(
        "--update-binaries",
        dest="updatebinaries",
        action="store_true",
        help="Download binaries",
    )
    parser.add_argument(
        "--update-extensions",
        dest="updateextensions",
        action="store_true",
        help="Download extensions",
    )
    parser.add_argument(
        "--update-malicious-extensions",
        dest="updatemalicious",
        action="store_true",
        help="Update the malicious extension list",
    )
    parser.add_argument(
        "--skip-binaries",
        dest="skipbinaries",
        action="store_true",
        help="Skip downloading binaries",
    )
    parser.add_argument(
        "--vscode-version",
        dest="version",
        default="1.100.1",
        help="VSCode version to search extensions as.",
    )
    parser.add_argument(
        "--total-recommended",
        type=int,
        dest="totalrecommended",
        default=500,
        help="Total number of recommended extensions to sync. Defaults to 500",
    )
    parser.add_argument(
        "--debug",
        dest="debug",
        action="store_true",
        help="Show debug output",
        default=False,
    )
    parser.add_argument(
        "--logfile",
        dest="logfile",
        default=None,
        help="Sets a logfile to store loggging output",
        type=pathlib.Path,
    )
    config, _ = parser.parse_known_args()

    # --
    # Debugging config
    log_config_args = {
        "format": "[%(levelname)1.1s %(asctime)s %(module)s:%(lineno)d] %(message)s",
        "datefmt": "%y%m%d %H:%M:%S",
        "level": logging.DEBUG if config.debug else logging.INFO,
    }

    if config.logfile:
        log_file_loc = pathlib.Path(config.logfile)
        if not log_file_loc.parent.exists():
            log_file_loc.parent.mkdir(parents=True)
        elif not log_file_loc.parent.is_dir():
            raise FileNotFoundError(
                f"Log directory specified is not a directory. Directory provided: {log_file_loc.parent.absolute()}"
            )
        log_config_args["filename"] = log_file_loc

    log.basicConfig(**log_config_args)

    # convert namespace into something actually useful by a linter
    config_cls: VSCSyncConfig = VSCSyncConfig.from_dict(vars(config))

    if config_cls.artifactdir and not config_cls.artifactdir.is_dir():
        raise FileNotFoundError(f"Artifact directory does not exist at {config_cls.artifactdir.absolute()}")

    while True:
        main(config_cls)

        if not config_cls.frequency:
            log.info("No Frequency Set. Exiting Now.")
            break
        log.info(f"Going to sleep for {utils.seconds_to_human_time(int(config_cls.frequency))}")
        time.sleep(int(config_cls.frequency))
