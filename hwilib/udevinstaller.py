"""
UDev Rules Installer
********************

Classes and utilities for installing device udev rules.
"""

from .errors import NeedsRootError

from subprocess import check_call, CalledProcessError, DEVNULL
from shutil import copy, which
from os import path, listdir, getlogin, geteuid, chmod

class UDevInstaller(object):
    """
    Installs the udev rules
    """
    @staticmethod
    def install(source: str, location: str) -> bool:
        """
        Install the udev rules from source into location.
        This will also reload and trigger udevadm so that devices matching the new rules will be detected.
        The user will be added to the ``plugdev`` group. If the group doesn't exist, the user will be added to it.

        :param source: The path to the source directory containing the rules
        :param location: The path to the directory to copy the rules to
        :return: Whether the install was successful
        """
        try:
            udev_installer = UDevInstaller()
            udev_installer.copy_udev_rule_files(source, location)
            udev_installer.trigger()
            udev_installer.reload_rules()
            udev_installer.add_user_plugdev_group()
        except CalledProcessError:
            if geteuid() != 0:
                raise NeedsRootError("Need to be root.")
            raise
        return True

    def __init__(self) -> None:
        self._udevadm = which('udevadm')
        self._groupadd = which('groupadd')
        self._usermod = which('usermod')

    def _execute(self, cmd: str, *args: str) -> None:
        command = [cmd] + list(args)
        check_call(command, stderr=DEVNULL, stdout=DEVNULL)

    def trigger(self) -> None:
        """
        Run ``udevadm trigger``
        """
        assert self._udevadm
        self._execute(self._udevadm, 'trigger')

    def reload_rules(self) -> None:
        """
        Run ``udevadm control --reload-rules``
        """
        assert self._udevadm
        self._execute(self._udevadm, 'control', '--reload-rules')

    def add_user_plugdev_group(self) -> None:
        """
        Add the user to the ``plugdev`` group
        """
        self._create_group('plugdev')
        self._add_user_to_group(getlogin(), 'plugdev')

    def _create_group(self, name: str) -> None:
        assert self._groupadd
        try:
            self._execute(self._groupadd, name)
        except CalledProcessError as e:
            if e.returncode != 9: # group already exists
                raise

    def _add_user_to_group(self, user: str, group: str) -> None:
        assert self._usermod
        self._execute(self._usermod, '-aG', group, user)

    def copy_udev_rule_files(self, source: str, location: str) -> None:
        """
        Copy the udev rules from source to location

        :param source: The path to the source directory containing the rules
        :param location: The path to the directory to copy the rules to
        """
        src_dir_path = source
        for rules_file_name in listdir(_resource_path(src_dir_path)):
            if '.rules' in rules_file_name:
                rules_file_path = _resource_path(path.join(src_dir_path, rules_file_name))
                copy(rules_file_path, location)
                chmod(path.join(location, rules_file_name), 0o644)

def _resource_path(relative_path: str) -> str:
    return path.join(path.dirname(__file__), relative_path)
