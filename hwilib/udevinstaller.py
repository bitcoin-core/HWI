from subprocess import check_call, CalledProcessError, DEVNULL
from .errors import NEED_TO_BE_ROOT
from shutil import copy
from os import path, listdir, getlogin, geteuid

class UDevInstaller(object):
    @staticmethod
    def install(source, location):
        try:
            udev_installer = UDevInstaller()
            udev_installer.copy_udev_rule_files(source, location)
            udev_installer.trigger()
            udev_installer.reload_rules()
            udev_installer.add_user_plugdev_group()
        except CalledProcessError:
            if geteuid() != 0:
                return {'error': 'Need to be root.', 'code': NEED_TO_BE_ROOT}
            raise
        return {"success": True}

    def __init__(self):
        self._udevadm = '/sbin/udevadm'
        self._groupadd = '/usr/sbin/groupadd'
        self._usermod = '/usr/sbin/usermod'

    def _execute(self, command, *args):
        command = [command] + list(args)
        check_call(command, stderr=DEVNULL, stdout=DEVNULL)

    def trigger(self):
        self._execute(self._udevadm, 'trigger')

    def reload_rules(self):
        self._execute(self._udevadm, 'control', '--reload-rules')

    def add_user_plugdev_group(self):
        self._create_group('plugdev')
        self._add_user_to_group(getlogin(), 'plugdev')

    def _create_group(self, name):
        try:
            self._execute(self._groupadd, name)
        except CalledProcessError as e:
            if e.returncode != 9: # group already exists
                raise

    def _add_user_to_group(self, user, group):
        self._execute(self._usermod, '-aG', group, user)

    def copy_udev_rule_files(self, source, location):
        src_dir_path = source
        for rules_file_name in listdir(_resource_path(src_dir_path)):
            if '.rules' in rules_file_name:
                rules_file_path = _resource_path(path.join(src_dir_path, rules_file_name))
                copy(rules_file_path, location)

def _resource_path(relative_path):
    return path.join(path.dirname(__file__), relative_path)
