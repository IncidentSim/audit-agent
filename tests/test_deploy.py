"""Portable bundle/deployment and installation identity checks; no system writes."""
import argparse
import importlib.util
import io
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch


def load(name):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).resolve().parents[1] / (name + '.py'))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


deploy = load('deploy')
installer = load('install')


def arguments(**overrides):
    values = dict(target='admin@host', sudo=False, vm_id='training-01', skip_packages=False,
                  verify=False, port=None, identity=None, ssh_option=[], python=sys.executable)
    return argparse.Namespace(**{**values, **overrides})


class DeploymentTests(unittest.TestCase):
    def fixture_bundle(self, directory):
        for name in deploy.FILES:
            (directory / name).parent.mkdir(parents=True, exist_ok=True)
            (directory / name).write_text('# fixture\n', encoding='utf-8')
        (directory / 'install.py').write_text(
            'import json, sys\nprint(json.dumps(sys.argv[1:]))\n', encoding='utf-8')
        return deploy.build_bundle(directory)

    def test_bundle_is_self_contained_and_excludes_unlisted_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.fixture_bundle(root)
            (root / 'private.key').write_text('not part of a distribution')
            bundle = deploy.build_bundle(root)
        with tarfile.open(fileobj=io.BytesIO(bundle), mode='r:gz') as archive:
            self.assertEqual(set(archive.getnames()), set(deploy.FILES))
            self.assertTrue(all(member.isfile() for member in archive))

    def test_destination_cannot_become_an_ssh_option(self):
        for target in ('-oProxyCommand=anything', 'bad host', 'host\nother'):
            with self.subTest(target=target), self.assertRaises(ValueError):
                deploy.make_command(arguments(target=target))

    def test_key_paths_ports_and_proxy_jump_are_passed_as_argv(self):
        command = deploy.make_command(arguments(
            identity='/keys/a key', port=2222, ssh_option=['ProxyJump=bastion']))
        self.assertIn(str(Path('/keys/a key').expanduser()), command)
        self.assertIn('2222', command)
        self.assertIn('ProxyJump=bastion', command)
        self.assertEqual(command[-2], 'admin@host')
        remote = shlex.split(command[-1])
        settings = json.loads(remote[-1])
        self.assertEqual(settings['vm_id'], 'training-01')
        self.assertEqual(set(settings['files']), set(deploy.FILES))

    def test_real_remote_shell_quoting_and_archive_bootstrap(self):
        if sys.platform != 'linux':
            self.skipTest('requires POSIX sh')
        label = "VM 'quoted'; $(printf not-executed)"
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.fixture_bundle(Path(directory))
            command = deploy.make_command(arguments(vm_id=label))
            result = subprocess.run(['sh', '-c', command[-1]], input=bundle, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(result.stdout), ['--vm-id', label])

    def test_bootstrap_rejects_path_traversal(self):
        if sys.platform != 'linux':
            self.skipTest('requires POSIX sh')
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode='w:gz') as archive:
            entry = tarfile.TarInfo('../unexpected')
            entry.size = 1
            archive.addfile(entry, io.BytesIO(b'x'))
        command = deploy.make_command(arguments())
        result = subprocess.run(['sh', '-c', command[-1]], input=buffer.getvalue(),
                                capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'unexpected entry', result.stderr)

    def test_unsupported_architecture_is_rejected_before_system_changes(self):
        with patch.object(installer.platform, 'machine', return_value='aarch64'):
            with self.assertRaisesRegex(RuntimeError, 'Linux x86_64'):
                installer.preflight(skip_packages=True)

    def test_generated_identity_is_reused_on_reinstallation(self):
        with tempfile.TemporaryDirectory() as directory:
            context = Path(directory) / 'context.json'
            identity = installer.select_vm_id(None, context)
            self.assertTrue(identity)
            context.write_text(json.dumps({'vm_id': identity}), encoding='utf-8')
            self.assertEqual(installer.select_vm_id(None, context), identity)
            self.assertEqual(installer.select_vm_id(identity, context), identity)
            with self.assertRaisesRegex(RuntimeError, 'another VM'):
                installer.select_vm_id('other-machine', context)
            self.assertEqual(json.loads(context.read_text())['vm_id'], identity)


if __name__ == '__main__':
    unittest.main()
