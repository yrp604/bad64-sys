import argparse
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys


parser = argparse.ArgumentParser(
	description='Test building the API repository and examples in-tree'
)
parser.add_argument('--headless', default=False, action='store_true', help='Only include headless plugins')
parser.add_argument('-j', '--parallel', default=4, help='Number of parallel jobs to tell cmake to run.')
parser.add_argument('--bn-install-dir', default=os.environ.get('BN_INSTALL_DIR'),
                    help='Path to a Binary Ninja installation. Defaults to BN_INSTALL_DIR.')
parser.add_argument('--qt-install-dir', default=os.environ.get('QT_INSTALL_DIR'),
                    help='Path to a Qt installation. Defaults to QT_INSTALL_DIR.')
parser.add_argument('--qmake', default=os.environ.get('QMAKE'), help='Path to qmake. Defaults to QMAKE or PATH lookup.')
parser.add_argument('--cmake', default=os.environ.get('CMAKE'), help='Path to cmake. Defaults to CMAKE or PATH lookup.')
parser.add_argument('--cc', default=os.environ.get('CC'), help='C compiler to use. Defaults to CC or CMake platform default.')
parser.add_argument('--cxx', default=os.environ.get('CXX'), help='C++ compiler to use. Defaults to CXX or CMake platform default.')
parser.add_argument('--config', default=os.environ.get('CMAKE_BUILD_CONFIG', 'Release'),
                    help='CMake build configuration to use. Defaults to CMAKE_BUILD_CONFIG or Release.')
args = parser.parse_args()

api_base = Path(__file__).parent.parent.absolute()


def fail(message):
	print(f'ERROR: {message}')
	sys.exit(1)


def prepend_path(env, path):
	env['PATH'] = f'{path}{os.pathsep}{env.get("PATH", "")}'


def find_executable(name, explicit_path=None, env=None):
	if explicit_path:
		path = Path(explicit_path).expanduser()
		if path.is_file():
			return str(path)
		fail(f'{name} was specified as {path}, but that file does not exist.')

	return shutil.which(name, path=(env or os.environ).get('PATH'))


def run_tool(tool, args_for_tool, env=None):
	try:
		result = subprocess.run([tool] + args_for_tool, check=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
		                        text=True, env=env)
		return result.stdout.strip()
	except subprocess.CalledProcessError as e:
		output = e.stdout.strip() if e.stdout else ''
		fail(f'{tool} failed with exit code {e.returncode}.\n{output}')


def print_tool(tool_name, tool_path, version_args, env=None):
	print(f'{tool_name}: {tool_path}')
	version = run_tool(tool_path, version_args, env=env)
	print(version)


def configure_qt_env(env):
	qt_dir = Path(args.qt_install_dir).expanduser().absolute() if args.qt_install_dir else None
	if qt_dir:
		if not qt_dir.exists():
			fail(f'Qt directory was specified as {qt_dir}, but it does not exist.')
		qt_bin_dir = qt_dir / 'bin'
		if not qt_bin_dir.exists():
			fail(f'Qt directory {qt_dir} does not contain a bin directory.')
		prepend_path(env, qt_bin_dir)
		env.setdefault('CMAKE_PREFIX_PATH', str(qt_dir / 'lib' / 'cmake'))
		print(f'Qt directory: {qt_dir}')
		print(f'CMAKE_PREFIX_PATH: {env["CMAKE_PREFIX_PATH"]}')

	if args.headless:
		return

	qmake = find_executable('qmake', args.qmake, env=env)
	if not qmake:
		fail('qmake not found. Install Qt and add its bin directory to PATH, set QT_INSTALL_DIR, or pass --qt-install-dir/--qmake.')

	print_tool('qmake', qmake, ['--version'], env=env)
	qt_lib_path = run_tool(qmake, ['-query', 'QT_INSTALL_LIBS'], env=env)
	env.setdefault('CMAKE_PREFIX_PATH', str(Path(qt_lib_path) / 'cmake'))
	print(f'Qt libraries: {qt_lib_path}')
	print(f'CMAKE_PREFIX_PATH: {env["CMAKE_PREFIX_PATH"]}')


def configure_binary_ninja_env(env):
	bn_install_dir = Path(args.bn_install_dir).expanduser().absolute() if args.bn_install_dir else None
	if not bn_install_dir:
		fail('Binary Ninja install directory was not specified. Set BN_INSTALL_DIR or pass --bn-install-dir.')
	if not bn_install_dir.exists():
		fail(f'Binary Ninja install directory {bn_install_dir} does not exist.')
	env['BN_INSTALL_DIR'] = str(bn_install_dir)
	print(f'Binary Ninja install: {bn_install_dir}')


env = os.environ.copy()
configure_qt_env(env)
configure_binary_ninja_env(env)

if args.cc:
	env['CC'] = args.cc
if args.cxx:
	env['CXX'] = args.cxx

cmake = find_executable('cmake', args.cmake, env=env)
if not cmake:
	fail('cmake not found. Install CMake and add it to PATH, set CMAKE, or pass --cmake.')
print_tool('cmake', cmake, ['--version'], env=env)

print(f'C compiler: {env.get("CC", "CMake platform default")}')
print(f'C++ compiler: {env.get("CXX", "CMake platform default")}')
print(f'CMake build config: {args.config}')

configure_args = ['-DBN_API_BUILD_EXAMPLES=1', f'-DCMAKE_BUILD_TYPE={args.config}']
build_args = ['--config', args.config]

if platform.system() == 'Windows':
	env['CXXFLAGS'] = f'/MP{args.parallel}'
	env['CFLAGS'] = f'/MP{args.parallel}'
else:
	build_args.extend(['-j', str(args.parallel)])

if args.headless:
	configure_args.extend(['-DHEADLESS=1'])

build_dir = api_base / 'build'
try:
	subprocess.check_call([cmake, '-B', str(build_dir)] + configure_args, cwd=api_base, env=env)
	subprocess.check_call([cmake, '--build', str(build_dir)] + build_args, cwd=api_base)
finally:
	if build_dir.exists():
		shutil.rmtree(build_dir)
