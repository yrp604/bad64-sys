import argparse
import glob
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime

parser = argparse.ArgumentParser(
	description='Test building the API repo and plugins out-of-tree (for CI checking of end-user workflow)'
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
parser.add_argument('--extra-project', action='append', default=[],
                    help='Additional out-of-tree CMake project directory to build. May be specified multiple times.')
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
		return None

	qmake = find_executable('qmake', args.qmake, env=env)
	if not qmake:
		fail('qmake not found. Install Qt and add its bin directory to PATH, set QT_INSTALL_DIR, or pass --qt-install-dir/--qmake.')

	print_tool('qmake', qmake, ['--version'], env=env)
	qt_lib_path = run_tool(qmake, ['-query', 'QT_INSTALL_LIBS'], env=env)
	qt_cmake_path = str(Path(qt_lib_path) / 'cmake')
	env.setdefault('CMAKE_PREFIX_PATH', qt_cmake_path)
	print(f'Qt libraries: {qt_lib_path}')
	print(f'CMAKE_PREFIX_PATH: {env["CMAKE_PREFIX_PATH"]}')
	return qmake


def check_binary_ninja_install(env):
	bn_install_dir = Path(args.bn_install_dir).expanduser().absolute() if args.bn_install_dir else None
	if not bn_install_dir:
		fail('Binary Ninja install directory was not specified. Set BN_INSTALL_DIR or pass --bn-install-dir.')
	if not bn_install_dir.exists():
		fail(f'Binary Ninja install directory {bn_install_dir} does not exist.')

	env['BN_INSTALL_DIR'] = str(bn_install_dir)
	if platform.system() == 'Darwin':
		core_candidates = [bn_install_dir / 'Contents' / 'MacOS' / 'libbinaryninjacore.dylib']
		ui_candidates = [bn_install_dir / 'Contents' / 'MacOS' / 'libbinaryninjaui.dylib']
	elif platform.system() == 'Windows':
		core_candidates = [bn_install_dir / 'binaryninjacore.dll']
		ui_candidates = [bn_install_dir / 'binaryninjaui.dll']
	else:
		core_candidates = [bn_install_dir / 'libbinaryninjacore.so.1', bn_install_dir / 'libbinaryninjacore.so']
		ui_candidates = [bn_install_dir / 'libbinaryninjaui.so.1', bn_install_dir / 'libbinaryninjaui.so']

	core = next((p for p in core_candidates if p.exists()), None)
	if not core:
		fail(f'Binary Ninja Core was not found in {bn_install_dir}. Checked: {", ".join(str(p) for p in core_candidates)}')
	print(f'Binary Ninja install: {bn_install_dir}')
	print(f'Binary Ninja Core: {core}')

	ui = next((p for p in ui_candidates if p.exists()), None)
	if args.headless:
		print('Binary Ninja UI: skipped because --headless was specified')
	elif ui:
		print(f'Binary Ninja UI: {ui}')
	else:
		fail(f'Binary Ninja UI was not found in {bn_install_dir}. Checked: {", ".join(str(p) for p in ui_candidates)}')


def contains_ui_dependency(cmake_lists):
	with open(cmake_lists, 'r', encoding='utf-8') as cmake_file:
		contents = cmake_file.read()
	return 'binaryninjaui' in contents or 'Qt6::' in contents or 'find_package(Qt6' in contents


def external_project_cmake_files():
	cmake_files = []

	# The examples are the supported customer-facing out-of-tree CMake projects
	for f in glob.glob(str(api_base / 'examples' / '**' / 'CMakeLists.txt'), recursive=True):
		cmake_path = Path(f)
		if cmake_path.parent == api_base / 'examples':
			continue
		cmake_files.append(cmake_path)

	for project in args.extra_project:
		project_path = Path(project).expanduser()
		if not project_path.is_absolute():
			project_path = api_base / project_path
		cmake_path = project_path / 'CMakeLists.txt'
		if not cmake_path.exists():
			fail(f'Extra project {project_path} does not contain a CMakeLists.txt file.')
		cmake_files.append(cmake_path)

	return sorted(cmake_files)


configure_env = os.environ.copy()
configure_qt_env(configure_env)
check_binary_ninja_install(configure_env)

if args.cc:
	configure_env['CC'] = args.cc
if args.cxx:
	configure_env['CXX'] = args.cxx

cmake = find_executable('cmake', args.cmake, env=configure_env)
if not cmake:
	fail('cmake not found. Install CMake and add it to PATH, set CMAKE, or pass --cmake.')
print_tool('cmake', cmake, ['--version'], env=configure_env)

print(f'C compiler: {configure_env.get("CC", "CMake platform default")}')
print(f'C++ compiler: {configure_env.get("CXX", "CMake platform default")}')
print(f'CMake build config: {args.config}')

configure_args = [f'-DCMAKE_BUILD_TYPE={args.config}']
build_args = ['--config', args.config]

if platform.system() == "Windows":
	configure_env['CXXFLAGS'] = f'/MP{args.parallel}'
	configure_env['CFLAGS'] = f'/MP{args.parallel}'
else:
	build_args.extend(['-j', str(args.parallel)])

if args.headless:
	configure_args.extend(['-DHEADLESS=1'])

# Copy api out of the source tree and build it externally
with tempfile.TemporaryDirectory() as tempdir:
	temp_api_base = Path(tempdir) / 'binaryninjaapi'
	print(f'Copy {api_base} => {temp_api_base}')
	shutil.copytree(api_base, temp_api_base)

	# Now try to build bundled out-of-tree projects the way customers would.
	for f in external_project_cmake_files():
		example_base = Path(f).parent

		# Check for headless
		if args.headless and contains_ui_dependency(f):
			print(f'Skip {example_base} because it requires UI/Qt and --headless was specified')
			continue

		with tempfile.TemporaryDirectory() as tempexdir:
			temp_example_base = Path(tempexdir) / example_base.name
			print(f'Copy {example_base} => {temp_example_base} at {datetime.now()}')
			shutil.copytree(example_base, temp_example_base)

			if (temp_example_base / 'build').exists():
				shutil.rmtree(temp_example_base / 'build')

			try:
				subprocess.check_call([cmake, '-B', 'build', f'-DBN_API_PATH={temp_api_base}'] + configure_args,
				                      cwd=temp_example_base, env=configure_env)
				subprocess.check_call([cmake, '--build', 'build'] + build_args, cwd=temp_example_base)
			finally:
				if (temp_example_base / 'build').exists():
					shutil.rmtree(temp_example_base / 'build')
