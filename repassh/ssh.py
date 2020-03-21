"""Helper function to start SSH agent and add keys using ssh-add
"""
import collections
import distutils.spawn
import errno
import fcntl
import getpass
import os
import re
import socket
import subprocess
import sys
import termios
import textwrap
import json

__all__ = ()

LOG_ERROR = 1
LOG_WARN = 2
LOG_INFO = 3
LOG_DEBUG = 4
LOG_CONSTANTS = {
    "LOG_ERROR": LOG_ERROR,
    "LOG_WARN": LOG_WARN,
    "LOG_INFO": LOG_INFO,
    "LOG_DEBUG": LOG_DEBUG
}


class Config:
    """Holds and loads users configurations."""

    defaults = {
        # Where to find the per-user configuration.
        "FILE_USER_CONFIG": "$HOME/.config/repassh/config.json"
                            if "XDG_CONFIG_HOME" not in os.environ
                            else "$XDG_CONFIG_HOME/repassh/config.json",

        # Where to find all the identities for the user.
        "DIR_IDENTITIES": "$HOME/.ssh/identities",
        # Where to keep the information about each running agent.
        "DIR_AGENTS": "$HOME/.ssh/agents",

        # How to identify key files in the identities directory.
        "PATTERN_KEYS": r"/(id_.*|identity.*|ssh[0-9]-.*)",

        # How to identify ssh config files.
        "PATTERN_CONFIG": r"/config$",

        # Dictionary with identity as a key, automatically adds
        # the specified options to the ssh command run.
        "SSH_OPTIONS": {},
        # Additional options to append to ssh by default.
        "SSH_DEFAULT_OPTIONS": "-oUseRoaming=no",

        # Complete path of full ssh binary to use. If not set, repassh will
        # try to find the correct binary in PATH.
        "BINARY_SSH": None,
        "BINARY_DIR": None,

        # Which identity to use by default if we cannot tell from
        # the current working directory and/or argv.
        "DEFAULT_IDENTITY": "$USER",

        # Those should really be overridden by the user. Look
        # at the documentation for more details.
        "MATCH_PATH": [],
        "MATCH_ARGV": [],

        # Dictionary with identity as a key, allows to specify
        # per identity options when using ssh-add.
        "SSH_ADD_OPTIONS": {},
        # ssh-add default options. By default, don't keep a key longer
        # than 2 hours.
        "SSH_ADD_DEFAULT_OPTIONS": "-t 7200",

        # Like BatchMode in ssh, see man 5 ssh_config.
        # In BatchMode repassh will not print any output and not ask for
        # any passphrases.
        "SSH_BATCH_MODE": False,

        # Output verbosity
        # valid values are: LOG_ERROR, LOG_WARN, LOG_INFO, LOG_DEBUG
        # use 0 to disable ALL output (not recommended!)
        "VERBOSITY": LOG_INFO,

        # If executed from python code, we should not use `sys.exit` to exit
        "SYSEXIT": True,
    }

    def __init__(self, cfg={}):
        self.values = cfg

    def load(self):
        """Load configurations from the default user file."""
        path = self.get("FILE_USER_CONFIG")
        variables = {}
        try:
            variables = json.load(open(path))
        except IOError:
            return self

        self.values.update(variables)
        return self

    @staticmethod
    def expand(value):
        """Expand environment variables or ~ in string parameters."""
        if isinstance(value, str):
            return os.path.expanduser(os.path.expandvars(value))
        return value

    def get(self, parameter):
        """Returns the value of a parameter, or causes the script to exit."""
        if parameter in os.environ:
            return self.expand(os.environ[parameter])
        if parameter in self.values:
            return self.expand(self.values[parameter])
        if parameter in self.defaults:
            return self.expand(self.defaults[parameter])

        print("Parameter '{0}' needs to be defined in "
              "config file or defaults".format(parameter), file=sys.stderr)
        self.exit(2)

    def set(self, parameter, value):
        """Sets configuration option parameter to value."""
        self.values[parameter] = value

    def print(self, *args, **kwargs):
        """Wrapper for print"""
        loglevel = kwargs.get('loglevel', LOG_INFO)
        if "loglevel" in kwargs:
            del kwargs["loglevel"]

        verbosity = self.get("VERBOSITY")

        if loglevel <= verbosity:
            print(*args, **kwargs)

    def exit(self, exit_code):
        """Based on configuration, calls `sys.exit` or simply logs the `exit_code`."""
        if self.get("SYSEXIT"):
            sys.exit(exit_code)

        if exit_code:
            self.print(f"ERROR [{exit_code}]", file=sys.stderr, loglevel=LOG_INFO)

        return exit_code


def find_identity_in_list(elements, identities):
    """Matches a list of identities to a list of elements.

    Args:
      elements: iterable of strings, arbitrary strings to match on.
      identities: iterable of (string, string), with first string
        being a regular expression, the second string being an identity.

    Returns:
      The identity specified in identities for the first regular expression
      matching the first element in elements.
    """
    for element in elements:
        for regex, identity in identities:
            if re.search(regex, element):
                return identity
    return None


def find_identity(argv, config):
    """Returns the identity to use based on current directory or argv.

    Args:
      argv: iterable of string, argv passed to this program.
      config: instance of an object implementing the same interface as
          the Config class.

    Returns:
      string, the name of the identity to use.
    """
    paths = set([os.getcwd(), os.path.abspath(os.getcwd()), os.path.normpath(os.getcwd())])
    return (
        find_identity_in_list(argv, config.get("MATCH_ARGV")) or
        find_identity_in_list(paths, config.get("MATCH_PATH")) or
        config.get("DEFAULT_IDENTITY"))


def find_keys(identity, config):
    """Finds all the private and public keys associated with an identity.

    Args:
      identity: string, name of the identity to load strings of.
      config: object implementing the Config interface, providing configurations
          for the user.

    Returns:
      dict, {"key name": {"pub": "/path/to/public/key", "priv":
      "/path/to/private/key"}}, for each key found, the path of the public
      key and private key. The key name is just a string representing the
      key. Note that for a given key, it is not guaranteed that both the
      public and private key will be found.
      The return value is affected by DIR_IDENTITIES and PATTERN_KEYS
      configuration parameters.
    """
    directories = [os.path.join(config.get("DIR_IDENTITIES"), identity)]
    if identity == getpass.getuser():
        directories.append(os.path.expanduser("~/.ssh"))

    pattern = re.compile(config.get("PATTERN_KEYS"))
    found = collections.defaultdict(dict)
    for directory in directories:
        try:
            keyfiles = os.listdir(directory)
        except OSError as e:
            if e.errno == errno.ENOENT:
                continue
            raise

        for key in keyfiles:
            key = os.path.join(directory, key)
            if not os.path.isfile(key):
                continue
            if not pattern.search(key):
                continue

            kinds = (
                ("private", "priv"),
                ("public", "pub"),
                (".pub", "pub"),
                ("", "priv"),
            )

            for match, kind in kinds:
                if match in key:
                    found[key.replace(match, "")][kind] = key

    if not found:
        config.print("Warning: no keys found for identity {0} in:".format(identity),
                     file=sys.stderr,
                     loglevel=LOG_WARN)
        config.print(directories, file=sys.stderr, loglevel=LOG_WARN)

    return found


def find_ssh_config(identity, config):
    """Finds a config file if there's one associated with an identity

    Args:
      identity: string, name of the identity to load strings of.
      config: object implementing the Config interface, providing configurations
        for the user.

    Returns:
      string, the configuration file to use
    """
    directories = [os.path.join(config.get("DIR_IDENTITIES"), identity)]

    pattern = re.compile(config.get("PATTERN_CONFIG"))
    sshconfigs = collections.defaultdict(dict)
    for directory in directories:
        try:
            sshconfigs = os.listdir(directory)
        except OSError as e:
            if e.errno == errno.ENOENT:
                continue
            raise

        for sshconfig in sshconfigs:
            sshconfig = os.path.join(directory, sshconfig)
            if os.path.isfile(sshconfig) and pattern.search(sshconfig):
                return sshconfig

    return False


def get_session_tty():
    """Returns a file descriptor for the session TTY, or None.

    In *nix systems, each process is tied to one session. Each
    session can be tied (or not) to a terminal, "/dev/tty".

    Additionally, when a command is run, its stdin or stdout can
    be any file descriptor, including one that represent a tty.

    So for example:

      ./test.sh < /dev/null > /dev/null

    will have stdin and stdout tied to /dev/null - but does not
    tell us anything about the session having a /dev/tty associated
    or not.

    For example, running

      ssh -t user@remotehost './test.sh < /dev/null > /dev/null'

    have a tty associated, while the same command without -t will not.

    When ssh is invoked by tools like git or rsyn, its stdin and stdout
    is often tied to a file descriptor which is not a terminal, has
    the tool wants to provide the input and process the output.

    repassh internally has to invoke ssh-add, which needs to know if
    it has any terminal it can use at all.

    This function returns an open file if the session has an usable terminal,
    None otherwise.
    """
    try:
        fd = open("/dev/tty", "r")
        fcntl.ioctl(fd, termios.TIOCGPGRP, "  ")
    except IOError:
        return None
    return fd


class AgentManager:
    """Manages the ssh-agent for one identity."""

    def __init__(self, identity, sshconfig, config):
        """Initializes an AgentManager object.

        Args:
            identity: string, identity the ssh-agent managed by this instance of
                an AgentManager will control.
            config: object implementing the Config interface, allows access to
                the user configuration parameters.

        Attributes:
            identity: same as above.
            config: same as above.
            agents_path: directory where the config of all agents is kept.
            agent_file: the config of the agent corresponding to this identity.

        Parameters:
            DIR_AGENTS: used to compute agents_path.
            BINARY_SSH: path to the ssh binary.
        """
        self.identity = identity
        self.config = config
        self.ssh_config = sshconfig
        self.agents_path = os.path.abspath(config.get("DIR_AGENTS"))
        self.agent_file = self.get_agent_file(self.agents_path, self.identity, config)

    def load_unloaded_keys(self, keys):
        """Loads all the keys specified that are not loaded.

        Args:
            keys: dict as returned by FindKeys.
        """
        toload = self.find_unloaded_keys(keys)
        if toload:
            self.config.print("Loading keys:\n    {0}".format("\n    ".join(toload)),
                              file=sys.stderr, loglevel=LOG_INFO)
            self.load_key_files(toload)
        else:
            self.config.print("All keys already loaded", file=sys.stderr, loglevel=LOG_INFO)

    def find_unloaded_keys(self, keys):
        """Determines which keys have not been loaded yet.

        Args:
            keys: dict as returned by FindKeys.

        Returns:
            iterable of strings, paths to private key files to load.
        """
        loaded = set(self.get_loaded_keys())
        toload = set()
        for _, config in keys.items():
            if "pub" not in config:
                continue
            if "priv" not in config:
                continue

            fingerprint = self.get_public_key_fingerprint(config["pub"])
            if fingerprint in loaded:
                continue

            toload.add(config["priv"])
        return toload

    def load_key_files(self, keys):
        """Load all specified keys.

        Args:
            keys: iterable of strings, each string a path to a key to load.
        """
        keys = " ".join(keys)
        options = self.config.get("SSH_ADD_OPTIONS").get(
            self.identity, self.config.get("SSH_ADD_DEFAULT_OPTIONS"))
        console = get_session_tty()
        self.run_shell_command_in_agent(
            self.agent_file, "ssh-add {0} {1}".format(options, keys),
            stdout=console, stdin=console)

    def get_loaded_keys(self):
        """Returns an iterable of strings, each the fingerprint of a loaded key."""
        retval, stdout = self.run_shell_command_in_agent(self.agent_file, "ssh-add -l")
        if retval != 0:
            return []

        fingerprints = []
        for line in stdout.decode("utf-8").split("\n"):
            try:
                _, fingerprint, _ = line.split(" ", 2)
                fingerprints.append(fingerprint)
            except ValueError:
                continue

        return fingerprints

    @staticmethod
    def get_public_key_fingerprint(key):
        """Returns the fingerprint of a public key as a string."""
        retval, stdout = AgentManager.run_shell_command(
            "ssh-keygen -l -f {0} |tr -s ' '".format(key))
        if retval:
            return None

        try:
            _, fingerprint, _ = stdout.decode("utf-8").split(" ", 2)
        except ValueError:
            return None

        return fingerprint

    @staticmethod
    def get_agent_file(path, identity, config):
        """Returns the path to an agent config file.

        Args:
            path: string, the path where agent config files are kept.
            identity: string, identity for which to load the agent.

        Returns:
            string, path to the agent file.
        """
        # Create the paths, if they do not exist yet.
        try:
            os.makedirs(path, 0o700)
        except OSError as e:
            if e.errno != errno.EEXIST:
                raise OSError(
                    "Cannot create agents directory, try manually with "
                    "'mkdir -p {0}'".format(path))

        # Use the hostname as part of the path just in case this is on NFS.
        agentfile = os.path.join(
            path, "agent-{0}-{1}".format(identity, socket.gethostname()))
        if os.access(agentfile, os.R_OK) and AgentManager.is_agent_file_valid(agentfile, config):
            config.print("Agent for identity {0} ready".format(identity), file=sys.stderr,
                         loglevel=LOG_DEBUG)
            return agentfile

        config.print("Preparing new agent for identity {0}".format(identity), file=sys.stderr,
                     loglevel=LOG_DEBUG)
        subprocess.call(
            ["/usr/bin/env", "-i", "/bin/sh", "-c", "ssh-agent > {0}".format(agentfile)])

        return agentfile

    @staticmethod
    def is_agent_file_valid(agentfile, config):
        """Returns true if the specified agentfile refers to a running agent."""
        retval, _ = AgentManager.run_shell_command_in_agent(
            agentfile, "ssh-add -l >/dev/null 2>/dev/null")
        if retval & 0xff not in [0, 1]:
            config.print("Agent in {0} not running".format(agentfile), file=sys.stderr,
                         loglevel=LOG_DEBUG)
            return False

        return True

    @staticmethod
    def run_shell_command(command):
        """Runs a shell command, returns (status, stdout), (int, string)."""
        command = ["/bin/sh", "-c", command]
        process = subprocess.Popen(command, stdout=subprocess.PIPE)
        stdout, _ = process.communicate()
        return process.wait(), stdout

    @staticmethod
    def run_shell_command_in_agent(agentfile, command, stdin=None, stdout=subprocess.PIPE):
        """Runs a shell command with an agent configured in the environment."""
        command = ["/bin/sh", "-c",
                   ". {0} >/dev/null 2>/dev/null; {1}".format(agentfile, command)]
        process = subprocess.Popen(command, stdin=stdin, stdout=stdout)
        stdout, _ = process.communicate()
        return process.wait(), stdout

    @staticmethod
    def escape_shell_arguments(argv):
        """Escapes all arguments to the shell, returns a string."""
        escaped = []
        for arg in argv:
            escaped.append("'{0}'".format(arg.replace("'", "'\"'\"'")))
        return " ".join(escaped)

    def get_shell_args(self):
        """Returns the flags to be passed to the shell to run a command."""
        shell_args = "-c"
        if self.config.get("VERBOSITY") >= LOG_DEBUG:
            shell_args = "-xc"

        return shell_args

    def run_ssh(self, argv):
        """Execs ssh with the specified arguments."""
        additional_flags = self.config.get("SSH_OPTIONS").get(
            self.identity, self.config.get("SSH_DEFAULT_OPTIONS"))

        if self.ssh_config:
            additional_flags += " -F {0}".format(self.ssh_config)

        command = [
            "/bin/sh", self.get_shell_args(),
            ". {0} >/dev/null 2>/dev/null; exec {1} {2} {3}".format(
                self.agent_file, self.config.get("BINARY_SSH"),
                additional_flags, self.escape_shell_arguments(argv))]
        exit_code = os.spawnv(os.P_WAIT, "/bin/sh", command)

        return self.config.exit(exit_code)


def autodetect_binary(argv, config):
    """Detects the correct binary to run and sets BINARY_SSH accordingly,
    if it is not already set."""
    # If BINARY_SSH is set by the user, respect that and do nothing.
    if config.get("BINARY_SSH"):
        config.print("Will run '{0}' as ssh binary - set by user via BINARY_SSH"
                     .format(config.get("BINARY_SSH")), loglevel=LOG_DEBUG)
        return

    # If BINARY_DIR is set, look for the binary in this directory.
    runtime_name = argv[0]
    if config.get("BINARY_DIR"):
        binary_name = os.path.basename(runtime_name)
        binary_path = os.path.join(config.get("BINARY_DIR"), binary_name)
        if not os.path.isfile(binary_path) or not os.access(binary_path, os.X_OK):
            binary_path = os.path.join(config.get("BINARY_DIR"), "ssh")

        config.set("BINARY_SSH", binary_path)
        config.print("Will run '{0}' as ssh binary - detected based on BINARY_DIR"
                     .format(config.get("BINARY_SSH")), loglevel=LOG_DEBUG)
        return

    # argv[0] could be pretty much anything the caller decides to set
    # it to: an absolute path, a relative path (common in older systems),
    # or even something entirely unrelated.
    #
    # Similar is true for __file__, which might even represent a location
    # that is entirely unrelated to how repassh was found.
    #
    # Consider also that there might be symlinks / hard links involved.
    #
    # The logic here is pretty straightforward:
    # - Try to eliminate the path of repassh from PATH.
    # - Search for a binary with the same name of repassh to run.
    #
    # If this fails, we may end up in some sort of loop, where repassh
    # tries to run itself. This should normally be detected later on,
    # where the code checks for the next binary to run.
    #
    # Note also that users may not be relying on having repassh in the
    # PATH at all - for example, with "rsync -e '/path/to/repassh' ..."
    binary_name = os.path.basename(runtime_name)
    ssh_ident_path = ""
    if not os.path.dirname(runtime_name):
        message = textwrap.dedent("""\
            argv[0] ("{0}") is a relative path. This means that repassh does
            not know its own directory, and can't exclude it from searching it
            in $PATH:

            PATH="{1}"

            This may result in a loop, with 'repassh' trying to run itself.
            It is recommended that you set BINARY_SSH, BINARY_DIR, or run
            repassh differently to prevent this problem.""")

        config.print(message.format(runtime_name, os.environ['PATH']),
                     loglevel=LOG_INFO)
    else:
        ssh_ident_path = os.path.abspath(os.path.dirname(runtime_name))

    # Remove the path containing the repassh symlink (or whatever) from
    # the search path, so we do not cause an infinite loop.
    # Note that:
    #  - paths in PATH may be not-normalized, example: "/usr/bin/../foo",
    #    or "/opt/scripts///". Normalize them before comparison.
    #  - paths in PATH may be repeated multiple times. We have to exclude
    #    all instances of the repassh path.
    normalized_path = [
        os.path.normpath(p) for p in os.environ['PATH'].split(os.pathsep)]
    search_path = os.pathsep.join([
        p for p in normalized_path if p != ssh_ident_path])

    # Find an executable with the desired name.
    binary_path = distutils.spawn.find_executable(binary_name, search_path)
    if not binary_path:
        # Nothing found. Try to find something named 'ssh'.
        binary_path = distutils.spawn.find_executable('ssh')

    if binary_path:
        config.set("BINARY_SSH", binary_path)
        config.print("Will run '{0}' as ssh binary - detected from argv[0] and $PATH"
                     .format(config.get("BINARY_SSH")), loglevel=LOG_DEBUG)
    else:
        message = textwrap.dedent("""\
            repassh was invoked in place of the binary {0} (determined from argv[0]).
            Neither this binary nor 'ssh' could be found in $PATH.

            PATH="{1}"

            You need to adjust your setup for repassh to work: consider setting
            BINARY_SSH or BINARY_DIR in your config, or running repassh some
            other way.""")

        config.print(message.format(argv[0], os.environ['PATH']), loglevel=LOG_ERROR)
        config.exit(255)


def check_exit(argv, config):
    # if `repassh` is used from `python` or `xonsh` `sys.exit` should not be used
    runtime_name = argv[0]
    binary_name = os.path.basename(runtime_name)
    if binary_name in ['', 'python', 'xonsh']:
        config.print(f"`repassh` was invoked by `{binary_name}`, not using `sys.exit`.",
                     loglevel=LOG_DEBUG)
        config.set('SYSEXIT', False)


def parse_command_line(argv, config):
    """Parses the command line parameters in argv
    and modifies config accordingly."""
    # This function may need a lot of refactoring if it is ever used for more
    # than checking for BatchMode for OpenSSH...
    binary = os.path.basename(config.get("BINARY_SSH"))
    if binary in ['ssh', 'scp']:
        # OpenSSH accepts -o Options as well as -oOption,
        # so let's convert argv to the latter form first
        i = iter(argv)
        argv = [p + next(i, '') if p == '-o' else p for p in i]
        # OpenSSH accepts 'Option=yes' and 'Option yes', 'true' instead of 'yes'
        # and treats everything case-insensitive
        # if an option is given multiple times,
        # OpenSSH considers the first occurrence only
        re_batchmode = re.compile(r"-oBatchMode[= ](yes|true)", re.IGNORECASE)
        re_nobatchmode = re.compile(r"-oBatchMode[= ](no|false)", re.IGNORECASE)
        for p in argv:
            if re.match(re_batchmode, p):
                config.set("SSH_BATCH_MODE", True)
                break
            if re.match(re_nobatchmode, p):
                config.set("SSH_BATCH_MODE", False)
                break


def main(argv, cfg={}):
    """Main method"""
    # Replace stdout and stderr with /dev/tty, so we don't mess up with scripts
    # that use ssh in case we error out or similar.
    try:
        sys.stdout = open("/dev/tty", "w")
        sys.stderr = open("/dev/tty", "w")
    except IOError:
        pass

    config = Config(cfg).load()
    check_exit(argv, config)
    autodetect_binary(argv, config)

    # Check that BINARY_SSH is not repassh.
    # This can happen if the user sets a binary name only (e.g. 'scp') and a
    # symlink with the same name was set up.
    # Note that this relies on argv[0] being set sensibly by the caller,
    # which is not always the case. argv[0] may also just have the binary
    # name if found in a path.
    binary_path = os.path.realpath(
        distutils.spawn.find_executable(config.get("BINARY_SSH")))

    if argv[0]:
        ssh_ident_path = os.path.realpath(
            distutils.spawn.find_executable(argv[0]))
        if binary_path == ssh_ident_path:
            message = textwrap.dedent("""\
            repassh found '{0}' as the next command to run.
            Based on argv[0] ({1}), it seems like this will create a
            loop.

            Please use BINARY_SSH, BINARY_DIR, or change the way
            repassh is invoked (eg, a different argv[0]) to make
            it work correctly.""")

            config.print(message.format(config.get("BINARY_SSH"), argv[0]), loglevel=LOG_ERROR)
            config.exit(255)

    parse_command_line(argv, config)
    identity = find_identity(argv, config)
    keys = find_keys(identity, config)
    sshconfig = find_ssh_config(identity, config)
    agent = AgentManager(identity, sshconfig, config)

    if not config.get("SSH_BATCH_MODE"):
        # do not load keys in BatchMode
        agent.load_unloaded_keys(keys)

    return agent.run_ssh(argv[1:])
