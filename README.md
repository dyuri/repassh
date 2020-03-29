# repassh

SSH wrapper to load private keys via `ssh-add` when they are first needed.

Heavily based on [ssh-ident](https://github.com/ccontavalli/ssh-ident).

## Usage

Use this script to start ssh-agents and load ssh keys on demand,
when they are first needed.

All you have to do is modify your .bashrc to have:

```
alias ssh='/path/to/repassh'
```

or add a link to `repassh` from a directory in your PATH, for example:

```
ln -s /path/to/repassh ~/bin/ssh
```

If you use scp or rsync regularly, you should add a few more lines described
below.

In any case, `repassh`:

- will start ssh-agent and load the keys you need the first time you
  actually need them, once. No matter how many terminals, ssh or login
  sessions you have, no matter if your home is shared via NFS.
- can prepare and use a different agent and different set of keys depending
  on the host you are connecting to, or the directory you are using ssh
  from.
  This allows for isolating keys when using agent forwarding with different
  sites (eg, university, work, home, secret evil internet identity, ...).
  It also allows to use multiple accounts on sites like github, unfuddle
  and gitorious easily.
- allows to specify different options for each set of keys. For example, you
  can provide a -t 60 to keep keys loaded for at most 60 seconds. Or -c to
  always ask for confirmation before using a key.


## Installation

All you need to run `repassh` is a standard installation of python >= 3.6.

To install it, run:

```
pip install repassh
```

Then you can use the `repassh` command just as you'd use `ssh`.

## Alternatives

In `.bashrc` you can define an alias:

```
alias ssh=/path/to/repassh
```

then all you have to do is:

```
ssh somewhere
```

`repassh` will be called instead of `ssh`, and it will:

- check if `ssh-agent` is running. If not, it will start one.
- try to load all the keys in `~/.ssh`, if not loaded.

If you use `ssh` again, `repassh` will reuse the same agent
and the same keys.

## About scp, rsync, and friends

`scp`, `rsync`, and most similar tools internally invoke `ssh`. If you don't tell
them to use `repassh` instead, key loading won't work. There are a few ways
to solve the problem:

### Rename or link

Rename `repassh` to `ssh` or create a symlink `ssh` pointing to
`repassh` in a directory in your PATH before `/usr/bin` or `/bin`.

For example:

```
ln -s /path/to/repassh ~/bin/ssh
export PATH="~/bin:$PATH"
```

Make sure `echo $PATH` shows `~/bin` *before* `/usr/bin` or `/bin`. You
can verify this is working as expected with `which ssh`, which should
show `~/bin/ssh`.

This works for `rsync` and `git`, among others, but not for `scp` and `sftp`, as
these do not look for `ssh` in your `PATH` but use a hard-coded path to the
binary.

If you want to use `repassh` with `scp` or `sftp`,  you can simply create
symlinks for them as well:

```
ln -s /path/to/repassh ~/bin/scp
ln -s /path/to/repassh ~/bin/sftp
```

### More aliases

Add a few more aliases in your .bashrc file, for example:

```
alias scp='BINARY_SSH=scp /path/to/repassh'
alias rsync='BINARY_SSH=rsync /path/to/repassh'
...
```

The first alias will make the `scp` command invoke `repassh` instead,
but tell `repassh` to invoke `scp` instead of the plain `ssh` command
after loading the necessary agents and keys.

Note that aliases don't work from scripts - if you have any script that
you expect to use with `repassh`, you may prefer the first method, or you will
need to update the script accordingly.

### Tell other programs to use `repassh` instead of `ssh`

Use command specific methods to force them to use `repassh` instead of
`ssh`, for example:

```
rsync -e '/path/to/repassh' ...
scp -S '/path/to/repassh' ...
```

## Config file with multiple identities

To have multiple identities:

1. create a `$XDG_CONFIG_HOME/repassh/config.json` file. In this file, you need to tell `repassh`
   which identities to use and when. The file should be a valid JSON (ignore/remove the lines
   starting with #, they are comments, but JSON does not have comments):

   ```
   {
   # Specifies which identity to use depending on the path I'm running ssh
   # from.
   # For example: ("mod-xslt", "personal") means that for any path that
   # contains the word "mod-xslt", the "personal" identity should be used.
   # This is optional - don't include any MATCH_PATH if you don't need it.
   
     "MATCH_PATH": [
       ["mod-xslt", "personal"],
       ["repassh", "personal"],
       ["opt/work", "work"],
       ["opt/private", "secret"]
     ],
  
   # If any of the ssh arguments have 'cweb' in it, the 'personal' identity
   # has to be used. For example: "ssh myhost.cweb.com" will have cweb in
   # argv, and the "personal" identity will be used.
   # This is optional - don't include any MATCH_ARGV if you don't
   # need it.
  
     "MATCH_ARGV": [
       ("cweb", "personal"),
       ("corp", "work")
     ],
  
   # Note that if no match is found, the DEFAULT_IDENTITY is used. This is
   # generally your loginname, no need to change it.
   # This is optional - don't include any DEFAULT_IDENTITY if you don't
   # need it.

   # "DEFAULT_IDENTITY": "foo",

   # Use running `ssh-agent`, true by default
   # If `SSH_AUTH_SOCK` and `SSH_AGENT_PID` environment variables are set
   # and the agent responds then it will be used instead of executing a new
   # one based on identity matching.
   # If the agent does not respond, a new one is started just like
   # `USE_RUNNING_AGENT` would be false.

   # "USE_RUNNING_AGENT": true,
  
   # This is optional - don't include any SSH_ADD_OPTIONS if you don't
   # need it.

     "SSH_ADD_OPTIONS": {
       # Regardless, ask for confirmation before using any of the
       # work keys.
       "work": "-c",
       # Forget about secret keys after ten minutes. repassh will
       # automatically ask you your passphrase again if they are needed.
       "secret": "-t 600"
     },
  
   # This is optional - don't include any SSH_OPTIONS if you don't
   # need it.
   # Otherwise, provides options to be passed to 'ssh' for specific
   # identities.

     "SSH_OPTIONS": {
       # Disable forwarding of the agent, but enable X forwarding,
       # when using the work profile.
       "work": "-Xa",
  
       # Always forward the agent when using the secret identity.
       "secret": "-A"
     },
  
   # Options to pass to ssh by default.
   # If you don't specify anything, UserRoaming=no is passed, due
   # to CVE-2016-0777. Leave it empty to disable this.

     "SSH_DEFAULT_OPTIONS": "-oUseRoaming=no",
  
   # Which options to use by default if no match with SSH_ADD_OPTIONS
   # was found. Note that repassh hard codes -t 7200 to prevent your
   # keys from remaining in memory for too long.

     "SSH_ADD_DEFAULT_OPTIONS": "-t 7200",
  
   # Output verbosity
   # valid values are:
   #   LOG_ERROR = 1, LOG_WARN = 2, LOG_INFO = 3, LOG_DEBUG = 4

     "VERBOSITY": 3
   }
   ```

2. Create the directory where all the identities and agents
   will be kept:

   ```
   mkdir -p ~/.ssh/identities; chmod u=rwX,go= -R ~/.ssh
   ```

3. Create a directory for each identity, for example:

   ```
   mkdir -p ~/.ssh/identities/personal
   mkdir -p ~/.ssh/identities/work
   mkdir -p ~/.ssh/identities/secret
   ```

4. Generate (or copy) keys for those identities:

   ```
   # Default keys are for my personal account
   $ cp ~/.ssh/id_rsa* ~/.ssh/identities/personal

   # Generate keys to be used for work only, rsa
   $ ssh-keygen -t rsa -b 4096 -f ~/.ssh/identities/work/id_rsa

   ...
   ```


Now if you run:

```
$ ssh corp.mywemployer.com
```

`repassh` will be invoked and:

1. checks `ssh` argv, determine that the *work* identity has to be used.
2. checks `~/.ssh/agents` for a *work* agent loaded. If there is no
   agent, it will prepare one.
3. checks `~/.ssh/identities/work/` for a list of keys to load for this
   identity. It will try to load any key that is not already loaded in
   the agent.
4. finally run `ssh` with the environment setup such that it will have
   access only to the agent for the identity work, and the corresponding
   keys.

Note that `repassh` needs to access both your private and public keys. Note
also that it identifies public keys by the .pub extension. All files in your
identities subdirectories will be considered keys.

If you want to only load keys that have "key" in the name, you can add
to your `config.json`:

```
PATTERN_KEYS = "key"
```

The default is:

```
PATTERN_KEYS = r"/(id_.*|identity.*|ssh[0-9]-.*)"
```

You can also redefine:

```
DIR_IDENTITIES = "$HOME/.ssh/identities"
DIR_AGENTS = "$HOME/.ssh/agents"
```

To point somewhere else if you so desire.
