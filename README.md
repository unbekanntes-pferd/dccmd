<h1 align="center">DRACOON Commander</h1>


## Table of Contents

* [About the Project](#about-the-project)
  * [Built With](#built-with)
* [Getting Started](#getting-started)
  * [Prerequisites](#prerequisites)
  * [Installation](#installation)
* [Usage](#usage)
* [Configuration](#configuration)
* [License](#license)


## About the project
_Disclaimer: This is an unofficial client and is not supported by DRACOON._<br>
This client is a CLI tool to perform basic commands in DRACOON and comes with the following functionalities:

* Full support for S3 direct up- / download
    * Chunked up- and downloads
* Full support for DRACOON end-to-end encryption
* Optimized for concurrent requests
* Store credentials in OS-specific secure location
    * Linux: Freedesktop Secret Service (secretstorage)
    * macOS: Keychain
    * Windows: Windows Credential Locker

### Built With
* [typer](https://typer.tiangolo.com)
* [keyring](https://pypi.org/project/keyring)
* [dracoon](https://github.com/unbekanntes-pferd/dracoon-python-api)
    * [httpx](https://www.python-httpx.org/)
* [poetry](https://python-poetry.org/)

A full dependency list can be viewed in
* [pyproject.toml](/pyproject.toml) - list of dependencies and project info
* [poetry.lock](/poetry.lock)

DRACOON Commander is built with typer as the CLI framework and uses keyring to store all credentials (OAuth2 tokens, client credentials and encryption password). 
The tool is built on top of dracoon, an async API wrapper for DRACOON based on httpx.
The project is managed with poetry (dependencies, release build and publishing).

## Getting Started
In order to get started, download the latest tarball from Github or install dccmd from pip:
[Releases]()

### Prerequisites
You need a working Python 3.10 installation – dccmd makes use of type annotations and uses 3.10 features.
Get the latest Python version from: [python.org](https://python.org).

```bash
python3 --version
```

In order to get going, you can install dccmd either in a virtual environment or globally.

### Installation

To install a version, use `pip` and install the `dccmd` package.

#### In a virtual environment
```bash
virtualenv <DIR>
source <DIR>/bin/activate 
python3 -m pip install dccmd
```
#### Globally
```bash
python3 -m pip install dccmd
```

#### Set PATH
In order for the script to work, you might need to add the relevant script path to your PATH.
When installing with pip, the output will already indicate if the path is present or not.
If you do not add the correct directory to PATH, you will *not* be able to use the `dccmd` command in your preferred shell.

##### Windows
In Windows, just add the script path by editing the environment variables for your account:
Look for an entry called 'Path' and install the script directory from the `pip install` output.

##### Unix
On Linux or macOS you can add a path to PATH by using the following command:<br>
`export PATH="/your/directory/see/install/output:$PATH"`<br>


## Usage

### Display commands

In order to see all available commands, arguments and options, use the --help flag:
```bash
dccmd --help
```

```
Usage: dccmd [OPTIONS] COMMAND [ARGS]...

Options:
  --install-completion [bash|zsh|fish|powershell|pwsh]
                                  Install completion for the specified shell.
  --show-completion [bash|zsh|fish|powershell|pwsh]
                                  Show completion for the specified shell, to
                                  copy it or customize the installation.
  --help                          Show this message and exit.

Commands:
  auth
  client
  crypto
  download  Download a file from DRACOON by providing a source path and a...
  ls        List all nodes in a DRACOON path
  mkdir     Create a folder in a DRACOON parent path
  mkroom    Create a room (inherit permissions) in a DRACOON parent path
  rm        Delete a file / folder / room in DRACOON
  upload    Upload a file into DRACOON by providing a source path and a...
```
All commands display their own help message, e.g. 
`dccmd upload --help`.

### Client registration and authentication

Before you can perform any command, you must authenticate and set up the client.
If you enter any command which requires authentication (e.g. `dccmd ls your.dracoon.domain.com/`), you will be prompted first for a client configuration:
* client id
* client secret

#### Client 
Before you can use `dccmd` you need to generate a client in your DRACOON instance (config manager role required).
1. Create a client with a client id and client secret.
Please make sure you have the following settings active:
* Authorization code 
* Redirect URI is set to `https://your.dracoon.domain.com/oauth/callback`
* Optional: If you wish to use the CLI mode (enter password and username via CLI), you can activate password flow 

2. Copy client id and client secret and use any command (e.g. `dccmd ls your.dracoon.domain.com/`).

3. Enter client id and client secret – the information will be securely stored in your OS-specific secret container.

#### Authentication
Once the client is set up, you will receive a link to authenticate via OAuth2 authorization code flow – you will then receive a code which you need to enter into the terminal.
When completed, you will be prompted to store credentials securely (OS-specific).

Additionally, you can skip the authorization code flow and provide credentials directly, e.g. for the `dccmd ls` command:

```bash
dccmd ls your-dracoon.domain.com/ --cli-mode username@mail.com topsecret123!
```

### Upload

**Important: if you use Windows, you need to provide the path with '/' instead of '\\'!**

You can upload single files using the upload command:

```bash
dccmd upload /path/to/file.pdf your-dracoon.domain.com/
```
In order to upload a directory, use the `--recursive` (`-r`) flag:

```bash
dccmd upload -r /path/to/folder your-dracoon.domain.com/
```

#### Conflict resolution
If you upload a file which already exists (based on file name), the upload will be rejected.<br> 
In order to force an overwrite, use the `--overwrite` flag:

```bash
dccmd upload /path/to/file.pdf your-dracoon.domain.com/ --overwrite
```

If you wish to auto-rename the file if it already exists, use the `auto-rename`flag:

```bash
dccmd upload /path/to/file.pdf your-dracoon.domain.com/ --auto-rename
```

#### Advanced usage
If you upload folders recursively, you might encounter performance issues, specifically when uploading many small files. 
You can therefore adjust concurrent file uploads via the `--velocity` (`-v`) flag:

```bash
dccmd upload -r /path/to/folder your-dracoon.domain.com/ -v 3
```
The default value is 2 - it does not coincide with real request value.<br>
Maximum (although not recommended) value is 10. Entering higher numbers will result in max value use.<br>
Minimum value is 1 - this will not upload a folder per file but is the minimum concurrent request value. Entering lower numbers will result in min value use.

If you need to understand why uploads fail, you can also run the command using the `--debug` flag:

```bash
dccmd upload -r /path/to/folder your-dracoon.domain.com/ --debug
```
*Note: This will have impact on performance as the log will be streamed to terminal and the log level will be increased to DEBUG.*

### Create folder

If you wish to create a folder, use the `mkdir` command:

```bash
dccmd mkdir your-dracoon.domain.com/parent/newfolder
```
Just enter the full new path to create a folder. 
You will need *create* permission to do so.


### Create room

If you wish to create a room, use the `mkroom` command:

```bash
dccmd mkroom your-dracoon.domain.com/parent/newroom
```
Just enter the full new path to create a room. 
The room will be created as a room with inherited permissions from the parent.
You will need *manage* permission to do so.

To create a room on the root level ('/'), you need to provide an admin user using 
the corresponding option (`-au` or `--admin-user`):

```bash
dccmd mkroom -au "admin.username" your-dracoon.domain.com/newroom
```
*Note: In order to use the username of an OIDC user, you need to escape the `\`, meaning you need to enter multiple slashes like so: `OIDC\\\user.name`*

To create a room on any level that does *not* inherit permissions, use the `-au` (`--admin-user`) flag and provide the room admin when creating the room as with root level rooms:

```bash
dccmd mkroom -au "admin.username" your-dracoon.domain.com/parent-room/newroom
```

### Delete node

If you wish to delete a node, use the `rm` command:

```bash
dccmd rm your-dracoon.domain.com/parent/somefile.pdf
```
In order to delete a container (room, folder) you need to use the `--recursive` (`r`) flag:

```bash
dccmd rm your-dracoon.domain.com/parent/folder/to/delete
```
**Warning: Deleting rooms cannot be undone!**

### List nodes

In order to list all nodes, use the `ls` command:

```bash
dccmd ls your-dracoon.domain.com/
```
*Note: In order to list the root node, you need to provide a trailing `/`*
For a specific container (room or folder), use the path:
```bash
dccmd ls your-dracoon.domain.com/your/room
```

#### Displaying additional information
Using the `ls` command by default only provides node names.
In order to display more information, use relevant flags:

* Display all information (size, last updated, last update user): `--long` (`-l`)
    * Display sizes in human readable format (B, KB..): `--human-readable` (`-h`)
* Display node id: `--inode` (`-i`)

Example displaying full information:

```bash
dccmd ls -h -i -l your-dracoon.domain.com/your/room
```
### Download

To download a file, use the `download` command:

```bash
dccmd download your-dracoon.domain.com/your/cool-file.mp4 /target/directory
```

To download a room or a folder, use the `download` command with `--recursive` (`-r`) flag:

```bash
dccmd download -r your-dracoon.domain.com/your/cool-folder /target/directory
```

#### Advanced usage
If you download folders recursively, you might encounter performance issues, specifically when downloading many small files. 
You can therefore adjust concurrent file uploads via the `--velocity` (`-v`) flag:

```bash
dccmd upload -r /path/to/folder your-dracoon.domain.com/ -v 3
```
The default value is 2 - it does not coincide with real request value.<br>
Maximum (although not recommended) value is 10. Entering higher numbers will result in max value use.<br>
Minimum value is 1 - this will not download a folder per file but is the minimum concurrent request value. Entering lower numbers will result in min value use.

### User operations

You can list, edit and import users with relevant `dccmd users` command:

* csv-import  Add a list of users to DRACOON from a CSV file
* ls          Get a list of users in DRACOON
* rm          Delete a user

#### Importing users

You can import users by using the `csv-import` command and providing a path to the csv file:

```bash
dccmd users csv-import /path/to/users.csv your-dracoon.domain.com/
```

The csv file must contain a header and should include the following attributes:

* first name
* last name
* email 
* login (optional)

By default, local users are created - if you want to import oidc users, you need pass the oidc config id:

```bash
#example with OIDC config 5
dccmd users csv-import /path/to/users.csv your-dracoon.domain.com/ 5
```

#### Listing users

You can list all users using the `ls` command:

```bash
dccmd users ls your-dracoon.domain.com/
```

You can get all users also as csv format by using the `--csv` flag:

```bash
dccmd users ls your-dracoon.domain.com/ --csv > users.csv
```

To find a user, you can pass a search string to search for either first name, last name or user name (search string applies to all):

```bash
# will return all users with either first name, last name or user name containing 'yourname'
dccmd users ls your-dracoon.domain.com/ yourname
```

#### Deleting users

You can delete a user by providing the username:
```bash
dccmd users rm your-dracoon.domain.com/ user123
```

### Room permissions management

For an overview of the available commands use 

```bash
dccmd rooms --help
```

#### List user / group permissions in a room

To list user permissions in a room, use the `list-users` command:

```bash
dccmd rooms list-users your-dracoon.domain.com/your-room
```
You need minimum `read` permissions to list users.

To list group permissions in a room, use the `list-groups` command:

```bash
dccmd rooms list-groups your-dracoon.domain.com/your-room
```
You need minimum `read` permissions to list groups.

As with other commands, you can use the `--csv` flag to get a csv export for the room
permissions (users and groups).

#### Add user / group to a room

Currently, the following templates are available:
- read: read-only perrmissions for a room 
- edit: edit permissions for a room
- admin: room admin permissions

The permissions coincide with the templates in use of the official DRACOON Web App.

You need `manage` permissions (room admin) to add users / groups.

To add a user, use the `add-user` command and provide the user and permission template (`-u` and `-p`):

```bash
dccmd rooms add-user -u "user.name" -p admin your-dracoon.domain.com/your-room
```

To add a group, use the `add-group` command and provide the group and permission template (`-g` and `-p`):

```bash
dccmd rooms add-group -g "group.name" -p admin your-dracoon.domain.com/your-room
```

#### Remove user / group from a room

You need `manage` permissions (room admin) to remove users / groups.

To add a user, use the `remove-user` command and provide the user (`-u`):

```bash
dccmd rooms remove-user -u "user.name" your-dracoon.domain.com/your-room
```

To add a group, use the `remove-group` command and provide the group (`-g`):

```bash
dccmd rooms remove-group -g "group.name" your-dracoon.domain.com/your-room
```

## Configuration / administration

You can view / manage the configuration for `dccmd` using the relevant commands:

* `dccmd auth` - manage credentials
    * `dccmd auth ls your.dracoon.domain.com` will display if a refresh token has been stored for the provided domain
    * `dccmd auth rm your-dracoon.domain.com` will remove stored credentials for the provided domain
* `dccmd client` - manage client
    * `dccmd client register your.dracoon.domain.com` will start the registration process for a client and given domain
    * `dccmd client ls your.dracoon.domain.com` will display client information for the provided domain
    * `dccmd client rm your-dracoon.domain.com` will remove the stored client config for the provided domain
* `dccmd crypto` - manage encryption
    * `dccmd crypto ls your.dracoon.domain.com` will display if encryption password is stored for the provided domain
    * `dccmd crypto rm your-dracoon.domain.com` will remove the encryption password for the provided domain
    * `dccmd crypto distribute your-dracoon.domain.com/` will generate file keys available to distribute - if providing a specific path (`dccmd crypto distribute your-dracoon.domain.com/some/path`), only keys for provided parent room will be generated.

### Logging 
When using a command, a log will be created in the current working directory.
Currently it is not possible to configure a default path for a log.

You can stream the log to stdout by using the `--debug` flag with any DRACOON-specific command (`upload`, `download`, `ls`, `rm`, `mkdir`, `mkroom`).


## License
Distributed under the Apache License. See [LICENSE](/LICENSE) for more information.
