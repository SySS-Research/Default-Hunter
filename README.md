# Default Hunter

A default credential scanner.

## Important note: This is a fork

This is a fork of [changeme](https://github.com/ztgrace/changeme/). The tool
appears to be abandoned and has become a bit dated. I modernized the code base somewhat
(formatting, linting, type hints, file structure, Python packaging) and removed
some features while adding others. Most important differences:

- To avoid confusion, the project has been renamed.
- Removed Redis dependency, as this was quite the obstacle to get the program
  installed. The code is now Python-only. That also means we lose the resume
  feature.
- Scan all protocols by default. If you want less protocols, you have to use the
  `--protocols` argument.
- When loading targets from nmap, use the protocol information from the nmap
  file. Only perform scans with matching protocol, i.e. no HTTP fingerprinting
  on SNMP ports.
- The output is now less chatty. To get a status update, press SPACE.
- Fixed the SNMP and Telnet scanners.

## About

Default Hunter picks up where commercial scanners leave off. It focuses on detecting default and backdoor credentials and not necessarily common credentials.

Default Hunter is designed to be simple to add new credentials without having to write any code or modules. Default Hunter keeps credential data separate from code. All credentials are stored in [yaml](http://yaml.org/) files so they can be both easily read by humans and processed by Default Hunter. Credential files can be created by using the `default-hunter --mkcred` tool and answering a few questions.

Default Hunter supports the http/https, mssql, mysql, postgres, ssh, ssh w/key, snmp, mongodb and ftp protocols. Use `default-hunter --dump` to output all of the currently available credentials.

You can load your targets using a variety of methods, single ip address/host, subnet, list of hosts, nmap xml file and Shodan query. All methods except for Shodan are loaded as a positional argument and the type is inferred.

## Installation

Default Hunter has only been tested on Linux and has known issues on Windows and OS X/macOS. Use docker to run Default Hunter on the unsupported platforms:

```console
docker run --rm -v uv-cache:/root/.cache -v $(pwd):/workdir -w /workdir \
    ghcr.io/astral-sh/uv:debian \
    uv tool run --with=git+https://github.com/SySS-Research/DefaultHunter.git \
    default-hunter --help
```

[PhantomJS](http://phantomjs.org/) is required in your PATH for HTML report screenshots.

Install it like any other Python package:

```console
# Using uv:
uv tool install .

# Using pipx:
pipx install .

# Using pip (not recommend):
python -m venv .venv
.venv/bin/pip install .
ln -s .venv/bin/default-hunter ~/.local/bin/default-hunter
```

## Usage Examples

Below are some common usage examples.

- Scan a single host: `default-hunter 192.168.59.100`
- Scan a subnet for default creds: `default-hunter 192.168.59.0/24`
- Scan using an nmap file `default-hunter subnet.xml`
- Scan a subnet for Tomcat default creds and set the timeout to 5 seconds: `default-hunter -n "Apache Tomcat" --timeout 5 192.168.59.0/24`
- Use [Shodan](https://www.shodan.io/) to populate a targets list and check them for default credentials: `default-hunter --shodan_query "Server: SQ-WEBCAM" --shodan_key keygoeshere -c camera`
- Scan for SSH and known SSH keys: `default-hunter --protocols ssh,ssh_key 192.168.59.0/24`
- Scan a host for SNMP creds using the protocol syntax: `default-hunter snmp://192.168.1.20`

## Contributors

Thanks for code contributions and suggestions.

- @ztgrace
- @AlessandroZ
- @m0ther_
- @GraphX
- @Equinox21_
- https://github.com/ztgrace/changeme/graphs/contributors
