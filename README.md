# go_dos
Simplistic denial of service testing tool written in GO

## Compilation

Use `go1.11` or higher.

Compile:

```shell

go build -ldflags="-s -w" .

```

## Usage

To see cli help write in terminal:

```shell

./go_dos -h

```

Help:

```shell

NAME:
   go_dos - Denial of service cli testing tool

USAGE:
   go_dos [global options] command [command options] [arguments...]

COMMANDS:
   help, h  Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --file FILE, -f FILE        Load targets from FILE
   --rounds value, -r value    Number of rounds per target per single time span (default: 100)
   --timeout value, -t value   Single request timeout in milliseconds (default: 1000)
   --stats value, -s value     Stats update time step in seconds (default: 5)
   --pace timeout, -p timeout  Time between attacks in milliseconds, should be grater then timeout (default: 2000)
   --help, -h                  show help (default: false)


```

### Important

Please use it responsibly and test only on servers you have legal rights to run against.
