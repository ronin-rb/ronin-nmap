# ronin-nmap 1 "2024-01-01" Ronin "User Manuals"

## NAME

ronin-nmap - A CLI for working with nmap

## SYNOPSIS

`ronin-nmap` [*options*] [*COMMAND* [...]]

## DESCRIPTION

`ronin-nmap` provides various commands for automating `nmap`, parsing
XML output files, and importing scan data into the database.

Runs a `ronin-nmap` *COMMAND*.

## ARGUMENTS

*COMMAND*
: The `ronin-nmap` command to execute.

## OPTIONS

`-h`, `--help`
: Print help information

## COMMANDS

*convert*
: Converts an nmap XML file to JSON or CSV.

*dump*
: Dumps the targets from an nmap XML file.

*import*
: Imports an nmap XML file into ronin-db.

*scan*
: Runs nmap and outputs data as JSON or CSV or imports into the database.

## AUTHOR

Postmodern <postmodern.mod3@gmail.com>

## SEE ALSO

[ronin-nmap-convert](ronin-nmap-convert.1.md) [ronin-nmap-dump](ronin-nmap-dump.1.md) [ronin-nmap-import](ronin-nmap-import.1.md) [ronin-nmap-scan](ronin-nmap-scan.1.md)
