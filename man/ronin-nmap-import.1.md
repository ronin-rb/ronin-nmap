# ronin-nmap-import 1 "2023-03-01" Ronin "User Manuals"

## SYNOPSIS

`ronin-nmap import` [*options*] *XML_FILE*

## DESCRIPTION

Imports the nmap XML file data into the Ronin database.

## ARGUMENTS

*XML_FILE*
  The nmap `.xml` file to import.

## OPTIONS

`-h`, `--help`
  Print help information

## ENVIRONMENT

*HOME*
  The user's home directory.

*XDG_CONFIG_HOME*
  Alternate location for the `~/.config` directory.

*XDG_DATA_HOME*
  Alternate location for the `~/.local/share` directory.

## FILES

`~/.local/share/ronin-db/database.sqlite3`
  The default sqlite3 database file.

`~/.config/ronin-db/database.yml`
  Optional database configuration.

## AUTHOR

Postmodern <postmodern.mod3@gmail.com>

