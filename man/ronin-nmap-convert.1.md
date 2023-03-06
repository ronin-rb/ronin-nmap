# ronin-nmap-convert 1 "2023-03-01" Ronin "User Manuals"

## SYNOPSIS

`ronin-nmap convert` [`--format` `json`\|`csv`] *XML_FILE* [*OUTPUT_FILE*]

## DESCRIPTION

Converts an nmap `.xml` file to JSON or CSV.

## ARGUMENTS

*XML_FILE*
  The nmap `.xml` file to import.

*OUTPUT_FILE*
  The optional output file to write to.

## OPTIONS

`-F`, `--format` `json`|`csv`
  Sets the output conversion format to JSON or CSV. If the option is not given,
  the output conversion format Will be inferred from the *OUTPUT_FILE* file
  extension.

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

