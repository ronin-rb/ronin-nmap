# ronin-nmap

[![CI](https://github.com/ronin-rb/ronin-nmap/actions/workflows/ruby.yml/badge.svg)](https://github.com/ronin-rb/ronin-nmap/actions/workflows/ruby.yml)
[![Code Climate](https://codeclimate.com/github/ronin-rb/ronin-nmap.svg)](https://codeclimate.com/github/ronin-rb/ronin-nmap)

* [Website](https://ronin-rb.dev/)
* [Source](https://github.com/ronin-rb/ronin-nmap)
* [Issues](https://github.com/ronin-rb/ronin-nmap/issues)
* [Documentation](https://ronin-rb.dev/docs/ronin-nmap/frames)
* [Discord](https://discord.gg/6WAb3PsVX9) |
  [Twitter](https://twitter.com/ronin_rb) |
  [Mastodon](https://infosec.exchange/@ronin_rb)

## Description

ronin-nmap is a Ruby library for working with nmap. ronin-nmap can parse nmap
XML, convert nmap XML into JSON or CSV, or import nmap XML into the [ronin-db]
database.

## Features

* Supports automating `nmap` using [ruby-nmap].
* Supports parsing and filtering nmap XML.
* Supports converting nmap XML into JSON or CSV.
* Supports importing nmap XML data into the [ronin-db] database.

## Synopsis

Import an nmap XML scan file into [ronin-db]\:

```shell
$ ronin-nmap import scan.xml
```

Perform an nmap scan and import it's results into the [ronin-db]\:

```shell
$ ronin-nmap scan --import -- -sT -sV -p 22,25,80,443
```

Parse and filter an nmap XML scan file:

```shell
$ ronin-nmap parse --hosts-with-port 443 scan.xml
```

Convert an nmap XML scan file to CSV:

```shell
$ ronin-nmap convert scan.xml scan.csv
```

Convert an nmap XML scan file to JSON:

```shell
$ ronin-nmap convert scan.xml scan.json
```

## Requirements

* [Ruby] >= 3.0.0
* [ruby-nmap] ~> 1.0
* [ronin-core] ~> 0.1
* [ronin-db] ~> 0.2

## Install

```shell
$ gem install ronin-nmap
```

### Gemfile

```ruby
gem 'ronin-nmap', '~> 0.1'
```

### gemspec

```ruby
gem.add_dependency 'ronin-nmap', '~> 0.1'
```

## Development

1. [Fork It!](https://github.com/ronin-rb/ronin-nmap/fork)
2. Clone It!
3. `cd ronin-nmap/`
4. `bundle install`
5. `git checkout -b my_feature`
6. Code It!
7. `bundle exec rake spec`
8. `git push origin my_feature`

## License

Copyright (c) 2023 Hal Brodigan (postmodern.mod3@gmail.com)

ronin-nmap is free software: you can redistribute it and/or modify
it under the terms of the GNU Lesser General Public License as published
by the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

ronin-nmap is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public License
along with ronin-nmap.  If not, see <https://www.gnu.org/licenses/>.

[Ruby]: https://www.ruby-lang.org
[ruby-nmap]: https://github.com/postmodern/ruby-nmap#readme
[ronin-core]: https://github.com/ronin-rb/ronin-core#readme
[ronin-db]: https://github.com/ronin-rb/ronin-db#readme
