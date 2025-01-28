# ronin-nmap

[![CI](https://github.com/ronin-rb/ronin-nmap/actions/workflows/ruby.yml/badge.svg)](https://github.com/ronin-rb/ronin-nmap/actions/workflows/ruby.yml)
[![Code Climate](https://codeclimate.com/github/ronin-rb/ronin-nmap.svg)](https://codeclimate.com/github/ronin-rb/ronin-nmap)

* [Website](https://ronin-rb.dev/)
* [Source](https://github.com/ronin-rb/ronin-nmap)
* [Issues](https://github.com/ronin-rb/ronin-nmap/issues)
* [Documentation](https://ronin-rb.dev/docs/ronin-nmap/frames)
* [Discord](https://discord.gg/6WAb3PsVX9) |
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

```
Usage: ronin-nmap [options]

Options:
    -V, --version                    Prints the version and exits
    -h, --help                       Print help information

Arguments:
    [COMMAND]                        The command name to run
    [ARGS ...]                       Additional arguments for the command

Commands:
    completion
    convert
    dump
    grep
    help
    import
    new
    print
    scan
```

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

Dump a nmap XML scan file to a list of `IP:PORT` pairs:

```shell
$ ronin-nmap dump --print-ip-ports scan.xml
```

Dump a nmap XML scan file to a list of `HOST:PORT` pairs:

```shell
$ ronin-nmap dump --print-host-ports scan.xml
```

Dump a nmap XML scan file to a list of `http`://` or `https://` URIs:

```shell
$ ronin-nmap dump --print-uris scan.xml
```

Convert an nmap XML scan file to CSV:

```shell
$ ronin-nmap convert scan.xml scan.csv
```

Convert an nmap XML scan file to JSON:

```shell
$ ronin-nmap convert scan.xml scan.json
```

Generate a new nmap scanner Ruby script:

```shell
$ ronin-nmap new scanner.rb --target example.com --ports 22,80,443,8000-9000
```

Generate a new nmap XML parser script:

```shell
$ ronin-nmap new parser.rb --parser --xml-file path/to/nmap.xml --printing
```

## Examples

Performing an `nmap` scan and returning the parsed nmap XML data:

```ruby
require 'ronin/nmap'

xml = Ronin::Nmap.scan(syn_scan: true, ports: [80, 443], targets: '192.168.1.*')
# => #<Nmap::XML: ...>

xml = Ronin::Nmap.scan do |nmap|
  nmap.syn_scan = true
  nmap.ports    = [80, 443]
  nmap.targets  = '192.168.1.*'
end
# => #<Nmap::XML: ...>
```

Accessesing the nmap XML scan data:

```ruby
xml.hosts
# => [#<Nmap::XML::Host: 192.168.1.1>, ...]

host = xml.host
# => #<Nmap::XML::Host: scanme.nmap.org>

xml.host.open_ports
# => [#<Nmap::XML::Port: 22>,
#     #<Nmap::XML::Port: 80>,
#     #<Nmap::XML::Port: 9929>,
#     #<Nmap::XML::Port: 31337>,
#     #<Nmap::XML::Port: 123>]

port = xml.host.open_ports.first
# => #<Nmap::XML::Port: 22>

port.state
# => :open

port.protocol
# => :tcp

port.service
# => #<Nmap::XML::Service:0x00007f5614e68248 @node=#<Nokogiri::XML::Element:0x7ada0 name="service" attribute_nodes=[#<Nokogiri::XML::Attr:0x7aecc name="name" value="ssh">, #<Nokogiri::XML::Attr:0x7b05c name="extrainfo" value="protocol 2.0">, #<Nokogiri::XML::Attr:0x7b1ec name="servicefp" value="SF-Port22-TCP:V=6.45%I=7%D=4/17%Time=55316FE1%P=x86_64-redhat-linux-gnu%r(NULL,29,\"SSH-2\\.0-OpenSSH_6\\.6\\.1p1\\x20Ubuntu-2ubuntu2\\r\\n\");">, #<Nokogiri::XML::Attr:0x7b37c name="method" value="probed">, #<Nokogiri::XML::Attr:0x7b50c name="conf" value="10">]>>

port.scripts
# => {"ssh-hostkey"=>...,
#     "ssh2-enum-algos"=>...}
```

Printing the parsed nmap XML data:

```ruby
xml.each_host do |host|
  puts "[ #{host.ip} ]"

  host.each_port do |port|
    puts "  #{port.number}/#{port.protocol}\t#{port.state}\t#{port.service}"

    port.scripts.each do |id,script|
      puts "    [ #{id} ]"

      script.output.each_line { |line| puts "      #{line}" }
    end
  end
end
```

## Requirements

* [Ruby] >= 3.0.0
* [nmap] >= 5.00
* [ruby-nmap] ~> 1.0
* [ronin-core] ~> 0.2
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
4. `./scripts/setup`
5. `git checkout -b my_feature`
6. Code It!
7. `bundle exec rake spec`
8. `git push origin my_feature`

## License

Copyright (c) 2023-2025 Hal Brodigan (postmodern.mod3@gmail.com)

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
[nmap]: http://www.insecure.org/
[ruby-nmap]: https://github.com/postmodern/ruby-nmap#readme
[ronin-core]: https://github.com/ronin-rb/ronin-core#readme
[ronin-db]: https://github.com/ronin-rb/ronin-db#readme
