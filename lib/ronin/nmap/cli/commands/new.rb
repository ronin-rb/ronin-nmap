# frozen_string_literal: true
#
# ronin-nmap - A Ruby library for automating nmap and importing nmap scans.
#
# Copyright (c) 2023-2024 Hal Brodigan (postmodern.mod3@gmail.com)
#
# ronin-nmap is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# ronin-nmap is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with ronin-nmap.  If not, see <https://www.gnu.org/licenses/>.
#

require 'ronin/nmap/cli/command'
require 'ronin/nmap/root'

require 'ronin/core/cli/generator'

module Ronin
  module Nmap
    class CLI
      module Commands
        #
        # Generates a new nmap ruby script.
        #
        # ## Usage
        #
        #     ronin-nmap new [options] FILE
        #
        # ## Options
        #
        #         --parser                     Generate a nmap XML parser script
        #         --scanner                    Generate a nmap scanner script
        #         --printing                   Adds additional printing of the nmap scan data
        #         --import                     Also import the nmap XML scan data
        #         --xml-file XML_FILE          Sets the XML file to write to or parse
        #     -p {PORT | [PORT1]-[PORT2]}[,...],
        #         --ports                      Sets the port range to scan
        #         --target TARGET              Sets the targets to scan (Defaults: ARGV[0])
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        #     FILE                             The path to the new nmap ruby script.
        #
        # ## Examples
        #
        #     ronin-nmap new scanner.rb --ports 22,80,443,8000-9000 --target example.com
        #     ronin-nmap new parser.rb --parser --xml-file path/to/nmap.xml --printing
        #
        class New < Command

          include Core::CLI::Generator

          template_dir File.join(ROOT,'data','templates')

          usage '[options] FILE'

          option :parser, desc: 'Generate a nmap XML parser script' do
            @script_type = :parser
          end

          option :scanner, desc: 'Generate a nmap scanner script' do
            @script_type = :scanner
          end

          option :printing, desc: 'Adds additional printing of the nmap scan data' do
            @features[:printing] = true
          end

          option :import, desc: 'Also import the nmap XML scan data' do
            @features[:import] = true
          end

          option :xml_file, value: {
                              type:  String,
                              usage: 'XML_FILE'
                            },
                            desc: 'Sets the XML file to write to or parse' do |file|
                              @xml_file = file
                            end

          option :ports, short: '-p',
                         value: {
                           type:  String,
                           usage: '{PORT | [PORT1]-[PORT2]}[,...]'
                         },
                         desc: 'Sets the port range to scan' do |ports|
                           @ports = parse_port_range(ports)
                         rescue ArgumentError => error
                           raise(OptionParser::InvalidArgument,error.message)
                         end

          option :target, value: {
                            type:  String,
                            usage: 'TARGET'
                          },
                          desc: 'Sets the targets to scan (Defaults: ARGV[0])' do |target|
                            @targets << target
                          end

          argument :path, desc: 'The path to the new nmap ruby script'

          description 'Generates a new nmap ruby script'

          man_page 'ronin-nmap-new.1'

          examples [
            "scanner.rb --ports 22,80,443,8000-9000 --target example.com",
            "parser.rb --parser --xml-file path/to/nmap.xml --printing"
          ]

          # The script type.
          #
          # @return [:scanner, :parser]
          attr_reader :script_type

          # The optioanl XML file to write to or parse.
          #
          # @return [String, nil]
          attr_reader :xml_file

          # The optional ports to scan.
          #
          # @return [Array<Integer, Range(Integer,Integer)>, "-", nil]
          attr_reader :ports

          # The targets to scan.
          #
          # @return [Array<String>]
          attr_reader :targets

          # Additional features.
          #
          # @return [Hash{Symbol => Boolean}]
          attr_reader :features

          #
          # Initializes the `ronin-nmap new` command.
          #
          # @param [Hash{Symbol => Object}] kwargs
          #   Additional keyword arguments for the command.
          #
          def initialize(**kwargs)
            super(**kwargs)

            @script_type = :scanner
            @targets     = []
            @features    = {}
          end

          #
          # Runs the `ronin-nmap new` command.
          #
          # @param [String] file
          #   The path to the new nmap ruby script.
          #
          def run(file)
            @directory  = File.dirname(file)

            mkdir @directory unless File.directory?(@directory)

            erb "script.rb.erb", file
            chmod '+x', file
          end

          #
          # Parses a port range.
          #
          # @param [String] ports
          #   The port range to parse.
          #
          # @return [Array<Integer, Range(Integer,Integer)>, "-"]
          #   The parsed port range.
          #
          # @raise [ArgumentError]
          #   An invalid port range was given.
          #
          def parse_port_range(ports)
            case ports
            when '-' then '-'
            else
              ports.split(',').map do |port|
                case port
                when /\A\d+-\d+\z/
                  start, stop = port.split('-',2)

                  (start.to_i..stop.to_i)
                when /\A\d+-\z/
                  start = port.chomp('-')

                  (start.to_i..)
                when /\A-\d+\z/
                  stop = port[1..]

                  (..stop.to_i)
                when /\A\d+\z/
                  port.to_i
                else
                  raise(ArgumentError,"invalid port range: #{ports.inspect}")
                end
              end
            end
          end

        end
      end
    end
  end
end
