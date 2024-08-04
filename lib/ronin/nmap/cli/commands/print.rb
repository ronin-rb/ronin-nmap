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

require_relative '../command'
require_relative '../filtering_options'

require 'nmap/xml'

module Ronin
  module Nmap
    class CLI
      module Commands
        #
        # Prints the scanned hosts from nmap XML file(s).
        #
        # ## Usage
        #
        #     ronin-nmap print [options] XML_FILE [...]
        #
        # ## Options
        #
        #         --ip IP                      Filters the targets by IP
        #         --ip-range CIDR              Filter the targets by IP range
        #         --domain DOMAIN              Filters the targets by domain
        #         --with-os OS                 Filters the targets by OS
        #         --with-ports {PORT | PORT1-PORT2},...
        #                                      Filter targets by port numbers
        #         --with-service SERVICE[,...] Filters targets by service
        #         --with-script SCRIPT[,...]   Filters targets with the script
        #         --with-script-output STRING  Filters targets containing the script output
        #         --with-script-regex /REGEX/  Filters targets containing the script output
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        #     XML_FILE ...                     The nmap XML file(s) to parse
        #
        class Print < Command

          usage '[options] XML_FILE [...]'

          include FilteringOptions

          argument :xml_file, required: true,
                              repeats:  true,
                              desc:     'The nmap XML file(s) to parse'

          description 'Prints the scanned hosts from nmap XML file(s)'

          man_page 'ronin-nmap-print.1'

          #
          # Runs the `ronin-nmap print` command.
          #
          # @param [Array<String>] xml_files
          #   The nmap XML files to parse.
          #
          def run(*xml_files)
            xml_files.each do |xml_file|
              xml = ::Nmap::XML.open(xml_file)

              filter_targets(xml).each do |host|
                print_target(host)
                puts
              end
            end
          end

          #
          # Prints the targets.
          #
          # @param [::Nmap::XML::Host] host
          #
          def print_target(host)
            puts "[ #{host} ]"
            puts

            unless host.addresses.empty?
              puts "  Addresses:"
              host.addresses.each do |address|
                puts "    #{address}"
              end
              puts
            end

            unless host.hostnames.empty?
              puts "  Hostnames:"
              host.hostnames.each do |hostname|
                puts "    #{hostname}"
              end
              puts
            end

            host.each_open_port do |port|
              puts "  #{port.number}/#{port.protocol}\t#{port.state}\t#{port.service}"

              unless port.scripts.empty?
                puts

                port.scripts.each_value do |script|
                  puts "    #{script.id}:"

                  script.output.strip.each_line do |line|
                    puts "      #{line}"
                  end

                  puts
                end
              end
            end
          end

        end
      end
    end
  end
end
