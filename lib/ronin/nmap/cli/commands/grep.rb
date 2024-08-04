# frozen_string_literal: true
#
# ronin-nmap - A Ruby library for automating nmap and importing nmap scans.
#
# Copyright (c) 2023 Hal Brodigan (postmodern.mod3@gmail.com)
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

require 'command_kit/colors'
require 'command_kit/printing/indent'
require 'nmap/xml'

module Ronin
  module Nmap
    class CLI
      module Commands
        #
        # Parses and searches nmap XML file(s) for the pattern.
        #
        # ## Usage
        #
        #     ronin-nmap grep [options] PATTERN XML_FILE [...]
        #
        # ## Options
        #
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        class Grep < Command

          include CommandKit::Colors
          include CommandKit::Printing::Indent

          usage '[options] PATTERN XML_FILE [...]'

          argument :pattern, required: true,
                             desc:     'The pattern to search for'

          argument :xml_file, required: true,
                              repeats:  true,
                              desc:     'The nmap XML file to search'

          description 'Parses and searches nmap XML file(s) for the pattern'

          man_page 'ronin-nmap-grep.1'

          #
          # Runs the `ronin-nmap grep` command.
          #
          # @param [String] pattern
          #   The pattern to search for.
          #
          # @param [Array<String>] xml_files
          #   The nmap `.xml` file(s) to grep.
          #
          def run(pattern,*xml_files)
            xml_files.each do |xml_file|
              unless File.file?(xml_file)
                print_error "no such file or directory: #{xml_file}"
                next
              end

              xml   = ::Nmap::XML.open(xml_file)
              hosts = grep_xml(xml,pattern)

              highlight_hosts(hosts,pattern)
            end
          end

          #
          # Searches the parsed nmap XML for the text pattern.
          #
          # @param [::Nmap::XML] xml
          #   The parsed nmap XML object.
          #
          # @param [String] pattern
          #   The text pattern to search for.
          #
          # @return [Enumerator::Lazy<::Nmap::XML::Host>]
          #   The nmap XML host objects that contain the text pattern.
          #
          def grep_xml(xml,pattern)
            xml.each_up_host.lazy.filter do |host|
              match_host(host,pattern)
            end
          end

          #
          # Determines if the nmap XML host object contains the text pattern.
          #
          # @param [::Nmap::XML::Host] host
          #   The nmap XML host object to search.
          #
          # @param [String] pattern
          #   The text pattern to search for.
          #
          # @return [Boolean]
          #
          def match_host(host,pattern)
            hostnames   = host.each_hostname
            open_ports  = host.each_open_port
            host_script = host.host_script

            hostnames.any? { |hostname| match_hostname(hostname,pattern) } ||
              open_ports.any? { |port| match_port(port,pattern) } ||
              (host_script && match_scripts(host_script,pattern))
          end

          #
          # Determines if the nmap XML hostname object contains the text
          # pattern.
          #
          # @param [::Nmap::XML::Hostname] hostname
          #   The nmap XML hostname object to search.
          #
          # @param [String] pattern
          #   The text pattern to search for.
          #
          # @return [Boolean]
          #
          def match_hostname(hostname,pattern)
            hostname.name.match(pattern)
          end

          #
          # Determines if the nmap XML port object contains the text pattern.
          #
          # @param [::Nmap::XML::Port] port
          #   The nmap XML port object to search.
          #
          # @param [String] pattern
          #   The text pattern to search for.
          #
          # @return [Boolean]
          #
          def match_port(port,pattern)
            match_scripts(port,pattern) || if (service = port.service)
                                             match_service(service,pattern)
                                           end
          end

          #
          # Determines if the nmap XML service object contains the text pattern.
          #
          # @param [::Nmap::XML::Service] service
          #   The nmap XML service object to search.
          #
          # @param [String] pattern
          #   The text pattern to search for.
          #
          # @return [Boolean]
          #
          def match_service(service,pattern)
            product    = service.product
            version    = service.version
            extra_info = service.extra_info

            service.name.match(pattern) ||
              (product && product.match(pattern)) ||
              (version && version.match(pattern)) ||
              (extra_info && extra_info.match(pattern))
          end

          #
          # Determines if the nmap XML scripts object contains the text pattern.
          #
          # @param [::Nmap::XML::Scripts] has_scripts
          #   The nmap XML object that includes `Nmap::XML::Scripts`.
          #
          # @param [String] pattern
          #   The text pattern to search for.
          #
          # @return [Boolean]
          #
          def match_scripts(has_scripts,pattern)
            has_scripts.scripts.any? do |id,script|
              match_script(script,pattern)
            end
          end

          #
          # Determines if the nmap XML script object contains the text pattern.
          #
          # @param [::Nmap::XML::Script] script
          #   The nmap XML script object to search.
          #
          # @param [String] pattern
          #   The text pattern to search for.
          #
          # @return [Boolean]
          #
          def match_script(script,pattern)
            script.id.match(pattern) || script.output.match(pattern)
          end

          #
          # Prints the nmap hosts with the pattern highlighted in the output.
          #
          # @param [Enumerator::Lazy<::Nmap::XML::Host>] hosts
          #   The nmap hosts to print.
          #
          # @param [String] pattern
          #   The pattern to highlight in the output.
          #
          def highlight_hosts(hosts,pattern)
            hosts.each do |host|
              highlight_host(host,pattern)
              puts
            end
          end

          #
          # Prints the nmap host with the pattern highlighted in the output.
          #
          # @param [::Nmap::XML::Host] host
          #   The nmap host to print.
          #
          # @param [String] pattern
          #   The text pattern to highlight in the output.
          #
          def highlight_host(host,pattern)
            addresses = host.addresses
            hostnames = host.hostnames

            unless hostnames.empty?
              puts "[ #{addresses.first} / #{highlight(hostnames.first,pattern)} ]"
            else
              puts "[ #{addresses.first} ]"
            end
            puts

            indent do
              if addresses.length > 1
                puts "[ addresses ]"
                puts

                indent do
                  addresses.each do |address|
                    puts address
                  end
                end
                puts
              end

              if hostnames.length > 1
                puts "[ hostnames ]"
                puts

                indent do
                  hostnames.each do |hostname|
                    puts highlight(hostname,pattern)
                  end
                end
                puts
              end

              if (host_script = host.host_script)
                puts "[ host scripts ]"
                puts

                indent do
                  highlight_scripts(host_script)
                end
              end

              puts "[ ports ]"
              puts

              indent do
                host.each_open_port do |port|
                  highlight_port(port,pattern)
                end
              end
            end
          end

          #
          # Prints the nmap port with the pattern highlighted in the output.
          #
          # @param [::Nmap::XML::Port] port
          #   The nmap XML port object to print.
          #
          # @param [String] pattern
          #   The text pattern to highlight in the output.
          #
          def highlight_port(port,pattern)
            port_line = "#{port.number}/#{port.protocol}\t#{port.state}"

            if (service = port.service)
              port_line << "\t#{highlight(service,pattern)}"

              if (extra_info = service.extra_info)
                port_line << " #{highlight(extra_info,pattern)}"
              end
            end

            puts port_line

            unless port.scripts.empty?
              puts

              indent do
                highlight_scripts(port,pattern)
              end
            end
          end

          #
          # Prints the nmap scripts with the pattern highlighted in the output.
          #
          # @param [::Nmap::XML::Scripts] has_scripts
          #   The nmap XML object that has scripts.
          #
          # @param [String] pattern
          #   The text pattern to highlight in the output.
          #
          def highlight_scripts(has_scripts,pattern)
            has_scripts.scripts.each_value do |script|
              highlight_script(script,pattern)
              puts
            end
          end

          #
          # Prints the nmap script with the pattern highlighted in the output.
          #
          # @param [::Nmap::XML::Script] script
          #   The nmap XML script object to print.
          #
          # @param [String] pattern
          #   The text pattern to highlight in the output.
          #
          def highlight_script(script,pattern)
            puts "#{highlight(script.id,pattern)}:"

            indent do
              script.output.strip.each_line do |line|
                puts highlight(line,pattern)
              end
            end
          end

          #
          # Highlights the pattern in the text.
          #
          # @param [String] text
          #   The text to modify.
          #
          # @param [String] pattern
          #   The pattern to highlight.
          #
          # @return [String]
          #   The modified text.
          #
          def highlight(text,pattern)
            text.to_s.gsub(pattern,colors.bold(colors.red(pattern)))
          end

        end
      end
    end
  end
end
