# frozen_string_literal: true
#
# ronin-nmap - A Ruby library for automating nmap and importing nmap scans.
#
# Copyright (c) 2023-2025 Hal Brodigan (postmodern.mod3@gmail.com)
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
require 'set'

module Ronin
  module Nmap
    class CLI
      module Commands
        #
        # Dumps the scanned ports from nmap XML file(s).
        #
        # ## Usage
        #
        #     ronin-nmap dump [options] XML_FILE [...]
        #
        # ## Options
        #
        #         --print-ips                  Print all IP addresses
        #         --print-hosts                Print all hostnames
        #         --print-ip-ports             Print IP:PORT pairs. (Default)
        #         --print-host-ports           Print HOST:PORT pairs
        #         --print-uris                 Print URIs
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
        #         -p, --ports {PORT | PORT1-PORT2},...
        #                                      Filter targets by port numbers
        #         --services SERVICE[,...]     Filters targets by service
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        #     XML_FILE ...                     The nmap XML file(s) to parse
        #
        # ## Examples
        #
        #     ronin-nmap dump --print-ip-ports scan.xml
        #     ronin-nmap dump --print-ip-ports --ports 22,80,443 scan.xml
        #     ronin-nmap dump --print-host-ports scan.xml
        #     ronin-nmap dump --print-hosts --with-port 22 scan.xml
        #     ronin-nmap dump --print-uris scan.xml
        #
        class Dump < Command

          usage '[options] XML_FILE [...]'

          option :print_ips, desc: 'Print all IP addresses' do
            @mode = :ips
          end

          option :print_hosts, desc: 'Print all hostnames' do
            @mode = :hostnames
          end

          option :print_ip_ports, desc: 'Print IP:PORT pairs. (Default)' do
            @mode = :ip_ports
          end

          option :print_host_ports, desc: 'Print HOST:PORT pairs' do
            @mode = :host_ports
          end

          option :print_uris, desc: 'Print URIs' do
            @mode = :uris
          end

          include FilteringOptions

          option :ports, short: '-p',
                         value: {
                           type: /\A(?:\d+|\d+-\d+)(?:,(?:\d+|\d+-\d+))*\z/,
                           usage: '{PORT | PORT1-PORT2},...'
                         },
                         desc: 'Filter targets by port numbers' do |ports|
                           @ports << PortList.parse(ports)
                         end

          option :services, value: {
                              type: /\A(?:[a-z]+[a-z0-9_+-]*)(?:,[a-z]+[a-z0-9_+-]*)*\z/,
                              usage: 'SERVICE[,...]'
                            },
                            desc: 'Filters targets by service' do |services|
                              @services.merge(services.split(','))
                            end

          argument :xml_file, required: true,
                              repeats:  true,
                              desc:     'The nmap XML file(s) to parse'

          examples [
            '--print-ip-ports scan.xml',
            '--print-ip-ports --ports 22,80,443 scan.xml',
            '--print-host-ports scan.xml',
            '--print-hosts --with-port 22 scan.xml',
            '--print-uris scan.xml'
          ]

          description 'Dumps the scanned ports from nmap XML file(s)'

          man_page 'ronin-nmap-dump.1'

          #
          # Initializes the command.
          #
          # @param [Hash{Symbol => Object}] kwargs
          #   Additional keywords for the command.
          #
          def initialize(**kwargs)
            super(**kwargs)

            @mode = :ip_ports

            @ports    = Set.new
            @services = Set.new
          end

          #
          # Runs the `ronin-nmap dump` command.
          #
          # @param [Array<String>] xml_files
          #   The nmap XML files to parse.
          #
          def run(*xml_files)
            xml_files.each do |xml_file|
              xml = ::Nmap::XML.open(xml_file)

              filter_targets(xml).each do |host|
                print_target(host)
              end
            end
          end

          #
          # Prints the targets.
          #
          # @param [::Nmap::XML::Host] host
          #
          def print_target(host)
            case @mode
            when :ips        then print_ip(host)
            when :hostnames  then print_hostname(host)
            when :ip_ports   then print_ip_ports(host)
            when :host_ports then print_host_ports(host)
            when :uris       then print_uris(host)
            end
          end

          #
          # Prints the IPs for the target.
          #
          # @param [::Nmap::XML::Host] host
          #
          def print_ip(host)
            puts host.address
          end

          #
          # Prints the host names for the target.
          #
          # @param [::Nmap::XML::Host] host
          #
          def print_hostnames(host)
            if (hostname = host.hostname)
              puts hostname
            end
          end

          #
          # Prints the `IP:PORT` pair for the target.
          #
          # @param [::Nmap::XML::Host] host
          #
          def print_ip_ports(host)
            filter_ports(host).each do |port|
              puts "#{host.address}:#{port.number}"
            end
          end

          #
          # Prints the `HOST:PORT` pair for the target.
          #
          # @param [::Nmap::XML::Host] host
          #
          def print_host_ports(host)
            filter_ports(host).each do |port|
              if (hostname = host.hostname)
                puts "#{hostname}:#{port.number}"
              end
            end
          end

          #
          # Prints the URIs for the target.
          #
          # @param [::Nmap::XML::Host] host
          #
          def print_uris(host)
            filter_ports(host).each do |port|
              if (port.service && port.service.name == 'http') ||
                 (port.number == 80)
                puts URI::HTTP.build(
                  host: host.to_s,
                  port: port.number
                )
              elsif (port.service && port.service.name == 'https') ||
                    (port.number == 443)
                puts URI::HTTPS.build(
                  host: host.to_s,
                  port: port.number
                )
              end
            end
          end

          #
          # @param [::Nmap::XML::Host] host
          #
          # @return [Enumerator::Lazy]
          #
          def filter_ports(host)
            ports = host.each_open_port.lazy

            unless @ports.empty?
              ports = filter_ports_by_number(ports)
            end

            unless @services.empty?
              ports = filter_ports_by_service(ports)
            end

            return ports
          end

          #
          # @param [Enumerator::Lazy] ports
          #
          # @return [Enumerator::Lazy]
          #
          def filter_ports_by_number(ports)
            ports.filter do |port|
              @ports.any? do |port_list|
                port_list.include?(port.number)
              end
            end
          end

          #
          # @param [Enumerator::Lazy] ports
          #
          # @return [Enumerator::Lazy]
          #
          def filter_ports_by_service(ports)
            ports.filter do |port|
              if (service = port.service)
                @services.include?(service.name)
              end
            end
          end

        end
      end
    end
  end
end
