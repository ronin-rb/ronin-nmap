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

require 'nmap/xml'
require 'csv'

module Ronin
  module Nmap
    module Converters
      #
      # Handles converting nmap XML into CSV.
      #
      module CSV
        #
        # Converts an nmap `.xml` file to a `.csv` file.
        #
        # @param [String] input_file
        #   The input `.xml` file path.
        #
        # @param [String] output_file
        #   The output file path.
        #
        # @api public
        #
        def self.convert_file(input_file,output_file)
          xml = ::Nmap::XML.open(input_file)

          File.open(output_file,'w') do |output|
            xml_to_csv(xml,output)
          end
        end

        #
        # Converts parsed nmap XML into CSV.
        #
        # @param [::Nmap::XML] xml
        #
        # @param [String, IO] output
        #   The optional output to write the CSV to.
        #
        # @return [String, IO]
        #   The CSV output.
        #
        # @api public
        #
        def self.convert(xml,output=String.new)
          xml_to_csv(xml,output)
        end

        #
        # Converts parsed XML to CSV.
        #
        # @param [::Nmap::XML] xml
        #   The parsed nmap XML to convert to CSV.
        #
        # @param [String, IO] output
        #   The optional output to write the CSV to.
        #
        # @return [String, IO]
        #   The CSV output.
        #
        def self.xml_to_csv(xml,output=String.new)
          xml_to_rows(xml) do |row|
            output << ::CSV.generate_line(row)
          end

          return output
        end

        # CSV rows header.
        HEADER = %w[host.start_time host.end_time host.status host.ip port.protocol port.number port.status port.reason port.reason_ttl service.name service.ssl service.protocol service.produce service.version service.extra_info service.hostnmae service.os_type service.device_type service.fingerprint_method service.fingerprint service.confidence]

        #
        # Converts parsed nmap XML to a series of rows.
        #
        # @param [::Nmap::XML] xml
        #   The parsed nmap XML.
        #
        # @yield [row]
        #   The given block will be passed each row.
        #
        # @yieldparam [Array] row
        #   A row to be converted to CSV.
        #
        def self.xml_to_rows(xml)
          yield HEADER

          xml.each_host do |host|
            each_host_rows(host) do |*row|
              yield row
            end
          end
        end

        #
        # Converts a nmap XML host into a series of rows.
        #
        # @param [::Nmap::XML] host
        #   The nmap XML host object.
        #
        # @yield [row]
        #   The given block will be passed each row.
        #
        # @yieldparam [Array] row
        #   A row to be converted to CSV.
        #
        def self.each_host_rows(host)
          host_row = [
            host.start_time,
            host.end_time,
            host.status,
            host.ip
          ]

          host.each_port do |port|
            yield(*host_row, *port_to_row(port))
          end
        end

        #
        # Converts a nmap XML port into a row.
        #
        # @param [::Nmap::Port] port
        #   The nmap XML port object.
        #
        # @return [Array]
        #   The row of values that represents the port.
        #
        def self.port_to_row(port)
          row = [
            port.protocol,
            port.number,
            port.state,
            port.reason,
            port.reason_ttl
          ]

          if (service = port.service)
            row.concat(service_to_row(service))
          end

          return row
        end

        #
        # Converts a nmap XML service into a series of rows.
        #
        # @param [::Nmap::Service] service
        #   The nmap XML service object.
        #
        # @return [Array]
        #   The row of values that represents the service.
        #
        def self.service_to_row(service)
          [
            service.name,
            service.ssl?,
            service.protocol,
            service.product,
            service.version,
            service.extra_info,
            service.hostname,
            service.os_type,
            service.device_type,
            service.fingerprint_method,
            service.fingerprint,
            service.confidence
          ]
        end
      end
    end
  end
end
