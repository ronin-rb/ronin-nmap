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

require 'ronin/nmap/importer'
require 'ronin/core/cli/logging'

module Ronin
  module Nmap
    class CLI
      #
      # Mixin module which adds the ability to import nmap XML into the
      # [ronin-db] database.
      #
      # [ronin-db]: https://github.com/ronin-rb/ronin-db#readme
      #
      module Importable
        include Core::CLI::Logging

        #
        # Imports an nmap `.xml` file into the [ronin-db] database.
        #
        # [ronin-db]: https://github.com/ronin-rb/ronin-db#readme
        #
        # @param [String] xml_file
        #   The path to the nmap `.xml` file to import.
        #
        def import_file(xml_file)
          Importer.import_file(xml_file) do |record|
            if (type = record_type(record))
              log_info "Imported #{type}: #{record}"
            end
          end
        end

        #
        # Maps a record to a human readable display name.
        #
        # @param [Ronin::DB::IPAddress,
        #         Ronin::DB::MACAddress,
        #         Ronin::DB::HostName,
        #         Ronin::DB::Port,
        #         Ronin::DB::Service,
        #         Ronin::DB::OpenPort] record
        #
        # @return [String, nil]
        #   The human readable type or `nil` if the record model is unknown.
        #
        def record_type(record)
          case record
          when Ronin::DB::HostName   then 'host'
          when Ronin::DB::IPAddress  then 'IP'
          when Ronin::DB::MACAddress then 'MAC'
          when Ronin::DB::Port       then 'port'
          when Ronin::DB::Service    then 'service'
          when Ronin::DB::OpenPort   then 'open port'
          end
        end
      end
    end
  end
end
