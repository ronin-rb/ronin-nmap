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

require 'ronin/nmap/cli/command'
require 'ronin/nmap/cli/importable'
require 'ronin/nmap/importer'

module Ronin
  module Nmap
    class CLI
      module Commands
        #
        # The `ronin-nmap import` command.
        #
        # ## Usage
        #
        #   ronin-nmap import [options] XML_FILE
        #
        # ## Options
        #
        #         --db NAME                    The database to connect to (Default: default)
        #         --db-uri URI                 The database URI to connect to
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        #     XML_FILE                         The XML file to import
        #
        class Import < Command

          include Importable

          usage '[options] XML_FILE'

          argument :xml_file, required: true,
                              desc:     'The XML file to import'

          man_page 'ronin-nmap-import.1'

          #
          # Runs the `ronin-nmap import` command.
          #
          # @param [String] xml_file
          #   The nmap `.xml` file to import.
          #
          def run(xml_file)
            unless File.file?(xml_file)
              print_error "no such file or directory: #{xml_file}"
              exit(1)
            end

            db_connect
            import_file(xml_file)
          end

        end
      end
    end
  end
end
