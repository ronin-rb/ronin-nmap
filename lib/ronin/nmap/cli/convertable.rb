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

require 'ronin/nmap/converters/json'
require 'ronin/nmap/converters/csv'

require 'nmap/xml'

module Ronin
  module Nmap
    class CLI
      #
      # Mixin module which adds the ability to convert nmap XML data into
      # JSON or CSV.
      #
      module Convertable
        # Mapping of formats to converter modules.
        FORMAT_CONVERTERS = {
          json: Converters::JSON,
          csv:  Converters::CSV
        }

        #
        # Looks up the converter module for the given format.
        #
        # @param [:json, :csv] format
        #   The desired format.
        #
        # @return [Converters::JSON, Converters::CSV]
        #   The converter module.
        #
        # @raise [ArgumentError]
        #   The format was not `:json` or `:csv`.
        #
        def converter_for(format)
          FORMAT_CONVERTERS.fetch(format) do
            raise(ArgumentError,"unsupported conversion format: #{format.inspect}")
          end
        end

        #
        # Converts the nmap `.xml` file into another file format.
        #
        # @param [String] xml_file
        #   The path to the nmap `.xml` file.
        #
        # @param [String] output
        #   The output path.
        #
        # @param [:json, :csv] format
        #   The desired format for the output file.
        #
        # @raise [ArgumentError]
        #   The format was not `:json` or `:csv`.
        #
        def convert_file(xml_file,output, format: infer_format_from(output))
          converter_for(format).convert_file(xml_file,output)
        end

        #
        # Converts the nmap `.xml` file into another format.
        #
        # @param [String] xml_file
        #   The path to the nmap `.xml` file.
        #
        # @param [IO] output
        #   The output stream to write to.
        #
        # @param [:json, :csv] format
        #   The desired format for the output file.
        #
        # @raise [ArgumentError]
        #   The format was not `:json` or `:csv`.
        #
        def convert(xml_file,output, format: )
          xml = ::Nmap::XML.open(xml_file)

          converter_for(format).convert(xml,output)
        end

        # Mapping of output file extensions to output formats.
        FILE_FORMATS = {
          '.json' => :json,
          '.csv'  => :csv
        }

        #
        # Infers the output format from the output file's extension.
        #
        # @param [String] output_path
        #   The output file name.
        #
        # @return [:json, :csv]
        #   The conversion format.
        #
        def infer_format_from(output_path)
          FORMAT_EXTS.fetch(File.extname(output_path))
        end
      end
    end
  end
end
