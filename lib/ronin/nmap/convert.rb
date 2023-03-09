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

require 'ronin/nmap/converters'

require 'nmap/xml'

module Ronin
  module Nmap
    #
    # Handles converting nmap XML into other formats.
    #
    # Supports the following formats:
    #
    # * JSON
    # * CSV
    #
    # @api public
    #
    module Convert
      # Mapping of file extension names to formats.
      #
      # @api private
      FILE_FORMATS = {
        '.json' => :json,
        '.csv'  => :csv
      }

      #
      # Converts an nmap `.xml` scan file into another format.
      #
      # @param [String] src
      #   The input `.xml` file path.
      #
      # @param [String] dest
      #   The output file path.
      #
      # @api public
      #
      def self.convert_file(src,dest, format: infer_format_for(dest))
        xml       = ::Nmap::XML.open(src)
        converter = Converters[format]

        File.open(dest,'w') do |output|
          converter.convert(xml,output)
        end
      end

      #
      # Converts parsed nmap XML into the desired format.
      #
      # @param [::Nmap::XML] xml
      #   The nmap XML to convert.
      #
      # @param [IO, String, nil] output
      #   Optional output to write the converted output to.
      #
      # @param [:json, :csv] format
      #   The desired convert to convert the parsed nmap XML to.
      #
      # @return [String]
      #   The converted nmap XML.
      #
      # @api public
      #
      def self.convert(xml,output=nil, format: )
        Converters[format].convert(xml,output)
      end

      #
      # Infers the output format from the output file's extension.
      #
      # @param [String] output_path
      #   The output file name.
      #
      # @return [:json, :csv]
      #   The conversion format.
      #
      # @raise [ArgumentError]
      #   The format could not be inferred from the path's file extension.
      #
      # @api private
      #
      def self.infer_format_for(path)
        FILE_FORMATS.fetch(File.extname(path)) do
          raise(ArgumentError,"cannot infer output format from path: #{path.inspect}")
        end
      end
    end
  end
end
