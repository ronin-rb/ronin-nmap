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

require_relative 'converters/json'
require_relative 'converters/csv'

module Ronin
  module Nmap
    #
    # @api private
    #
    module Converters
      # Mapping of formats to converter modules.
      FORMATS = {
        json: JSON,
        csv:  CSV
      }

      #
      # Fetches the converter for the given format.
      #
      # @param [:json, :csv] format
      #
      # @return [Converters::JSON, Converters::CSV]
      #   The converter module.
      #
      # @raise [ArgumentError]
      #   The given format is unsupported.
      #
      def self.[](format)
        FORMATS.fetch(format) do
          raise(ArgumentError,"unsupported format: #{format.inspect}")
        end
      end
    end
  end
end
