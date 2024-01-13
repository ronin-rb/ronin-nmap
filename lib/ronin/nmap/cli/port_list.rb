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

require 'set'

module Ronin
  module Nmap
    class CLI
      #
      # Represents a list of port numbers and port ranges.
      #
      class PortList

        # Port numbers.
        #
        # @return [Array<Integer>]
        attr_reader :numbers

        # Port ranges.
        #
        # @return [Array<Range>]
        attr_reader :ranges

        #
        # Initialize the port list.
        #
        # @param [Array<Integer, Range>] ports
        #   The port numbers and ranges.
        #
        # @raise [ArgumentError]
        #   One of the ports was not an Integer or Range object.
        #
        def initialize(ports)
          @numbers = Set.new
          @ranges  = Set.new

          ports.each do |port|
            case port
            when Integer then @numbers << port
            when Range   then @ranges  << port
            else
              raise(ArgumentError,"port must be an Integer or Range: #{port.inspect}")
            end
          end
        end

        #
        # Parses the port list.
        #
        # @param [String] ports
        #   The port list to parse.
        #
        # @return [PortList]
        #   The port numbers and port ranges.
        #
        def self.parse(ports)
          new(
            ports.split(',').map do |port|
              if port.include?('-')
                start, stop = port.split('-',2)

                Range.new(start.to_i,stop.to_i)
              else
                port.to_i
              end
            end
          )
        end

        #
        # Determines if the port is in the port list.
        #
        # @param [Integer] port
        #
        # @return [Boolean]
        #
        def include?(port)
          @numbers.include?(port) ||
            @ranges.any? { |range| range.include?(port) }
        end

      end
    end
  end
end
