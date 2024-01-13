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

require 'ronin/nmap/cli/command'
require 'ronin/nmap/converter'

module Ronin
  module Nmap
    class CLI
      module Commands
        #
        # Converts an nmap XML file to JSON or CSV.
        #
        # ## Usage
        #
        #     ronin-nmap convert [--format json|csv] XML_FILE [OUTPUT_FILE]
        #
        # ## Option
        #
        #     -F, --format json|csv            The desired output format
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        #     XML_FILE                         The input XML file to parse
        #     OUTPUT_FILE                      The output file
        #
        class Convert < Command

          usage '[--format json|csv] XML_FILE [OUTPUT_FILE]'

          option :format, short: '-F',
                          value: {
                            type:     [:json, :csv],
                            required: true
                          },
                          desc: 'The desired output format'

          argument :xml_file, required: true,
                              desc:     'The input XML file to parse'

          argument :output_file, required: false,
                                 desc:     'The output file'

          description "Converts an nmap XML file to JSON or CSV"

          man_page 'ronin-nmap-convert.1'

          # The desired output format.
          #
          # @return [:json, :csv, nil]
          attr_reader :format

          #
          # Runs the `ronin-nmap convert` command.
          #
          # @param [String] xml_file
          #   The XML input file to parse.
          #
          # @param [String] output_file
          #   The output file to write to.
          #
          def run(xml_file,output_file=nil)
            unless File.file?(xml_file)
              print_error "no such file or directory: #{xml_file}"
              exit(-1)
            end

            if output_file
              if (format = options[:format])
                Converter.convert_file(xml_file,output_file, format: format)
              else
                Converter.convert_file(xml_file,output_file)
              end
            else
              unless (format = options[:format])
                print_error "must specify a --format if no output file is given"
                exit(-1)
              end

              xml = ::Nmap::XML.open(xml_file)

              Converter.convert(xml,stdout, format: format)
            end
          end

        end
      end
    end
  end
end
