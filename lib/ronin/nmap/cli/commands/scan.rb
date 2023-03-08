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
require 'ronin/nmap/convert'
require 'ronin/core/cli/logging'

require 'tempfile'
require 'set'

module Ronin
  module Nmap
    class CLI
      module Commands
        #
        # The `ronin-nmap scan` command.
        #
        # ## Usage
        #
        #     ronin-nmap scan [options] -- [nmap_options]
        #
        # ## Options
        #
        #         --db NAME                    The database to connect to (Default: default)
        #         --db-uri URI                 The database URI to connect to
        #         --sudo                       Runs the nmap command under sudo
        #     -o, --output FILE                The output file
        #     -F, --output-format xml|json|csv The output format
        #         --import                     Imports the scan results into the database
        #     -h, --help                       Print help information
        #
        # ## Arguments
        #
        #     nmap_options ...                 Additional arguments for nmap
        #
        # ## Examples
        #
        #     ronin-nmap scan -o scan.json -- -sV 192.168.1.1
        #     ronin-nmap scan --import -- -sV 192.168.1.1
        #
        class Scan < Command

          include Importable
          include Core::CLI::Logging

          usage '[options] -- [nmap_options]'

          option :sudo, desc: 'Runs the nmap command under sudo'

          option :output, short: '-o',
                          value: {
                            type:  String,
                            usage: 'FILE'
                          },
                          desc: 'The output file'

          option :output_format, short: '-F',
                                 value: {
                                   type: [:xml, :json, :csv]
                                 },
                                 desc: 'The output format'

          option :import, desc: 'Imports the scan results into the database'

          argument :nmap_args, required: true,
                               repeats:  true,
                               usage:    'nmap_options',
                               desc:     'Additional arguments for nmap'

          description 'Runs nmap and outputs data as JSON or CSV or imports into the database'

          examples [
            '-o scan.json -- -sV 192.168.1.1',
            '--import -- -sV 192.168.1.1'
          ]

          man_page 'ronin-nmap-scan.1'

          #
          # Runs the `ronin-nmap scan` command.
          #
          # @param [Array<String>] nmap_args
          def run(*nmap_args)
            output        = options[:output]
            output_format = options.fetch(:output_format) do
                              infer_output_format(output)
                            end

            if output && output_format.nil?
              print_error "cannot infer the output format of the output file (#{output.inspect}), please specify --output-format"
              exit(1)
            end

            tempfile = Tempfile.new(['ronin-nmap', '.xml'])

            log_info "Running nmap #{nmap_args.join(' ')} ..."

            unless run_nmap(*nmap_args, output: tempfile.path)
              print_error "failed to run nmap"
              exit(1)
            end

            if output
              log_info "Saving #{output_format.upcase} output to #{output} ..."
              save_output(tempfile.path,output, format: output_format)
            end

            if options[:import]
              log_info "Importing scan XML ..."
              import_scan(tempfile.path)
            end
          end

          # `nmap` options that require `sudo`.
          SUDO_OPTIONS = Set[
            '-sS',
            '-sA',
            '-sW',
            '-sM',
            '-sN',
            '-sF',
            '-sX',
            '--scanflags',
            '-sO',
            '-O',
            '--traceroute'
          ]

          #
          # Runs the `nmap` command.
          #
          # @param [Array<String>] nmap_args
          #   Additional arguments for `nmap`.
          #
          # @param [String] output
          #   The `.xml` output file to save the scan data to.
          #
          # @return [Boolean, nil]
          #   Indicates whether the `nmap` command was successful.
          #
          def run_nmap(*nmap_args, output: )
            sudo = options.fetch(:sudo) do
              nmap_args.any? do |arg|
                SUDO_OPTIONS.include?(arg)
              end
            end

            nmap_command = ['nmap', *nmap_args, '-oX', output]
            nmap_command.unshift('sudo') if sudo

            return system(*nmap_command)
          end

          #
          # Saves the nmap scan results to an output file in the given format.
          #
          # @param [String] path
          #   The path to the nmap `.xml` file.
          #
          # @param [String] output
          #   The path to the desired output file.
          #
          # @param [:xml, :json, :csv] format
          #   The desired output format.
          #
          def save_output(path,output, format: )
            case format
            when :xml
              # copy the file if the output format is xml
              FileUtils.cp(path,output)
            else
              # the format has been explicitly specified
              Nmap::Convert.convert_file(path,output, format: format)
            end
          end

          #
          # Imports a nmap `.xml` scan file.
          #
          # @param [String] path
          #   The path to the `.xml` file.
          #
          def import_scan(path)
            require 'ronin/db'

            db_connect
            import_file(path)
          end

          # Supported output formats.
          OUTPUT_FORMATS = {
            '.xml'  => :xml,
            '.json' => :json,
            '.csv'  => :csv
          }

          #
          # Infers the output format from the given path's file extension.
          #
          # @param [String] path
          #   The path to infer the output format from.
          #
          # @return [:xml, :json, :csv, nil]
          #   The output format or `nil` if the path's file extension is
          #   unknown.
          #
          def infer_output_format(path)
            OUTPUT_FORMATS[File.extname(path)]
          end

        end
      end
    end
  end
end
