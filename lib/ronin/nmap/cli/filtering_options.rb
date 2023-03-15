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

require 'ronin/nmap/cli/port_list'

module Ronin
  module Nmap
    class CLI
      #
      # Mixin which adds nmap target filtering options to commands.
      #
      module FilteringOptions
        #
        # Adds filtering options to the command class including
        # {FilteringOptions}.
        #
        # @param [Class<Command>] command
        #   The command class including {FilteringOptions}.
        #
        def self.included(command)
          command.option :ip, value: {
                                type:  String,
                                usage: 'IP'
                              },
                              desc: 'Filters the targets by IP' do |ip|
                                @with_ips << ip
                              end

          command.option :ip_range, value: {
                                      type:  String,
                                      usage: 'CIDR'
                                    },
                                    desc: 'Filter the targets by IP range' do |ip_range|
                                      @with_ip_ranges << IPAddr.new(ip_range)
                                    end

          command.option :domain, value: {
                                    type:  String,
                                    usage: 'DOMAIN'
                                  },
                                  desc: 'Filters the targets by domain' do |domain|
                                    @with_domains << domain
                                  end

          command.option :with_os, value: {
                                     type:  String,
                                     usage: 'OS'
                                   },
                                   desc: 'Filters the targets by OS' do |os|
                                     @with_oses << os.to_sym
                                   end

          command.option :with_ports, value: {
                                        type: /\A(?:\d+|\d+-\d+)(?:,(?:\d+|\d+-\d+))*\z/,
                                        usage: '{PORT | PORT1-PORT2},...'
                                      },
                                      desc: 'Filter targets by port numbers' do |ports|
                                        @with_ports << PortList.parse(ports)
                                      end

          command.option :with_service, value: {
                                          type:  /\A[a-z]+[a-z0-9_+-]*\z/,
                                          usage: 'SERVICE[,...]'
                                        },
                                        desc: 'Filters targets by service' do |service|
                                          @with_services << service
                                        end

          command.option :with_script, value: {
                                         type:  /\A[a-z][a-z0-9-]*\z/,
                                         usage: 'SCRIPT[,...]'
                                       },
                                       desc: 'Filters targets with the script' do |script|
                                         @with_scripts << script
                                       end

          command.option :with_script_output, value: {
                                                type:  String,
                                                usage: 'STRING'
                                              },
                                              desc: 'Filters targets containing the script output' do |string|
                                                @with_script_output << string
                                              end

          command.option :with_script_regex, value: {
                                               type:  Regexp,
                                               usage: '/REGEX/'
                                             },
                                             desc: 'Filters targets containing the script output' do |regexp|
                                               @with_script_output << regexp
                                             end
        end

        # @return [Set<String>]
        attr_reader :with_ips

        # @return [Set<IPAddr>]
        attr_reader :with_ip_ranges

        # @return [Set<String>]
        attr_reader :with_domains

        # @return [Set<String>]
        attr_reader :with_oses

        # @return [Set<PortList>]
        attr_reader :with_ports

        # @return [Set<String>]
        attr_reader :with_services

        # @return [Set<String>]
        attr_reader :with_scripts

        # @return [Set<String, Regexp>]
        attr_reader :with_script_output

        #
        # Initializes the command.
        #
        # @param [Hash{Symbol => String}] kwargs
        #   Additional keywords for the command.
        #
        def initialize(**kwargs)
          super(**kwargs)

          @with_ips           = Set.new
          @with_ip_ranges     = Set.new
          @with_domains       = Set.new
          @with_oses          = Set.new
          @with_ports         = Set.new
          @with_services      = Set.new
          @with_scripts       = Set.new
          @with_script_output = Set.new
        end

        #
        # Filters the nmap scan targets.
        #
        # @param [::Nmap::XML] xml
        #   The parsed nmap xml data to filter.
        #
        # @return [Enumerator::Lazy]
        #   A lazy enumerator of the filtered targets.
        #
        def filter_targets(xml)
          targets = xml.each_up_host.lazy

          unless @with_ips.empty?
            targets = filter_targets_by_ip(targets)
          end

          unless @with_ip_ranges.empty?
            targets = filter_targets_by_ip_range(targets)
          end

          unless @with_domains.empty?
            targets = filter_targets_by_domain(targets)
          end

          unless @with_oses.empty?
            targets = filter_targets_by_os(targets)
          end

          unless @with_ports.empty?
            targets = filter_targets_by_port(targets)
          end

          unless @with_services.empty?
            targets = filter_targets_by_scripts(targets)
          end

          unless @with_script_output.empty?
            targets = filter_targets_by_script_output(targets)
          end

          return targets
        end

        #
        # Filters the targets by IP address.
        #
        # @param [Enumerator::Lazy] targets
        #   The targets to filter.
        #
        # @param [String] ip
        #   The IP address to filter by.
        #
        # @return [Enumerator::Lazy]
        #   A lazy enumerator of the filtered targets.
        #
        def filter_targets_by_ip(targets)
          targets.filter do |host|
            @with_ips.include?(host.address)
          end
        end

        #
        # Filters the targets by an IP rangeo.
        #
        # @param [Enumerator::Lazy] targets
        #   The targets to filter.
        #
        # @return [Enumerator::Lazy]
        #   A lazy enumerator of the filtered targets.
        #
        def filter_targets_by_ip_range(target)
          targets.filter do |host|
            @with_ip_ranges.any? do |ip_range|
              ip_range.include?(host.address)
            end
          end
        end

        #
        # Filters the targets by a domain.
        #
        # @param [Enumerator::Lazy] targets
        #   The targets to filter.
        #
        # @return [Enumerator::Lazy]
        #   A lazy enumerator of the filtered targets.
        #
        def filter_targets_by_domain(targets)
          regexp = Regexp.union(
            @with_domains.map { |domain|
              escaped_domain = Regexp.escape(domain)

              /\.#{escaped_domain}\z|\A#{escaped_domain}\z/
            }
          )

          targets.filter do |host|
            if (hostname = host.hostname)
              hostname.name =~ regexp
            end
          end
        end

        #
        # Filters the targets by OS.
        #
        # @param [Enumerator::Lazy] targets
        #   The targets to filter.
        #
        # @return [Enumerator::Lazy]
        #   A lazy enumerator of the filtered targets.
        #
        def filter_targets_by_os(targets)
          targets.filter do |host|
            if (os = host.os)
              os.each_class.any? do |os_class|
                @with_oses.include?(os_class.family)
              end
            end
          end
        end

        #
        # Filters the targets by port number.
        #
        # @param [Enumerator::Lazy] targets
        #   The targets to filter.
        #
        # @return [Enumerator::Lazy]
        #   A lazy enumerator of the filtered targets.
        #
        def filter_targets_by_port(targets)
          targets.filter do |host|
            host.each_open_port.any? do |port|
              @with_ports.any? do |port_list|
                port_list.include?(port.number)
              end
            end
          end
        end

        #
        # Filters the targets by service name.
        #
        # @param [Enumerator::Lazy] targets
        #   The targets to filter.
        #
        # @return [Enumerator::Lazy]
        #   A lazy enumerator of the filtered targets.
        #
        def filter_targets_by_service(targets)
          targets.filter do |host|
            host.each_open_port.any? do |port|
              if (service = port.service)
                @with_services.include?(service.name)
              end
            end
          end
        end

        #
        # Filters the targets by script IDs.
        #
        # @param [Enumerator::Lazy] targets
        #   The targets to filter.
        #
        # @return [Enumerator::Lazy]
        #   A lazy enumerator of the filtered targets.
        #
        def filter_targets_by_script(targets)
          targets.filter do |host|
            host.each_open_port.any? do |port|
              @with_scripts.intersect?(port.scripts.keys)
            end
          end
        end

        #
        # Filters the targets by script output.
        #
        # @param [Enumerator::Lazy] targets
        #   The targets to filter.
        #
        # @return [Enumerator::Lazy]
        #   A lazy enumerator of the filtered targets.
        #
        def filter_targets_by_script_output(targets)
          regexp = Regexp.union(@with_script_output.to_a)

          targets.filter do |host|
            host.each_open_port.any? do |port|
              port.scripts.each_value.any? do |script|
                script.output =~ regexp
              end
            end
          end
        end
      end
    end
  end
end
