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

require 'json'

module Ronin
  module Nmap
    module Converters
      #
      # Handles converting nmap XML into JSON.
      #
      module JSON
        #
        # Converts parsed nmap XML to JSON.
        #
        # @param [::Nmap::XML] xml
        #   The parsed nmap XML.
        #
        # @param [IO, nil] output
        #   Optional output stream to write the JSON to.
        #
        # @return [String]
        #   The raw JSON.
        #
        # @api public
        #
        def self.convert(xml,output=nil)
          xml_to_json(xml,output)
        end

        #
        # Converts parsed nmap XML to JSON.
        #
        # @param [::Nmap::XML] xml
        #   The parsed nmap XML.
        #
        # @param [IO, nil] output
        #   Optional output stream to write the JSON to.
        #
        # @return [String]
        #   The raw JSON.
        #
        def self.xml_to_json(xml,output=nil)
          ::JSON.dump(xml_as_json(xml),output)
        end

        #
        # Converts the parsed nmap XML into a JSON representation.
        #
        # @param [::Nmap::XML] xml
        #   The parsed nmap XML.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.xml_as_json(xml)
          hash = {
            scanner:   scanner_as_json(xml.scanner),
            version:   xml.version,
            scan_info: xml.scan_info.map(&method(:scan_info_as_json)),
            run_stats: xml.each_run_stat.map(&method(:run_stat_as_json)),
            verbose:   xml.verbose,
            debugging: xml.debugging,
            tasks:     xml.each_task.map(&method(:scan_task_as_json))
          }

          if xml.prescript
            hash[:prescript] = prescript_as_json(xml.prescript)
          end

          if xml.postscript
            hash[:postscript] = postscript_as_json(xml.postscript)
          end

          hash[:hosts] = xml.each_host.map(&method(:host_as_json))
          return hash
        end

        #
        # Converts a `Nmap::XML::Scanner` object into JSON representation.
        #
        # @param [::Nmap::XML::Scanner] scanner
        #   The `Nmap::XML::Scanner` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.scanner_as_json(scanner)
          {
            name:    scanner.name,
            version: scanner.version,
            args:    scanner.arguments,
            start:   scanner.start_time
          }
        end

        #
        # Converts a `Nmap::XML::ScanInfo` object into JSON representation.
        #
        # @param [::Nmap::XML::ScanInfo] scan_info
        #   The `Nmap::XML::ScanInfo` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.scan_info_as_json(scan_info)
          {
            type:     scan_info.type,
            protocol: scan_info.protocol,
            services: scan_info.services.map do |ports|
                        case ports
                        when Range then "#{ports.begin}-#{ports.end}"
                        else            ports
                        end
                      end
          }
        end

        #
        # Converts the `Nmap::XML::RunStat` object into JSON representation.
        #
        # @param [::Nmap::XML::RunStat] run_stat
        #   The `Nmap::XML::RunStat` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.run_stat_as_json(run_stat)
          {
            end_time:    run_stat.end_time,
            elapsed:     run_stat.elapsed,
            summary:     run_stat.summary,
            exit_status: run_stat.exit_status
          }
        end

        #
        # Converts the `Nmap::XML::ScanTask` object into JSON representation.
        #
        # @param [::Nmap::XML::ScanTask] scan_task
        #   The `Nmap::XML::ScanTask` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.scan_task_as_json(scan_task)
          {
            name:       scan_task.name,
            start_time: scan_task.start_time,
            end_time:   scan_task.end_time,
            extra_info: scan_task.extra_info
          }
        end

        #
        # Converts the `Nmap::XML::Host` object into JSON representation.
        #
        # @param [::Nmap::XML::Host] host
        #   The `Nmap::XML::Host` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.host_as_json(host)
          hash = {
            start_time: host.start_time,
            end_time:   host.end_time,
            status:     status_as_json(host.status),
            addresses:  host.each_address.map(&method(:address_as_json)),
            hostnames:  host.each_hostname.map(&method(:hostname_as_json))
          }

          if (os = host.os)
            hash[:os] = os_as_json(os)
          end

          if (uptime = host.uptime)
            hash[:uptime] = uptime_as_json(uptime)
          end

          if (tcp_sequence = host.tcp_sequence)
            hash[:tcp_sequence] = tcp_sequence_as_json(tcp_sequence)
          end

          if (ip_id_sequence = host.ip_id_sequence)
            hash[:ip_id_sequence] = ip_id_sequence_as_json(ip_id_sequence)
          end

          if (tcp_ts_sequence = host.tcp_ts_sequence)
            hash[:tcp_ts_sequence] = tcp_ts_sequence_as_json(tcp_ts_sequence)
          end

          hash[:ports] = host.each_port.map(&method(:port_as_json))

          if (host_script = host.host_script)
            hash[:host_script] = host_script_as_json(host_script)
          end

          if (traceroute = host.traceroute)
            hash[:traceroute] = traceroute_as_json(traceroute)
          end

          return hash
        end

        #
        # Converts the `Nmap::XML::Status` object into JSON representation.
        #
        # @param [::Nmap::XML::Status] status
        #   The `Nmap::XML::Status` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.status_as_json(status)
          {
            state:      status.state,
            reason:     status.reason,
            reason_ttl: status.reason_ttl
          }
        end

        #
        # Converts the `Nmap::XML::Address` object into JSON representation.
        #
        # @param [::Nmap::XML::Address] address
        #   The `Nmap::XML::Address` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.address_as_json(address)
          {
            type:   address.type,
            addr:   address.addr,
            vendor: address.vendor
          }
        end

        #
        # Converts the `Nmap::XML::Hostname` object into JSON representation.
        #
        # @param [::Nmap::XML::Hostname] hostname
        #   The `Nmap::XML::Hostname` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.hostname_as_json(hostname)
          {
            type: hostname.type,
            name: hostname.name
          }
        end

        #
        # Converts the `Nmap::XML::OS` object into JSON representation.
        #
        # @param [::Nmap::XML::OS] os
        #   The `Nmap::XML::OS` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.os_as_json(os)
          hash = {
            os_classes: os.each_class.map(&method(:os_class_as_json)),
            os_matches: os.each_match.map(&method(:os_match_as_json)),
            ports_used: os.ports_used
          }

          if (fingerprint = os.fingerprint)
            hash[:fingerprint] = fingerprint
          end

          return hash
        end

        #
        # Converts the `Nmap::XML::OSClass` object into JSON representation.
        #
        # @param [::Nmap::XML::OSClass] os_class
        #   The `Nmap::XML::OSClass` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.os_class_as_json(os_class)
          hash = {}

          if (type = os_class.type)
            hash[:type] = type
          end

          hash[:vendor] = os_class.vendor
          hash[:family] = os_class.family

          if (gen = os_class.gen)
            hash[:gen] = gen
          end

          hash[:accuracy] = os_class.accuracy
          return hash
        end

        #
        # Converts the `Nmap::XML::OSMatch` object into JSON representation.
        #
        # @param [::Nmap::XML::OSMatch] os_match
        #   The `Nmap::XML::OSMatch` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.os_match_as_json(os_match)
          {
            name:     os_match.name,
            accuracy: os_match.accuracy
          }
        end

        #
        # Converts the ``Nmap::XML::Uptime object into JSON representation.
        #
        # @param [::Nmap::XML::Uptime] uptime
        #   The `Nmap::XML::Uptime` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.uptime_as_json(uptime)
          {
            seconds:   uptime.seconds,
            last_boot: uptime.last_boot
          }
        end

        #
        # Converts the `Nmap::XML::TcpSequence` object into JSON representation.
        #
        # @param [::Nmap::XML::TcpSequence] tcp_sequence
        #   The `Nmap::XML::TcpSequence` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.tcp_sequence_as_json(tcp_sequence)
          hash = sequence_as_json(tcp_sequence)

          hash[:index]      = tcp_sequence.index
          hash[:difficulty] = tcp_sequence.difficulty

          return hash
        end

        #
        # Converts the `Nmap::XML::IpIdSequence` object into JSON
        # representation.
        #
        # @param [::Nmap::XML::IpIdSequence] ip_id_sequence
        #   The `Nmap::XML::IpIdSequence` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.ip_id_sequence_as_json(ip_id_sequence)
          sequence_as_json(ip_id_sequence)
        end

        #
        # Converts the `Nmap::XML::TcpTsSequence` object into JSON
        # representation.
        #
        # @param [::Nmap::XML::TcpTsSequence] tcp_ts_sequence
        #   The `Nmap::XML::TcpTsSequence` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.tcp_ts_sequence_as_json(tcp_ts_sequence)
          sequence_as_json(tcp_ts_sequence)
        end

        #
        # Converts the `Nmap::XML::Sequence` object into JSON representation.
        #
        # @param [::Nmap::XML::Sequence] sequence
        #   The `Nmap::XML::Sequence` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.sequence_as_json(sequence)
          {
            description: sequence.description,
            values:      sequence.values
          }
        end

        #
        # Converts the `Nmap::XML::Port` object into JSON representation.
        #
        # @param [::Nmap::XML::Port] port
        #   The `Nmap::XML::Port` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.port_as_json(port)
          hash = {
            protocol:   port.protocol,
            number:     port.number,
            state:      port.state,
            reason:     port.reason,
            reason_ttl: port.reason_ttl
          }

          if (service = port.service)
            hash[:service] = service_as_json(service)
          end

          hash[:scripts] = scripts_as_json(port)
          return hash
        end

        #
        # Converts the `Nmap::XML::Serivce` object into JSON representation.
        #
        # @param [::Nmap::XML::Serivce] service
        #   The `Nmap::XML::Serivce` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.service_as_json(service)
          {
            name:               service.name,
            ssl:                service.ssl?,
            protocol:           service.protocol,
            product:            service.product,
            version:            service.version,
            extra_info:         service.extra_info,
            hostname:           service.hostname,
            os_type:            service.os_type,
            device_type:        service.device_type,
            fingerprint_method: service.fingerprint_method,
            fingerprint:        service.fingerprint,
            confidence:         service.confidence
          }
        end

        #
        # Converts the `Nmap::XML::HostScript` object into JSON representation.
        #
        # @param [::Nmap::XML::HostScript] host_script
        #   The `Nmap::XML::HostScript` object.
        #
        # @return [Hash{String => Object}]
        #   The JSON representation.
        #
        def self.host_script_as_json(host_script)
          scripts_as_json(host_script)
        end

        #
        # Converts the object, which includes `Nmap::XML::Scripts` module, into
        # JSON representation.
        #
        # @param [Object<::Nmap::XML::Scripts>] has_scripts
        #   The object including the `Nmap::XML::Scripts` module.
        #
        # @return [Hash{String => Object}]
        #   The JSON representation.
        #
        def self.scripts_as_json(has_scripts)
          hash = {}

          has_scripts.scripts.each do |id,script|
            hash[id] = script_as_json(script)
          end

          return hash
        end

        #
        # Converts the `Nmap::XML::Script` object into JSON representation.
        #
        # @param [::Nmap::XML::Script] script
        #   The `Nmap::XML::Script` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.script_as_json(script)
          hash = {
            id:     script.id,
            output: script.output
          }

          if (data = script.data)
            hash[:data] = data
          end

          return hash
        end

        #
        # Converts the `Nmap::XML::Traceroute` object into JSON representation.
        #
        # @param [::Nmap::XML::Traceroute] traceroute
        #   The `Nmap::XML::Traceroute` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.traceroute_as_json(traceroute)
          hash = {}

          if (port = traceroute.port)
            hash[:port] = port
          end

          if (protocol = traceroute.protocol)
            hash[:protocol] = protocol
          end

          hash[:traceroute] = traceroute.map(&method(:hop_as_json))
          return hash
        end

        #
        # Converts an `Nmap::XML::Hop` object into JSON representation.
        #
        # @param [::Nmap::XML::Hop] hop
        #   The `Nmap::XML::Hop` object.
        #
        # @return [Hash{Symbol => Object}]
        #   The JSON representation.
        #
        def self.hop_as_json(hop)
          {
            addr: hop.addr,
            host: hop.host,
            ttl:  hop.ttl,
            rtt:  hop.rtt
          }
        end
      end
    end
  end
end
