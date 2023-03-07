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

require 'ronin/db'
require 'nmap/xml'

module Ronin
  module Nmap
    #
    # Handles importing a parsed nmap XML file into [ronin-db].
    #
    # [ronin-db]: https://github.com/ronin-rb/ronin-db#readme
    #
    # ## Examples
    #
    #     require 'ronin/db'
    #     require 'ronin/nmap/importer'
    #
    #     Ronin::DB.connect
    #     Ronin::Nmap::Importer.import_file('scan.xml') do |record|
    #       puts "Imported #{record.inspect}!"
    #     end
    #
    # @api private
    #
    module Importer
      #
      # Parses the nmap XML file and imports it's contents into the database.
      #
      # @param [String] path
      #   The path to the nmap XML file to parse and import.
      #
      # @yield [imported]
      #   If a block is given, it will be passed the imported database records.
      #
      # @yieldparam [Ronin::DB::IPAddress,
      #              Ronin::DB::MACAddress,
      #              Ronin::DB::HostName,
      #              Ronin::DB::Port,
      #              Ronin::DB::Service,
      #              Ronin::DB::OpenPort] imported
      #   An imported IP address, MAC address, host name, or open port.
      #
      # @return [Array<Ronin::DB::IPAddress>]
      #
      def self.import_file(path,&block)
        import(::Nmap::XML.open(path),&block)
      end

      #
      # Imports the parsed nmap XML into the database.
      #
      # @param [::Nmap::XML] xml
      #   The parsed nmap XML document.
      #
      # @yield [imported]
      #   If a block is given, it will be passed the imported database records.
      #
      # @yieldparam [Ronin::DB::IPAddress,
      #              Ronin::DB::MACAddress,
      #              Ronin::DB::HostName,
      #              Ronin::DB::Port,
      #              Ronin::DB::Service,
      #              Ronin::DB::OpenPort] imported
      #   An imported IP address, MAC address, host name, or open port.
      #
      # @return [Array<Ronin::DB::IPAddress>]
      #
      def self.import(xml,&block)
        imported_ip_addresses = []

        xml.each_up_host do |host|
          imported_ip_addresses.concat(import_host(host,&block))
        end

        return imported_ip_addresses
      end

      #
      # Imports an nmap host into the database.
      #
      # @yield [imported]
      #   If a block is given, it will be passed the imported database records.
      #
      # @yieldparam [Ronin::DB::IPAddress,
      #              Ronin::DB::MACAddress,
      #              Ronin::DB::HostName,
      #              Ronin::DB::Port,
      #              Ronin::DB::Service,
      #              Ronin::DB::OpenPort] imported
      #   An imported IP address, MAC address, host name, or open port.
      #
      # @param [::Nmap::XML::Host] host
      #
      # @return [Array<Ronin::DB::IPAddress>]
      #
      def self.import_host(host,&block)
        imported_ip_addresses, = import_addresses(host,&block)
        imported_hostnames     = import_hostnames(host,&block)

        # associate any imported host names with the imported IP addresses
        imported_hostnames.each do |imported_hostname|
          imported_ip_addresses.each do |imported_ip_address|
            DB::HostNameIPAddress.transaction do
              DB::HostNameIPAddress.find_or_create_by(
                host_name:  imported_hostname,
                ip_address: imported_ip_address
              )
            end
          end
        end

        host.each_open_port do |port|
          imported_port, imported_service = import_port(port,&block)

          # associate the imported port with the imported IP addresses
          imported_ip_addresses.each do |imported_ip_address|
            import_open_port(imported_ip_address,
                             imported_port,
                             imported_service,
                             &block)
          end
        end

        return imported_ip_addresses
      end

      #
      # Creates or updates an open port association between the imported IP
      # address, imported port, and imported service.
      #
      # @param [Ronin::DB::IPAddress] imported_ip_address
      #
      # @param [Ronin::DB::Port] imported_port
      #
      # @param [Ronin::DB::Service] imported_service
      #
      # @return [Ronin::DB::OpenPort]
      #
      def self.import_open_port(imported_ip_address,
                                imported_port,
                                imported_service)
        imported_open_port = DB::OpenPort.transaction do
                               DB::OpenPort.find_or_create_by(
                                 ip_address: imported_ip_address,
                                 port:       imported_port,
                                 service:    imported_service
                               )
                             end

        yield imported_open_port if block_given?
        return imported_open_port
      end

      #
      # Imports the host names for the scanned nmap host.
      #
      # @param [::Nmap::XML::Host] host
      #
      # @yield [imported]
      #   If a block is given, it will be passed the imported database records.
      #
      # @yieldparam [Ronin::DB::HostName] imported
      #   An imported host name.
      #
      # @return [Array<Ronin::DB::HostName>]
      #
      def self.import_hostnames(host)
        host.each_hostname.map do |hostname|
          imported_host_name = import_hostname(hostname)
          yield imported_host_name if block_given?
          imported_host_name
        end
      end

      #
      # Imports a hostname into the database.
      #
      # @param [::Nmap::XML::HostName] hostname
      #   The nmap XML hostname object to import.
      #
      # @return [Ronin::DB::HostName]
      #   The imported host name.
      #
      def self.import_hostname(hostname)
        DB::HostName.transaction do
          DB::HostName.find_or_import(hostname.name)
        end
      end

      #
      # Imports the addresses for a host.
      #
      # @param [::Nmap::XML::Host] host
      #
      # @yield [imported]
      #   If a block is given, it will be passed the imported database records.
      #
      # @yieldparam [Ronin::DB::IPAddress, Ronin::DB::MACAddress] imported
      #   An imported IP address or MAC address.
      #
      # @return [(Array<Ronin::DB::IPAddress>, Array<Ronin::DB::MACAddress>)]
      #   The imported IP addresses and MAC addresses.
      #
      def self.import_addresses(host)
        imported_ip_addresses  = []
        imported_mac_addresses = []

        host.each_address do |address|
          case (imported_address = import_address(address))
          when DB::IPAddress
            imported_ip_addresses << imported_address
          when DB::MACAddress
            imported_mac_addresses << imported_address
          end

          yield imported_address if block_given?
        end

        # associate any imported MAC addresses with the imported IP addresses
        imported_mac_addresses.each do |imported_mac_address|
          imported_ip_addresses.each do |imported_ip_address|
            DB::IPAddressMACAddress.transaction do
              DB::IPAddressMACAddress.find_or_create_by(
                mac_address: imported_mac_address,
                ip_address:  imported_ip_address
              )
            end
          end
        end

        return imported_ip_addresses, imported_mac_addresses
      end

      #
      # Imports and IP address or a MAC address into the database.
      #
      # @param [::Nmap::XML::Address] address
      #   The nmap XML address object.
      #
      # @return [Ronin::DB::IPAddress, Ronin::DB::MACAddress]
      #   The imported IP address or MAC address.
      #
      def self.import_address(address)
        case address.type
        when :ipv4, :ipv6 then import_ip_address(address)
        when :mac         then import_mac_address(address)
        end
      end

      # Mapping of nmap XML IP address types to IP versions.
      IP_VERSIONS = {
        ipv4: 4,
        ipv6: 6
      }

      #
      # Imports an IP address into the database.
      #
      # @param [::Nmap::XML::Address] address
      #   The nmap XML IP address object.
      #
      # @return [Ronin::DB::IPAddress]
      #   The imported IP address.
      #
      def self.import_ip_address(address)
        DB::IPAddress.transaction do
          DB::IPAddress.find_or_create_by(
            version: IP_VERSIONS.fetch(address.type),
            address: address.addr
          )
        end
      end

      #
      # Imports an MAC address into the database.
      #
      # @param [::Nmap::XML::Address] address
      #   The nmap XML MAC address object.
      #
      # @return [Ronin::DB::MACAddress]
      #   The imported MAC address.
      #
      def self.import_mac_address(address)
        DB::MACAddress.transaction do
          DB::MACAddress.find_or_import(address.addr)
        end
      end

      #
      # Import an nmap port.
      #
      # @param [::Nmap::XML::Port] port
      #   The nmap port.
      #
      # @yield [imported]
      #   If a block is given, it will be passed the imported database records.
      #
      # @yieldparam [Ronin::DB::Port, Ronin::DB::Service] imported
      #   An imported port or service.
      #
      # @return [Ronin::DB::Port, (Ronin::DB::Port, Ronin::DB::Service)]
      #   The imported port and optionally the imported service.
      #
      def self.import_port(port)
        imported_port = DB::Port.transaction do
                          DB::Port.find_or_create_by(
                            protocol: port.protocol,
                            number:   port.number
                          )
                        end

        imported_service = if (service = port.service)
                             DB::Service.transaction do
                               DB::Service.find_or_create_by(
                                 name: service.name
                               )
                             end
                           end

        if block_given?
          yield imported_port
          yield imported_service if imported_service
        end

        return imported_port, imported_service
      end
    end
  end
end
