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

require 'ronin/nmap/exceptions'
require 'ronin/nmap/importer'
require 'ronin/core/home'
require 'nmap/command'
require 'nmap/xml'

require 'tempfile'
require 'fileutils'

module Ronin
  #
  # Namespace for the `ronin-nmap` library.
  #
  module Nmap
    # The `~/.cache/ronin-nmap` cache directory.
    #
    # @api private
    CACHE_DIR = Core::Home.cache_dir('ronin-nmap')

    #
    # Runs `nmap` and parses the XML output.
    #
    # @param [Array<#to_s>] targets
    #   The targets to scan.
    #
    # @param [Hash{Symbol => Object}, Boolean, nil] sudo
    #   Controls whether the `nmap` command should be ran under `sudo`.
    #   If the `sudo:` keyword argument is not given, then `nmap` will
    #   automatically be ran under `sudo` if `sync_scan`, `ack_scan`,
    #   `window_scan`, `maimon_scan`, `null_scan`, `fin_scan`, `xmas_scan`,
    #   `scan_flags`, `os_fingerprint`, or `traceroute` are enabled.
    #
    # @option sudo [Boolean] :askpass
    #   Enables the `--askpass` `sudo` option.
    #
    # @option sudo [Boolean] :background
    #   Enables the `--background` `sudo` option
    #
    # @option sudo [Boolean] :bell
    #   Enables the `--bell` `sudo` option
    #
    # @option sudo [Integer] :close_from
    #   Enables the `--close-from=...` `sudo` option
    #
    # @option sudo [String] :chdir
    #   Enables the `--chdir=...` `sudo` option
    #
    # @option sudo [String] :preserve_env
    #   Enables the `--preseve-env=...` `sudo` option
    #
    # @option sudo [String, Boolean] :group
    #   Enables the `--preseve-env=...` `sudo` option
    #
    # @option sudo [Boolean] :set_home
    #   Enables the `--set-home` `sudo` option
    #
    # @option sudo [String] :host
    #   Enables the `--host=...` `sudo` option
    #
    # @option sudo [Boolean] :login
    #   Enables the `--login` `sudo` option
    #
    # @option sudo [Boolean] :remove_timestamp
    #   Enables the `--remove-timestamp` `sudo` option
    #
    # @option sudo [Boolean] :reset_timestamp
    #   Enables the `--reset-timestamp` `sudo` option
    #
    # @option sudo [Boolean] :non_interactive
    #   Enables the `--non-interactive` `sudo` option
    #
    # @option sudo [Boolean] :preserve_groups
    #   Enables the `--preserve-groups` `sudo` option
    #
    # @option sudo [String] :prompt
    #   Enables the `--prompt=...` `sudo` option
    #
    # @option sudo [String] :chroot
    #   Enables the `--chroot=...` `sudo` option
    #
    # @option sudo [String] :role
    #   Enables the `--role=...` `sudo` option
    #
    # @option sudo [Boolean] :stdin
    #   Enables the `--stdin` `sudo` option
    #
    # @option sudo [Boolean] :shell
    #   Enables the `--shell` `sudo` option
    #
    # @option sudo [String] :type
    #   Enables the `--type=...` `sudo` option
    #
    # @option sudo [Integer] :command_timeout
    #   Enables the `--command-timeout=...` `sudo` option
    #
    # @option sudo [String] :other_user
    #   Enables the `--other-user=...` `sudo` option
    #
    # @option sudo [String] :user
    #   Enables the `--user=...` `sudo` option
    #
    # @param [Hash{Symbol => Object}] kwargs
    #   Additional keyword arguments for `nmap`.
    #
    # @yield [nmap]
    #   If a block is given, it will be passed the new `nmap` command object
    #   for additional configuration.
    #
    # @yieldparam [::Nmap::Command] nmap
    #   The `nmap` command object.
    #
    # @return [::Nmap::XML]
    #   If the `nmap` command was successful, the parsed nmap XML data will be
    #   returned.
    #
    # @raise [NotInstalled]
    #   The `nmap` command was not installed.
    #
    # @raise [ScanFailed]
    #   The `nmap` scan failed.
    #
    # @example
    #   xml = Nmap.scan('192.168.1.*', syn_scan: true, ports: [80, 443])
    #   # => #<Nmap::XML: ...>
    #   xml.up_hosts
    #   # => [#<Nmap::XML::Host: 192.168.1.1>, ...]
    #
    # @see https://rubydoc.info/gems/ruby-nmap/Nmap/Command
    # @see https://rubydoc.info/gems/ruby-nmap/Nmap/XML
    #
    # @api public
    #
    def self.scan(*targets, sudo: nil, **kwargs,&block)
      if targets.empty?
        raise(ArgumentError,"must specify at least one target")
      end

      nmap = ::Nmap::Command.new(targets: targets, **kwargs,&block)

      unless nmap.output_xml
        FileUtils.mkdir_p(CACHE_DIR)
        tempfile = Tempfile.new(['nmap','.xml'], CACHE_DIR)

        nmap.output_xml = tempfile.path
      end

      sudo ||= nmap.syn_scan ||
               nmap.ack_scan ||
               nmap.window_scan ||
               nmap.maimon_scan ||
               nmap.null_scan ||
               nmap.fin_scan ||
               nmap.xmas_scan ||
               nmap.scan_flags ||
               nmap.ip_scan ||
               nmap.os_fingerprint ||
               nmap.traceroute

      # run the nmap command
      status = case sudo
               when Hash       then nmap.sudo_command(**sudo)
               when true       then nmap.sudo_command
               when false, nil then nmap.run_command
               else
                 raise(ArgumentError,"sudo keyword must be a Hash, true, false, or nil")
               end

      # if the command was successful, return the parsed XML, otherwise raises
      # an exception.
      case status
      when nil
        raise(NotInstalled,"the nmap command is not installed")
      when false
        raise(ScanFailed,"nmap scan failed: #{nmap.command_argv.join(' ')}")
      else
        ::Nmap::XML.open(nmap.output_xml)
      end
    end

    #
    # Parses a nmap XML file.
    #
    # @param [String] path
    #   The path to the nmap XML file.
    #
    # @return [::Nmap::XML]
    #   The parsed nmap XML file.
    #
    # @see https://rubydoc.info/gems/ruby-nmap/Nmap/XML
    #
    # @api public
    #
    def self.parse(path)
      ::Nmap::XML.open(path)
    end
  end
end
