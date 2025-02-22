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

require_relative '../root'

require 'ronin/core/cli/command'

module Ronin
  module Nmap
    class CLI
      #
      # Base class for all other `ronin-nmap` commands.
      #
      class Command < Core::CLI::Command

        man_dir File.join(ROOT,'man')

        bug_report_url 'https://github.com/ronin-rb/ronin-nmap/issues/new'

      end
    end
  end
end
