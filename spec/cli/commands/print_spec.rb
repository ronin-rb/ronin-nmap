require 'spec_helper'
require 'ronin/nmap/cli/commands/print'
require_relative 'man_page_example'

describe Ronin::Nmap::CLI::Commands::Print do
  include_examples "man_page"

  describe "#run"

  describe "#print_target"
end
