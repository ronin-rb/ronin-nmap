require 'spec_helper'
require 'ronin/nmap/cli/commands/completion'
require_relative 'man_page_example'

describe Ronin::Nmap::CLI::Commands::Completion do
  it "must inherit from Ronin::Core::CLI::CompletionCommand" do
    expect(described_class).to be < Ronin::Core::CLI::CompletionCommand
  end

  it "must set completion_file" do
    expect(described_class.completion_file).to eq(
      File.join(Ronin::Nmap::ROOT,'data','completions','ronin-nmap')
    )
  end

  it "must set man_dir" do
    expect(described_class.man_dir).to_not be(nil)
    expect(File.directory?(described_class.man_dir)).to be(true)
  end

  include_examples "man_page"
end
