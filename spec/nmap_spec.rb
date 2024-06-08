require 'spec_helper'
require 'ronin/nmap'

RSpec.describe Ronin::Nmap do
  let(:fixtures_dir) { File.join(__dir__,'fixtures') }

  describe '.scan' do
    let(:targets) { '192.168.1.*' }

    context 'if tartets is empty' do
      it 'must raise an ArgumentError' do
        expect {
          subject.scan
        }.to raise_error(ArgumentError, 'must specify at least one target')
      end
    end

    context 'if sudo is not a Hash, true, false, nor nil' do
      it 'must raise an ArgumentError' do
        expect {
          subject.scan(targets, sudo: 'sudo')
        }.to raise_error(ArgumentError, 'sudo keyword must be a Hash, true, false, or nil')
      end
    end

    context 'when nmap command was successfull' do
      let(:expected_output_filename) { %r{#{Ronin::Nmap::CACHE_DIR}\/nmap[^.]+\.xml} }

      before do
        allow(Kernel).to receive(:system).with({}, 'nmap', '-oX', match(expected_output_filename), targets).and_return(true)
      end

      it 'must return a Nmap::XML' do
        expect(subject.scan(targets)).to be_kind_of(Nmap::XML)
      end
    end

    context 'when nmap command fails' do
      before do
        allow(Kernel).to receive(:system).with({}, 'nmap', '-oX', anything, targets).and_return(false)
      end

      it "must raise Ronin::Nmap::ScanFailed with the command arguments" do
        expect {
          subject.scan(targets)
        }.to raise_error(Ronin::Nmap::ScanFailed,/\Anmap scan failed: nmap -oX [^\s]+ [^\s]+\z/)
      end
    end

    context 'when nmap command is not installed' do
      before do
        allow(Kernel).to receive(:system).with({}, 'nmap', '-oX', anything, targets).and_return(nil)
      end

      it "must raise Ronin::Nmap::NotInstalled" do
        expect {
          subject.scan(targets)
        }.to raise_error(Ronin::Nmap::NotInstalled,"the nmap command is not installed")
      end
    end
  end

  describe ".parse" do
    let(:path) { File.join(fixtures_dir,'nmap.xml') }

    it "must return a Nmap::XML object for the given path" do
      xml = subject.parse(path)

      expect(xml).to be_kind_of(Nmap::XML)
      expect(xml.path).to eq(path)
    end
  end
end
