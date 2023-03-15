require 'spec_helper'
require 'ronin/nmap/cli/port_list'

describe Ronin::Nmap::CLI::PortList do
  let(:port1)  { 80 }
  let(:port2)  { 443 }
  let(:range1) { 1..20 }
  let(:range2) { 8000..8080 }
  let(:ports)  { [port1, range1, port2, range2] }

  subject { described_class.new(ports) }

  describe "#initialize" do
    it "must populate #numbers with the Integers" do
      expect(subject.numbers).to eq(Set[port1, port2])
    end

    it "must populate #ranges with the Ranges" do
      expect(subject.ranges).to eq(Set[range1, range2])
    end

    context "when the ports Array contains a non-Integer/non-Range" do
      let(:bad_port) { Object.new }
      let(:ports)    { [port1, range1, bad_port, port2, range2] }

      it do
        expect {
          described_class.new(ports)
        }.to raise_error(ArgumentError,"port must be an Integer or Range: #{bad_port.inspect}")
      end
    end
  end

  describe ".parse" do
    subject { described_class.parse(string) }

    context "when the port list contains explicit port numbers" do
      let(:string) { "#{port1},#{port2}" }

      it "must parse the ports and add them to #numbers" do
        expect(subject.numbers).to eq(Set[port1, port2])
      end
    end

    context "when the port list contains a N-M range" do
      let(:string) do
        "#{range1.begin}-#{range1.end},#{range2.begin}-#{range2.end}"
      end

      it "must parse the port range" do
        expect(subject.ranges).to eq(Set[range1, range2])
      end
    end
  end

  describe "#include?" do
    context "when the port is explicitly listed in the port list" do
      it "must return true" do
        expect(subject.include?(port2)).to be(true)
      end
    end

    context "when the port is within a range in the port list" do
      it "must return true" do
        expect(subject.include?(8000)).to be(true)
      end
    end

    context "when the port is neither in the port list or a range in the port list" do
      it "must return false" do
        expect(subject.include?(65535)).to be(false)
      end
    end
  end
end
