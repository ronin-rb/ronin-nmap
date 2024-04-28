require 'spec_helper'
require 'ronin/nmap/converters/csv'
require 'tempfile'
require 'nmap/xml'

RSpec.describe Ronin::Nmap::Converters::CSV do
  let(:fixtures_path) { File.expand_path(File.join(__dir__, '..', 'fixtures')) }
  let(:nmap_xml_path) { File.join(fixtures_path, 'nmap.xml') }
  let(:csv_path)      { File.join(fixtures_path, 'nmap.csv') }
  let(:nmap_file)     { Nmap::XML.open(nmap_xml_path) }
  let(:expected_csv)  { File.read(csv_path) }

  describe '.convert' do
    let(:tempfile) { ['dest', '.csv'] }

    around(:each) do |example|
      original_timezone = ENV['TZ']
      ENV['TZ']         = 'America/New_York'

      example.run

      ENV['TZ'] = original_timezone
    end

    it 'must convert nmap XML to csv and write it into output' do
      Tempfile.create(tempfile) do |output|
        subject.convert(nmap_file, output)

        output.rewind
        expect(output.read).to eq(expected_csv)
      end
    end
  end

  describe '.xml_to_csv' do
    let(:tempfile) { ['dest', '.csv'] }

    around(:each) do |example|
      original_timezone = ENV['TZ']
      ENV['TZ']         = 'America/New_York'

      example.run

      ENV['TZ'] = original_timezone
    end

    it 'must convert nmap XML to csv and write it into output' do
      Tempfile.create(tempfile) do |output|
        subject.xml_to_csv(nmap_file, output)

        output.rewind
        expect(output.read).to eq(expected_csv)
      end
    end
  end

  describe '.xml_to_rows' do
    let(:start_time) { Time.at(1429302190) }
    let(:end_time)   { Time.at(1429303392) }
    let(:status)     { Nmap::XML::Status.new(:up, 'reset', 54) }
    let(:expected_row) do
      [
        start_time, end_time, status, :tcp, 22, "45.33.32.156", :open, "syn-ack", "syn-ack",
        "ssh", false, nil, nil, nil, "protocol 2.0", nil, nil, nil, :probed,
        "SF-Port22-TCP:V=6.45%I=7%D=4/17%Time=55316FE1%P=x86_64-redhat-linux-gnu%r(NULL,29,\"SSH-2\\.0-OpenSSH_6\\.6\\.1p1\\x20Ubuntu-2ubuntu2\\r\\n\");", 10
      ]
    end

    it 'must yield headers and each row' do
      result = []
      subject.xml_to_rows(nmap_file) do |row|
        result << row
      end

      expect(result.size).to eq(21)
      expect(result[0]).to eq(Ronin::Nmap::Converters::CSV::HEADER)
      expect(result[1]).to match_array(expected_row)
    end
  end

  describe '.each_host_rows' do
    let(:start_time) { Time.at(1429302190) }
    let(:end_time)   { Time.at(1429303392) }
    let(:status)     { Nmap::XML::Status.new(:up, 'reset', 54) }
    let(:expected_row) do
      [
        start_time, end_time, status, "45.33.32.156", :tcp, 22, :open, "syn-ack", "syn-ack",
        "ssh", false, nil, nil, nil, "protocol 2.0", nil, nil, nil, :probed,
        "SF-Port22-TCP:V=6.45%I=7%D=4/17%Time=55316FE1%P=x86_64-redhat-linux-gnu%r(NULL,29,\"SSH-2\\.0-OpenSSH_6\\.6\\.1p1\\x20Ubuntu-2ubuntu2\\r\\n\");", 10
      ]
    end
    let(:host) { nmap_file.host }

    it 'must yeald each nmap XML host row' do
      result = []
      subject.each_host_rows(host) do |row|
        result << row
      end

      expect(result.size).to eq(20)
      expect(result[0]).to eq(expected_row)
    end
  end

  describe '.port_to_row' do
    let(:port)    { nmap_file.host.ports.first }
    let(:service) { port.service }
    let(:expected_port_row) do
      [
        port.protocol,
        port.number,
        port.state,
        port.reason,
        port.reason_ttl,
        service.name,
        service.ssl?,
        service.protocol,
        service.product,
        service.version,
        service.extra_info,
        service.hostname,
        service.os_type,
        service.device_type,
        service.fingerprint_method,
        service.fingerprint,
        service.confidence
      ]
    end

    it 'converts nmap XML port into a row of values tat represents it' do
      expect(subject.port_to_row(port)).to eq(expected_port_row)
    end
  end

  describe '.service_to_row' do
    let(:service) { nmap_file.host.ports.first.service }
    let(:expected_service_row) do
      [
        service.name,
        service.ssl?,
        service.protocol,
        service.product,
        service.version,
        service.extra_info,
        service.hostname,
        service.os_type,
        service.device_type,
        service.fingerprint_method,
        service.fingerprint,
        service.confidence
      ]
    end

    it 'converts nmap XML service to row of values that represents it' do
      expect(subject.service_to_row(service)).to eq(expected_service_row)
    end
  end
end
