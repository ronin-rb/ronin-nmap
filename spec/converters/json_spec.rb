require 'spec_helper'
require 'ronin/nmap/converters/json'
require 'tempfile'
require 'nmap/xml'
require 'nmap/xml/scanner'

RSpec.describe Ronin::Nmap::Converters::JSON do
  let(:fixtures_path) { File.expand_path(File.join(__dir__, '..', 'fixtures')) }
  let(:nmap_xml_path) { File.join(fixtures_path, 'nmap.xml') }
  let(:json_path)     { File.join(fixtures_path, 'nmap.json') }
  let(:nmap_file)     { Nmap::XML.open(nmap_xml_path) }
  let(:expected_json) { File.read(json_path) }

  around(:each) do |example|
    original_timezone = ENV['TZ']
    ENV['TZ']         = 'America/New_York'

    example.run

    ENV['TZ'] = original_timezone
  end

  describe '.convert' do
    let(:tempfile) { ['dest', '.json'] }

    it 'must convert nmap XML to json and write it into output' do
      Tempfile.create(tempfile) do |output|
        subject.convert(nmap_file, output)

        output.rewind
        expect(output.read).to eq(expected_json)
      end
    end
  end

  describe '.xml_to_json' do
    let(:tempfile) { ['dest', '.json'] }

    it 'must convert nmap XML to json and write it into output' do
      Tempfile.create(tempfile) do |output|
        subject.xml_to_json(nmap_file, output)

        output.rewind
        expect(output.read).to eq(expected_json)
      end
    end
  end

  describe '.xml_as_json' do
    it 'must convert nmap XML to json representation' do
      result = subject.xml_as_json(nmap_file)
      expect(JSON.dump(result)).to eq(expected_json)
    end
  end

  describe '.scanner_as_json' do
    let(:scanner) do
      Nmap::XML::Scanner.new('nmap',
                             '6.45',
                             'nmap -v -sS -sU -A -O -oX scan.xml scanme.nmap.org',
                             Time.at(1429302190))
    end
    let(:expected_json) do
      {
        name:    scanner.name,
        version: scanner.version,
        args:    scanner.arguments,
        start:   scanner.start_time
      }
    end

    it 'must convert Scanner into json representation' do
      expect(subject.scanner_as_json(scanner)).to eq(expected_json)
    end
  end

  describe '.scan_info_as_json' do
    let(:scan_info) { Nmap::XML::Scan.new('syn', 'tcp', [1,9,13,17]) }
    let(:expected_json) do
      {
        type:     scan_info.type,
        protocol: scan_info.protocol,
        services: scan_info.services
      }
    end

    it 'must convert ScanInfo into json representation' do
      expect(subject.scan_info_as_json(scan_info)).to eq(expected_json)
    end
  end

  describe '.run_stat_as_json' do
    let(:run_stat) { Nmap::XML::RunStat.new(Time.at(1429240388), '21.13', 'summary', 'success') }
    let(:expected_json) do
      {
        end_time:    run_stat.end_time,
        elapsed:     run_stat.elapsed,
        summary:     run_stat.summary,
        exit_status: run_stat.exit_status
      }
    end

    it 'must convert RunStat into json representation' do
      expect(subject.run_stat_as_json(run_stat)).to eq(expected_json)
    end
  end

  describe '.scan_task_as_json' do
    let(:scan_task) { Nmap::XML::ScanTask.new('name', Time.at(1429240388), Time.at(1429240390), '1 total hosts') }
    let(:expected_json) do
      {
        name:       scan_task.name,
        start_time: scan_task.start_time,
        end_time:   scan_task.end_time,
        extra_info: scan_task.extra_info
      }
    end

    it 'must convert ScanTask into json representation' do
      expect(subject.scan_task_as_json(scan_task)).to eq(expected_json)
    end
  end

  describe '.host_as_json' do
    let(:host) { nmap_file.host }
    let(:expected_json) do
      {
        start_time:      host.start_time,
        end_time:        host.end_time,
        status:          subject.status_as_json(host.status),
        addresses:       host.each_address.map { |address| subject.address_as_json(address) },
        hostnames:       host.each_hostname.map { |hostname| subject.hostname_as_json(hostname) },
        os:              subject.os_as_json(host.os),
        uptime:          subject.uptime_as_json(host.uptime),
        tcp_sequence:    subject.tcp_sequence_as_json(host.tcp_sequence),
        ip_id_sequence:  subject.ip_id_sequence_as_json(host.ip_id_sequence),
        tcp_ts_sequence: subject.tcp_ts_sequence_as_json(host.tcp_ts_sequence),
        ports:           host.each_port.map { |port| subject.port_as_json(port) },
        traceroute:      subject.traceroute_as_json(host.traceroute)
      }
    end

    it 'must convert Host to json representation' do
      expect(subject.host_as_json(host)).to eq(expected_json)
    end
  end

  describe '.status_as_json' do
    let(:status) { Nmap::XML::Status.new('up', 'reset', '54') }
    let(:expected_json) do
      {
        state:      status.state,
        reason:     status.reason,
        reason_ttl: status.reason_ttl
      }
    end

    it 'must convert Status into json representation' do
      expect(subject.status_as_json(status)).to eq(expected_json)
    end
  end

  describe '.address_as_json' do
    let(:address) { Nmap::XML::Address.new('ipv4', '45.33.32.156', 'vendor') }
    let(:expected_json) do
      {
        type:   address.type,
        addr:   address.addr,
        vendor: address.vendor
      }
    end

    it 'must convert Address into json representation' do
      expect(subject.address_as_json(address)).to eq(expected_json)
    end
  end

  describe '.hostname_as_json' do
    let(:hostname) { Nmap::XML::Hostname.new('scanme.nmap.org', 'user') }
    let(:expected_json) do
      {
        type: hostname.type,
        name: hostname.name
      }
    end

    it 'must convert Address into json representation' do
      expect(subject.hostname_as_json(hostname)).to eq(expected_json)
    end
  end

  describe '.os_as_json' do
    let(:os) { nmap_file.host.os }
    let(:expected_json) do
      {
        os_classes:  os.each_class.map { |os_class| subject.os_class_as_json(os_class) },
        os_matches:  os.each_match.map { |os_match| subject.os_match_as_json(os_match) },
        ports_used:  os.ports_used
      }
    end

    it 'must convert OS into json representation' do
      expect(subject.os_as_json(os)).to eq(expected_json)
    end
  end

  describe '.os_class_as_json' do
    let(:os_class) { nmap_file.host.os.classes.first }
    let(:expected_json) do
      {
        type: os_class.type,
        vendor: os_class.vendor,
        family: os_class.family,
        gen: os_class.gen,
        accuracy: os_class.accuracy
      }
    end

    it 'must convert OSClass into json representation' do
      expect(subject.os_class_as_json(os_class)).to eq(expected_json)
    end
  end

  describe '.os_match_as_json' do
    let(:os_match) { Nmap::XML::OSMatch.new('Linux 3.0', '94') }
    let(:expected_json) do
      {
        name:     os_match.name,
        accuracy: os_match.accuracy
      }
    end

    it 'must convert OSMatch into json representation' do
      expect(subject.os_match_as_json(os_match)).to eq(expected_json)
    end
  end

  describe '.uptime_as_json' do
    let(:uptime) { Nmap::XML::Uptime.new('142510', 'Wed Apr 15 22:08:02 2015') }
    let(:expected_json) do
      {
        seconds:   uptime.seconds,
        last_boot: uptime.last_boot
      }
    end

    it 'must convert Uptime into json representation' do
      expect(subject.uptime_as_json(uptime)).to eq(expected_json)
    end
  end

  describe '.tcp_sequence_as_json' do
    let(:sequence)      { nmap_file.host.tcp_sequence }
    let(:expected_json) { subject.tcp_sequence_as_json(sequence) }

    it 'must convert TcpSequence into json representation' do
      expect(subject.tcp_sequence_as_json(sequence)).to eq(expected_json)
    end
  end

  describe '.ip_id_sequence_as_json' do
    let(:sequence) { nmap_file.host.ip_id_sequence }
    let(:expected_json) do
      {
        description: sequence.description,
        values:      sequence.values
      }
    end

    it 'must convert IpIdSequence into json representation' do
      expect(subject.ip_id_sequence_as_json(sequence)).to eq(expected_json)
    end
  end

  describe '.tcp_ts_sequence_as_json' do
    let(:sequence) { nmap_file.host.tcp_ts_sequence }
    let(:expected_json) do
      {
        description: sequence.description,
        values:      sequence.values
      }
    end

    it 'must convert TcpTsSequence into json representation' do
      expect(subject.tcp_ts_sequence_as_json(sequence)).to eq(expected_json)
    end
  end

  describe '.sequence_as_json' do
    let(:sequence) { nmap_file.host.tcp_sequence }
    let(:expected_json) do
      {
        description: sequence.description,
        values:      sequence.values
      }
    end

    it 'must convert Sequence into json representation' do
      expect(subject.sequence_as_json(sequence)).to eq(expected_json)
    end
  end

  describe '.port_as_json' do
    let(:port) { nmap_file.host.ports.first }
    let(:expected_json) do
      {
        protocol:   port.protocol,
        number:     port.number,
        state:      port.state,
        reason:     port.reason,
        reason_ttl: port.reason_ttl,
        scripts:    subject.scripts_as_json(port),
        service:    subject.service_as_json(port.service)
      }
    end

    it 'converts nmap Port into json representation' do
      expect(subject.port_as_json(port)).to eq(expected_json)
    end
  end

  describe '.service_as_json' do
    let(:service) { nmap_file.host.ports.first.service }
    let(:expected_json) do
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

    it 'converts nmap Service into json representation' do
      expect(subject.service_as_json(service)).to eq(expected_json)
    end
  end

  describe '.scripts_as_json' do
    let(:has_scripts) { nmap_file.host.ports.first }
    let(:expected_json) do
      has_scripts.scripts.transform_values do |script|
        subject.script_as_json(script)
      end
    end

    it 'must convert Script into json representation' do
      expect(subject.scripts_as_json(has_scripts)).to eq(expected_json)
    end
  end

  describe '.script_as_json' do
    let(:script) { nmap_file.host.ports.first.scripts.first[1] }
    let(:expected_json) do
      {
        id:     script.id,
        output: script.output,
        data:   script.data
      }
    end

    it 'must convert Script into json representation' do
      expect(subject.script_as_json(script)).to eq(expected_json)
    end
  end

  describe '.traceroute_as_json' do
    let(:traceroute) { nmap_file.host.traceroute }
    let(:expected_json) do
      {
        port: traceroute.port,
        protocol: traceroute.protocol,
        traceroute: traceroute.map { |hop| subject.hop_as_json(hop) }
      }
    end

    it 'must convert Traceroute into json representation' do
      expect(subject.traceroute_as_json(traceroute)).to eq(expected_json)
    end
  end

  describe '.hop_as_json' do
    let(:hop) { Nmap::XML::Hop.new('10.0.0.1', 'router4-fmt.linode.com', '1', '0.67') }
    let(:expected_json) do
      {
        addr: hop.addr,
        host: hop.host,
        ttl:  hop.ttl,
        rtt:  hop.rtt
      }
    end

    it 'must convert Hop into json representation' do
      expect(subject.hop_as_json(hop)).to eq(expected_json)
    end
  end
end
