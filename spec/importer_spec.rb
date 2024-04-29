require 'spec_helper'
require 'ronin/nmap/importer'
require 'ronin/db'

RSpec.describe Ronin::Nmap::Importer do
  let(:fixtures_dir) { File.join(__dir__,'fixtures') }
  let(:nmap_path)    { File.join(fixtures_dir, 'nmap.xml') }
  let(:nmap_file)    { Nmap::XML.open(nmap_path) }

  before(:all) do
    Ronin::DB.connect('sqlite3::memory:')
  end

  after do
    Ronin::DB::OpenPort.destroy_all
    Ronin::DB::Port.destroy_all
    Ronin::DB::IPAddress.destroy_all
  end

  let(:expected_imported_classes) do
    [
      Ronin::DB::IPAddress,
      Ronin::DB::HostName,
      Ronin::DB::HostName,
      Ronin::DB::Port,
      Ronin::DB::Service,
      Ronin::DB::OpenPort,
      Ronin::DB::Port,
      Ronin::DB::Service,
      Ronin::DB::OpenPort,
      Ronin::DB::Port,
      Ronin::DB::Service,
      Ronin::DB::OpenPort,
      Ronin::DB::Port,
      Ronin::DB::Service,
      Ronin::DB::OpenPort,
      Ronin::DB::Port,
      Ronin::DB::Service,
      Ronin::DB::OpenPort
    ]
  end

  describe '.import_file' do
    it 'must import and yield records from parsed nmap XML' do
      yielded_values = []

      subject.import_file(nmap_path) do |value|
        yielded_values << value
      end

      expect(yielded_values.size).to eq(18)
      expect(yielded_values.map(&:class)).to match_array(expected_imported_classes)
      expect(yielded_values[0].address).to eq('45.33.32.156')
      expect(yielded_values[1].name).to eq('scanme.nmap.org')
      expect(yielded_values[2].name).to eq('li982-156.members.linode.com')
      expect(yielded_values[3].number).to eq(22)
      expect(yielded_values[4].name).to eq('ssh')
      expect(yielded_values[5].number).to eq(22)
      expect(yielded_values[6].number).to eq(80)
      expect(yielded_values[7].name).to eq('http')
      expect(yielded_values[8].number).to eq(80)
      expect(yielded_values[9].number).to eq(9929)
      expect(yielded_values[10].name).to eq('nping-echo')
      expect(yielded_values[11].number).to eq(9929)
      expect(yielded_values[12].number).to eq(31337)
      expect(yielded_values[13].name).to eq('ncat-chat')
      expect(yielded_values[14].number).to eq(31337)
      expect(yielded_values[15].number).to eq(123)
      expect(yielded_values[16].name).to eq('ntp')
      expect(yielded_values[17].number).to eq(123)
    end
  end

  describe '.import' do
    context 'when no block is given' do
      it 'must return an array' do
        result = subject.import(nmap_file)

        expect(result.size).to eq(18)
        expect(result.map(&:class)).to match_array(expected_imported_classes)
        expect(result[0].address).to eq('45.33.32.156')
        expect(result[1].name).to eq('scanme.nmap.org')
        expect(result[2].name).to eq('li982-156.members.linode.com')
        expect(result[3].number).to eq(22)
        expect(result[4].name).to eq('ssh')
        expect(result[5].number).to eq(22)
        expect(result[6].number).to eq(80)
        expect(result[7].name).to eq('http')
        expect(result[8].number).to eq(80)
        expect(result[9].number).to eq(9929)
        expect(result[10].name).to eq('nping-echo')
        expect(result[11].number).to eq(9929)
        expect(result[12].number).to eq(31337)
        expect(result[13].name).to eq('ncat-chat')
        expect(result[14].number).to eq(31337)
        expect(result[15].number).to eq(123)
        expect(result[16].name).to eq('ntp')
        expect(result[17].number).to eq(123)
      end
    end

    context 'when block is given' do
      it 'must import records from parsed nmap XML' do
        yielded_values = []

        subject.import(nmap_file) do |value|
          yielded_values << value
        end

        expect(yielded_values.size).to eq(18)
        expect(yielded_values.map(&:class)).to match_array(expected_imported_classes)
      end
    end
  end

  describe '.import_host' do
    let(:host) { nmap_file.host }

    it 'must return imported Ronin::DB::IPAddress' do
      expect(subject.import_host(host)).to match_array(be_a(Ronin::DB::IPAddress))
    end

    context 'when block is given' do
      it 'must yield all ip addresses' do
        yielded_values = []

        subject.import_host(host) do |imported_model|
          yielded_values << imported_model
        end

        expect(yielded_values.size).to eq(18)
        expect(yielded_values.map(&:class)).to match_array(expected_imported_classes)
        expect(yielded_values[0].address).to eq('45.33.32.156')
        expect(yielded_values[1].name).to eq('scanme.nmap.org')
        expect(yielded_values[2].name).to eq('li982-156.members.linode.com')
        expect(yielded_values[3].number).to eq(22)
        expect(yielded_values[4].name).to eq('ssh')
        expect(yielded_values[5].number).to eq(22)
        expect(yielded_values[6].number).to eq(80)
        expect(yielded_values[7].name).to eq('http')
        expect(yielded_values[8].number).to eq(80)
        expect(yielded_values[9].number).to eq(9929)
        expect(yielded_values[10].name).to eq('nping-echo')
        expect(yielded_values[11].number).to eq(9929)
        expect(yielded_values[12].number).to eq(31337)
        expect(yielded_values[13].name).to eq('ncat-chat')
        expect(yielded_values[14].number).to eq(31337)
        expect(yielded_values[15].number).to eq(123)
        expect(yielded_values[16].name).to eq('ntp')
        expect(yielded_values[17].number).to eq(123)
      end
    end
  end

  describe '.import_open_port' do
    let(:ip_address) { Ronin::DB::IPAddress.create(address: '1.2.3.4', version: 4) }
    let(:port)       { Ronin::DB::Port.create(protocol: :tcp, number: 22) }
    let(:service)    { Ronin::DB::Service.create(name: 'service') }

    it 'must import and return an OpenPort' do
      result = subject.import_open_port(ip_address, port, service)

      expect(result.ip_address).to be(ip_address)
      expect(result.port).to be(port)
      expect(result.service).to be(service)
    end

    context 'when block is given' do
      it 'must yield imported OpenPort' do
        yielded_value = nil

        subject.import_open_port(ip_address, port, service) do |open_port|
          yielded_value = open_port
        end

        expect(yielded_value).to be_a(Ronin::DB::OpenPort)
        expect(yielded_value.ip_address).to be(ip_address)
        expect(yielded_value.port).to be(port)
        expect(yielded_value.service).to be(service)
      end
    end
  end

  describe '.import_hostnames' do
    let(:host) { nmap_file.host }

    it 'must import and return hostnames' do
      result = subject.import_hostnames(host)

      expect(result.size).to eq(2)
      expect(result[0]).to be_a(Ronin::DB::HostName)
      expect(result[0].name).to eq('scanme.nmap.org')
      expect(result[1]).to be_a(Ronin::DB::HostName)
      expect(result[1].name).to eq('li982-156.members.linode.com')
    end

    context 'when block is given' do
      it 'must yield all hostnames' do
        yielded_values = []

        subject.import_hostnames(host) do |host|
          yielded_values << host
        end

        expect(yielded_values.size).to eq(2)
      end
    end
  end

  describe '.import_hostname' do
    let(:hostname) { nmap_file.host.hostname }

    it 'must import and return a hostname' do
      result = subject.import_hostname(hostname)

      expect(result).to be_a(Ronin::DB::HostName)
      expect(result.name).to eq(hostname.name)
    end
  end

  describe '.import_addresses' do
    let(:host)          { nmap_file.host }
    let(:expected_addr) { '45.33.32.156' }

    it 'must import and return ip and mac addresses' do
      result = subject.import_addresses(host)

      expect(result[0]).to match_array(be_a(Ronin::DB::IPAddress))
      expect(result[0][0].address).to eq('45.33.32.156')
      expect(result[1]).to eq([])
    end
  end

  describe '.import_address' do
    let(:address) { Nmap::XML::Address.new(version, addr) }

    context 'when it is a ip address' do
      let(:version) { :ipv4 }
      let(:addr)    { '45.33.32.156' }

      it 'must return imported Ronin::DB::IPAddress' do
        imported_ip_address = subject.import_address(address)

        expect(imported_ip_address).to be_a(Ronin::DB::IPAddress)
        expect(imported_ip_address.address).to eq(addr)
        expect(imported_ip_address.version).to eq(4)
      end
    end

    context 'when it is a mac address' do
      let(:version) { :mac }
      let(:addr)    { '00-B0-D0-63-C2-26' }

      it 'must return imported Ronin::DB::MACAddress' do
        imported_mac_address = subject.import_mac_address(address)

        expect(imported_mac_address).to be_a(Ronin::DB::MACAddress)
        expect(imported_mac_address.address).to eq(addr)
      end
    end
  end

  describe '.import_ip_address' do
    let(:addr)    { '45.33.32.156' }
    let(:address) { Nmap::XML::Address.new(:ipv4, addr) }

    it 'must return imported Ronin::DB::IPAddress' do
      imported_ip_address = subject.import_address(address)

      expect(imported_ip_address).to be_a(Ronin::DB::IPAddress)
      expect(imported_ip_address.address).to eq(addr)
    end

    context 'when block is given' do
      it 'must yield the imported Ronin::DB::IPAddress' do
        yielded_ip_address = nil

        subject.import_ip_address(address) do |ip_address|
          yielded_ip_address = ip_address
        end

        expect(yielded_ip_address.address).to eq(addr)
      end
    end
  end

  describe '.import_mac_address' do
    let(:addr)    { '00-B0-D0-63-C2-26' }
    let(:address) { Nmap::XML::Address.new(:mac, addr) }

    it 'must return imported Ronin::DB::MACAddress' do
      imported_mac_address = subject.import_mac_address(address)

      expect(imported_mac_address).to be_a(Ronin::DB::MACAddress)
      expect(imported_mac_address.address).to eq(addr)
    end

    context 'when block is given' do
      it 'must yield the imported Ronin::DB::MACAddress' do
        yielded_mac_address = nil

        subject.import_mac_address(address) do |ip_address|
          yielded_mac_address = ip_address
        end

        expect(yielded_mac_address.address).to eq(addr)
      end
    end
  end

  describe '.import_port' do
    let(:port) { nmap_file.host.ports.first }

    it 'must import and return ports and services' do
      result = subject.import_port(port)

      expect(result.size).to be(2)
      expect(result[0]).to be_a(Ronin::DB::Port)
      expect(result[0].number).to be(22)
      expect(result[1]).to be_a(Ronin::DB::Service)
      expect(result[1].name).to eq('ssh')
    end

    context 'when block is given' do
      it 'must yield imported models' do
        yielded_values = []

        subject.import_port(port) do |imported_model|
          yielded_values << imported_model
        end

        expect(yielded_values.size).to be(2)
        expect(yielded_values[0]).to be_a(Ronin::DB::Port)
        expect(yielded_values[0].number).to be(22)
        expect(yielded_values[1]).to be_a(Ronin::DB::Service)
        expect(yielded_values[1].name).to eq('ssh')
      end
    end
  end
end
