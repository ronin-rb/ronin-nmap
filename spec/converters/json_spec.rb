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
    let(:expected) do
      {
        name: 'nmap',
        version: '6.45',
        args: 'nmap -v -sS -sU -A -O -oX scan.xml scanme.nmap.org',
        start: Time.at(1429302190)
      }
    end

    it 'must convert Scanner into json representation' do
      expect(subject.scanner_as_json(scanner)).to eq(expected)
    end
  end

  describe '.scan_info_as_json' do
    let(:scan_info) { Nmap::XML::Scan.new('syn', 'tcp', [1,9,13,17]) }
    let(:expected) do
      {
        type:     'syn',
        protocol: 'tcp',
        services: [1,9,13,17]
      }
    end

    it 'must convert ScanInfo into json representation' do
      expect(subject.scan_info_as_json(scan_info)).to eq(expected)
    end
  end

  describe '.run_stat_as_json' do
    let(:run_stat) { Nmap::XML::RunStat.new(Time.at(1429240388), '21.13', 'summary', 'success') }
    let(:expected) do
      {
        end_time:    Time.at(1429240388),
        elapsed:     '21.13',
        summary:     'summary',
        exit_status: 'success'
      }
    end

    it 'must convert RunStat into json representation' do
      expect(subject.run_stat_as_json(run_stat)).to eq(expected)
    end
  end

  describe '.scan_task_as_json' do
    let(:scan_task) { Nmap::XML::ScanTask.new('name', Time.at(1429240388), Time.at(1429240390), '1 total hosts') }
    let(:expected) do
      {
        name:       'name',
        start_time: Time.at(1429240388),
        end_time:   Time.at(1429240390),
        extra_info: '1 total hosts'
      }
    end

    it 'must convert ScanTask into json representation' do
      expect(subject.scan_task_as_json(scan_task)).to eq(expected)
    end
  end

  describe '.host_as_json' do
    let(:host) { nmap_file.host }
    let(:expected) do
      {
        start_time: Time.at(1429302190),
        end_time:   Time.at(1429303392),
        status:     {
                      state: :up,
                      reason: "reset",
                      reason_ttl: 54
                    },
        addresses:  [{:addr=>"45.33.32.156", :type=>:ipv4, :vendor=>nil}],
        hostnames:  [{:name=>"scanme.nmap.org", :type=>"user"}, {:name=>"li982-156.members.linode.com", :type=>"PTR"}],
        ip_id_sequence: {:description=>"All zeros", :values=>[0, 0, 0, 0, 0, 0]},
        os: {:os_classes=>[{:accuracy=>94, :family=>:Linux, :gen=>:"3.X", :type=>:"general purpose", :vendor=>"Linux"}, {:accuracy=>94, :family=>:Linux, :gen=>:"2.6.X", :type=>:"general purpose", :vendor=>"Linux"}, {:accuracy=>94, :family=>:Linux, :gen=>:"3.X", :type=>:"general purpose", :vendor=>"Linux"}, {:accuracy=>93, :family=>:Linux, :gen=>:"2.6.X", :type=>:"general purpose", :vendor=>"Linux"}, {:accuracy=>92, :family=>:Linux, :gen=>:"2.6.X", :type=>:"general purpose", :vendor=>"Linux"}, {:accuracy=>91, :family=>:embedded, :type=>:WAP, :vendor=>"Netgear"}, {:accuracy=>91, :family=>:embedded, :type=>:"media device", :vendor=>"Western Digital"}, {:accuracy=>91, :family=>:Linux, :gen=>:"2.6.X", :type=>:"general purpose", :vendor=>"Linux"}, {:accuracy=>91, :family=>:Linux, :gen=>:"3.X", :type=>:"general purpose", :vendor=>"Linux"}, {:accuracy=>91, :family=>:Linux, :gen=>:"2.6.X", :type=>:"general purpose", :vendor=>"Linux"}, {:accuracy=>91, :family=>:embedded, :type=>:"storage-misc", :vendor=>"HP"}, {:accuracy=>90, :family=>:Linux, :gen=>:"2.6.X", :type=>:"general purpose", :vendor=>"Linux"}], :os_matches=>[{:accuracy=>94, :name=>"Linux 3.0"}, {:accuracy=>94, :name=>"Linux 2.6.26 - 2.6.35"}, {:accuracy=>94, :name=>"Linux 3.0 - 3.9"}, {:accuracy=>93, :name=>"Linux 2.6.23 - 2.6.38"}, {:accuracy=>92, :name=>"Linux 2.6.32"}, {:accuracy=>91, :name=>"Netgear DG834G WAP or Western Digital WD TV media player"}, {:accuracy=>91, :name=>"Linux 2.6.32 - 3.9"}, {:accuracy=>91, :name=>"Linux 2.6.8 - 2.6.27"}, {:accuracy=>91, :name=>"HP P2000 G3 NAS device"}, {:accuracy=>90, :name=>"Linux 2.6.22"}], :ports_used=>[22, 1, 2]},
        ports: [{:number=>22, :protocol=>:tcp, :reason=>"syn-ack", :reason_ttl=>"syn-ack", :scripts=>{"ssh-hostkey"=>{:data=>[{"bits"=>"1024", "fingerprint"=>"ac00a01a82ffcc5599dc672b34976b75", "key"=>"QUFBQUIzTnphQzFrYzNNQUFBQ0JBT2U4bzU5dkZXWkdhQm1HUFZlSkJPYkVmaTFBUjh5RVVZQy9VZmtrdTNzS2hHRjd3TTJtMnVqSWVaREs1dnFlQzBTNUVOMnhZbzZGc2hDUDRGUVJZZVR4RDE3bk5PNFBod1c2NXFBakRSUlUwdUhGZlNBaDV3ayt2dDR5UXp0T0UrK3NUZDFHOU9CTHpBOEhPOTlxRG1DQXhiM3p3K0dRREVnUGp6Z3l6R1ozQUFBQUZRQ0JtRTF2Uk9QOElhUGtVbWhNNXhMRnRhL3hId0FBQUlFQTNFd1JmYWVPUExMN1RLRGdHWDY3TGJrZjlVdGRscENkQzRkb01qR2dzem5ZTXdXSDZhN0xqM3ZpNC9LbWVaWmRpeDZGTWRGcXErMnZyZlQxRFJxeDBSUzBYWWRHeG5rZ1MrMmczMzNXWUNyVWtEQ242UlBVV1IvMVRnR01QSENqN0xXQ2ExWndKd0xXUzJLWDI4OFBhMmdMT1d1aFptMlZZS1NReDZORURPSUFBQUNCQU54SWZwclNkQmRibzRFenJoNi9YNkhTdnJoanRaN01vdVN0V2FFNzE0QnlPNWJTMmNvTTlDeWFDd1l5ckU1cXpZaXlJZmIrMUJHM081blZkRHVOOTVzUS8wYkFkQktsa3FMRnZGcUZqVmJFVEYwcmkzdjk3dzZNcFVhd2ZGNzVvdURyUTR4ZGFVT0xMRVdUc282VkZKY002Smc5YkRsMEZBMHVMWlVTREVITA==", "type"=>"ssh-dss"}, {"bits"=>"2048", "fingerprint"=>"203d2d44622ab05a9db5b30514c2a6b2", "key"=>"QUFBQUIzTnphQzF5YzJFQUFBQURBUUFCQUFBQkFRQzZhZm9vVFo5bVZVR0ZORWhrTW9SUjFCdHp1NjRYWHdFbGhDc0h3L3pWbEl4L0hYeWxOYmI5KzExZG0yVmdKUTIxcHhrV0RzK0w2K0ViWXlEbnZSVVJUck1UZ0hMMHhzZUIwRWtOcWV4czloWVpTaXF0TXg0anRHTnRIdnNNeFpuYnh2VlVrMmRhc1d2dEJrbjhKNUphZ1NieldUUW80aGpLTU9JMVNVbFh0aUt4QXMyRjh3aXEyRWRTdUt3L0tOazhHZklwMVRBKzhjY0dlQXRuc1ZwdFRKNEQvOE1oQVdzUk9rUXpPb3dRdm5CQnoyLzhlY0V2b01TY2FmK2tEZk5Rb3dLM2dFTnRTU09xWXc5SkxPemE2WUpCUEwvYVl1UVEwbko3NFJyNXZMNDRhTklsckdJOWpKYzJ4MGJWN0JlTkE1a1Z1WHNtaHlmV2Jia0I4eUdk", "type"=>"ssh-rsa"}, {"bits"=>"256", "fingerprint"=>"9602bb5e57541c4e452f564c4a24b257", "key"=>"QUFBQUUyVmpaSE5oTFhOb1lUSXRibWx6ZEhBeU5UWUFBQUFJYm1semRIQXlOVFlBQUFCQkJNRDQ2ZzY3eDZ5V05qalFKblhoaXovVHNrSHJxUTB1UGNPc3BGcklZVzM4MnVPR3ptV0RaQ0ZWOEZiRndReUg5MHUrajBRcjFTR05BeEJaTWhPUThwYz0=", "type"=>"ecdsa-sha2-nistp256"}], :id=>"ssh-hostkey", :output=>"\n  1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)\nssh-dss AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL\n  2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd\n  256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)\necdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc="}, "ssh2-enum-algos"=>{:data=>{"compression_algorithms"=>["none", "zlib@openssh.com"], "encryption_algorithms"=>["aes128-ctr", "aes192-ctr", "aes256-ctr", "arcfour256", "arcfour128", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com", "aes128-cbc", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "rijndael-cbc@lysator.liu.se"], "kex_algorithms"=>["curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"], "mac_algorithms"=>["hmac-md5-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-ripemd160-etm@openssh.com", "hmac-sha1-96-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-md5", "hmac-sha1", "umac-64@openssh.com", "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-ripemd160", "hmac-ripemd160@openssh.com", "hmac-sha1-96", "hmac-md5-96"], "server_host_key_algorithms"=>["ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519"]}, :id=>"ssh2-enum-algos", :output=>"\n  kex_algorithms: (8)\n      curve25519-sha256@libssh.org\n      ecdh-sha2-nistp256\n      ecdh-sha2-nistp384\n      ecdh-sha2-nistp521\n      diffie-hellman-group-exchange-sha256\n      diffie-hellman-group-exchange-sha1\n      diffie-hellman-group14-sha1\n      diffie-hellman-group1-sha1\n  server_host_key_algorithms: (4)\n      ssh-rsa\n      ssh-dss\n      ecdsa-sha2-nistp256\n      ssh-ed25519\n  encryption_algorithms: (16)\n      aes128-ctr\n      aes192-ctr\n      aes256-ctr\n      arcfour256\n      arcfour128\n      aes128-gcm@openssh.com\n      aes256-gcm@openssh.com\n      chacha20-poly1305@openssh.com\n      aes128-cbc\n      3des-cbc\n      blowfish-cbc\n      cast128-cbc\n      aes192-cbc\n      aes256-cbc\n      arcfour\n      rijndael-cbc@lysator.liu.se\n  mac_algorithms: (19)\n      hmac-md5-etm@openssh.com\n      hmac-sha1-etm@openssh.com\n      umac-64-etm@openssh.com\n      umac-128-etm@openssh.com\n      hmac-sha2-256-etm@openssh.com\n      hmac-sha2-512-etm@openssh.com\n      hmac-ripemd160-etm@openssh.com\n      hmac-sha1-96-etm@openssh.com\n      hmac-md5-96-etm@openssh.com\n      hmac-md5\n      hmac-sha1\n      umac-64@openssh.com\n      umac-128@openssh.com\n      hmac-sha2-256\n      hmac-sha2-512\n      hmac-ripemd160\n      hmac-ripemd160@openssh.com\n      hmac-sha1-96\n      hmac-md5-96\n  compression_algorithms: (2)\n      none\n      zlib@openssh.com"}}, :service=>{:confidence=>10, :device_type=>nil, :extra_info=>"protocol 2.0", :fingerprint=>"SF-Port22-TCP:V=6.45%I=7%D=4/17%Time=55316FE1%P=x86_64-redhat-linux-gnu%r(NULL,29,\"SSH-2\\.0-OpenSSH_6\\.6\\.1p1\\x20Ubuntu-2ubuntu2\\r\\n\");", :fingerprint_method=>:probed, :hostname=>nil, :name=>"ssh", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:open}, {:number=>80, :protocol=>:tcp, :reason=>"syn-ack", :reason_ttl=>"syn-ack", :scripts=>{}, :service=>{:confidence=>10, :device_type=>nil, :extra_info=>"(Ubuntu)", :fingerprint=>nil, :fingerprint_method=>:probed, :hostname=>nil, :name=>"http", :os_type=>nil, :product=>"Apache httpd", :protocol=>nil, :ssl=>false, :version=>"2.4.7"}, :state=>:open}, {:number=>9929, :protocol=>:tcp, :reason=>"syn-ack", :reason_ttl=>"syn-ack", :scripts=>{}, :service=>{:confidence=>10, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:probed, :hostname=>nil, :name=>"nping-echo", :os_type=>nil, :product=>"Nping echo", :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:open}, {:number=>31337, :protocol=>:tcp, :reason=>"syn-ack", :reason_ttl=>"syn-ack", :scripts=>{}, :service=>{:confidence=>10, :device_type=>nil, :extra_info=>"users: nobody", :fingerprint=>nil, :fingerprint_method=>:probed, :hostname=>nil, :name=>"ncat-chat", :os_type=>nil, :product=>"Ncat chat", :protocol=>nil, :ssl=>true, :version=>nil}, :state=>:open}, {:number=>68, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"dhcpc", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>113, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"auth", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>123, :protocol=>:udp, :reason=>"udp-response", :reason_ttl=>"udp-response", :scripts=>{}, :service=>{:confidence=>10, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:probed, :hostname=>nil, :name=>"ntp", :os_type=>nil, :product=>"NTP", :protocol=>nil, :ssl=>false, :version=>"v4"}, :state=>:open}, {:number=>135, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"msrpc", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>136, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"profile", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>137, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"netbios-ns", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>138, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"netbios-dgm", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>139, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"netbios-ssn", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>161, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"snmp", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>445, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"microsoft-ds", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>520, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"route", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>1214, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"fasttrack", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>4666, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"edonkey", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>4672, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"rfa", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>5555, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"rplay", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}, {:number=>6346, :protocol=>:udp, :reason=>"no-response", :reason_ttl=>"no-response", :scripts=>{}, :service=>{:confidence=>3, :device_type=>nil, :extra_info=>nil, :fingerprint=>nil, :fingerprint_method=>:table, :hostname=>nil, :name=>"gnutella", :os_type=>nil, :product=>nil, :protocol=>nil, :ssl=>false, :version=>nil}, :state=>:"open|filtered"}],
        tcp_sequence: {:description=>nil, :difficulty=>"Good luck!", :index=>262, :values=>[2003789810, 2551658239, 3896849460, 2640469570, 432386215, 656392704]},
        tcp_ts_sequence: {:description=>"other", :values=>[42168890, 42168918, 42168949, 42168982, 42169010, 42169038]},
        traceroute: {:port=>80, :protocol=>:tcp, :traceroute=>[{:addr=>"10.0.0.1", :host=>nil, :rtt=>"0.67", :ttl=>"1"}, {:addr=>"68.87.218.65", :host=>"xe-3-1-2-0-sur04.troutdale.or.bverton.comcast.net", :rtt=>"21.22", :ttl=>"3"}, {:addr=>"68.87.216.253", :host=>"et-5-0-0-0-0-ar03.troutdale.or.bverton.comcast.net", :rtt=>"19.93", :ttl=>"4"}, {:addr=>"68.86.93.25", :host=>"he-0-4-0-0-11-cr02.seattle.wa.ibone.comcast.net", :rtt=>"21.56", :ttl=>"5"}, {:addr=>"68.86.85.62", :host=>"he-0-10-0-1-pe04.seattle.wa.ibone.comcast.net", :rtt=>"18.52", :ttl=>"6"}, {:addr=>"65.19.191.137", :host=>"10ge1-20.core1.sea1.he.net", :rtt=>"29.30", :ttl=>"7"}, {:addr=>"72.52.92.157", :host=>"10ge13-4.core1.sjc2.he.net", :rtt=>"33.93", :ttl=>"8"}, {:addr=>"184.105.222.13", :host=>"10ge3-2.core3.fmt2.he.net", :rtt=>"34.66", :ttl=>"9"}, {:addr=>"64.71.132.138", :host=>"router4-fmt.linode.com", :rtt=>"35.65", :ttl=>"10"}, {:addr=>"45.33.32.156", :host=>"li982-156.members.linode.com", :rtt=>"35.92", :ttl=>"11"}]},
        uptime: {:last_boot=>Time.at(1429150082), :seconds=>142510}
      }
    end

    it 'must convert Host to json representation' do
      expect(subject.host_as_json(host)).to eq(expected)
    end
  end

  describe '.status_as_json' do
    let(:status) { Nmap::XML::Status.new('up', 'reset', '54') }
    let(:expected) do
      {
        state:      'up',
        reason:     'reset',
        reason_ttl: '54'
      }
    end

    it 'must convert Status into json representation' do
      expect(subject.status_as_json(status)).to eq(expected)
    end
  end

  describe '.address_as_json' do
    let(:address) { Nmap::XML::Address.new('ipv4', '45.33.32.156', 'vendor') }
    let(:expected) do
      {
        type:   'ipv4',
        addr:   '45.33.32.156',
        vendor: 'vendor'
      }
    end

    it 'must convert Address into json representation' do
      expect(subject.address_as_json(address)).to eq(expected)
    end
  end

  describe '.hostname_as_json' do
    let(:hostname) { Nmap::XML::Hostname.new('scanme.nmap.org', 'user') }
    let(:expected) do
      {
        type: 'scanme.nmap.org',
        name: 'user'
      }
    end

    it 'must convert Address into json representation' do
      expect(subject.hostname_as_json(hostname)).to eq(expected)
    end
  end

  describe '.os_as_json' do
    let(:os) { nmap_file.host.os }
    let(:expected) do
      {
        os_classes: [
          { accuracy: 94, family: :Linux, gen: :"3.X", type: :"general purpose", vendor: "Linux" },
          { accuracy: 94, family: :Linux, gen: :"2.6.X", type: :"general purpose", vendor: "Linux" },
          { accuracy: 94, family: :Linux, gen: :"3.X", type: :"general purpose", vendor: "Linux" },
          { accuracy: 93, family: :Linux, gen: :"2.6.X", type: :"general purpose", vendor: "Linux"},
          { accuracy: 92, family: :Linux, gen: :"2.6.X", type: :"general purpose", vendor: "Linux" },
          { accuracy: 91, family: :embedded, type: :WAP, vendor: "Netgear" },
          { accuracy: 91, family: :embedded, type: :"media device", vendor: "Western Digital" },
          { accuracy: 91, family: :Linux, gen: :"2.6.X", type: :"general purpose", vendor: "Linux" },
          { accuracy: 91, family: :Linux, gen: :"3.X", type: :"general purpose", vendor: "Linux" },
          { accuracy: 91, family: :Linux, gen: :"2.6.X", type: :"general purpose", vendor: "Linux" },
          { accuracy: 91, family: :embedded, type: :"storage-misc", vendor: "HP" },
          { accuracy: 90, family: :Linux, gen: :"2.6.X", type: :"general purpose", vendor: "Linux" }
        ],
        os_matches: [
          { accuracy: 94, name: "Linux 3.0" },
          { accuracy: 94, name: "Linux 2.6.26 - 2.6.35" },
          { accuracy: 94, name: "Linux 3.0 - 3.9" },
          { accuracy: 93, name: "Linux 2.6.23 - 2.6.38" },
          { accuracy: 92, name: "Linux 2.6.32" },
          { accuracy: 91, name: "Netgear DG834G WAP or Western Digital WD TV media player"},
          { accuracy: 91, name: "Linux 2.6.32 - 3.9" },
          { accuracy: 91, name: "Linux 2.6.8 - 2.6.27" },
          { accuracy: 91, name: "HP P2000 G3 NAS device" },
          { accuracy: 90, name: "Linux 2.6.22" }
        ],
        ports_used: [22, 1, 2]
      }
    end

    it 'must convert OS into json representation' do
      expect(subject.os_as_json(os)).to eq(expected)
    end
  end

  describe '.os_class_as_json' do
    let(:os_class) { nmap_file.host.os.classes.first }
    let(:expected) do
      {
        type: :"general purpose",
        vendor: 'Linux',
        family: :Linux,
        gen: :"3.X",
        accuracy: 94
      }
    end

    it 'must convert OSClass into json representation' do
      expect(subject.os_class_as_json(os_class)).to eq(expected)
    end
  end

  describe '.os_match_as_json' do
    let(:os_match) { Nmap::XML::OSMatch.new('Linux 3.0', '94') }
    let(:expected) do
      {
        name: 'Linux 3.0',
        accuracy: '94'
      }
    end

    it 'must convert OSMatch into json representation' do
      expect(subject.os_match_as_json(os_match)).to eq(expected)
    end
  end

  describe '.uptime_as_json' do
    let(:uptime) { Nmap::XML::Uptime.new('142510', 'Wed Apr 15 22:08:02 2015') }
    let(:expected) do
      {
        seconds:   '142510',
        last_boot: 'Wed Apr 15 22:08:02 2015'
      }
    end

    it 'must convert Uptime into json representation' do
      expect(subject.uptime_as_json(uptime)).to eq(expected)
    end
  end

  describe '.tcp_sequence_as_json' do
    let(:sequence) { nmap_file.host.tcp_sequence }
    let(:expected) do
      {
        description: nil,
        difficulty: 'Good luck!',
        index: 262,
        values: [2003789810, 2551658239, 3896849460, 2640469570, 432386215, 656392704]
      }
    end

    it 'must convert TcpSequence into json representation' do
      expect(subject.tcp_sequence_as_json(sequence)).to eq(expected)
    end
  end

  describe '.ip_id_sequence_as_json' do
    let(:sequence) { nmap_file.host.ip_id_sequence }
    let(:expected) do
      {
        description: 'All zeros',
        values: [0, 0, 0, 0, 0, 0]
      }
    end

    it 'must convert IpIdSequence into json representation' do
      expect(subject.ip_id_sequence_as_json(sequence)).to eq(expected)
    end
  end

  describe '.tcp_ts_sequence_as_json' do
    let(:sequence) { nmap_file.host.tcp_ts_sequence }
    let(:expected) do
      {
        description: 'other',
        values: [42168890, 42168918, 42168949, 42168982, 42169010, 42169038]
      }
    end

    it 'must convert TcpTsSequence into json representation' do
      expect(subject.tcp_ts_sequence_as_json(sequence)).to eq(expected)
    end
  end

  describe '.sequence_as_json' do
    let(:sequence) { nmap_file.host.tcp_sequence }
    let(:expected) do
      {
        description: nil,
        values: [2003789810, 2551658239, 3896849460, 2640469570, 432386215, 656392704]
      }
    end

    it 'must convert Sequence into json representation' do
      expect(subject.sequence_as_json(sequence)).to eq(expected)
    end
  end

  describe '.port_as_json' do
    let(:port) { nmap_file.host.ports.first }
    let(:expected) do
      {
        protocol: :tcp,
        number: 22,
        state: :open,
        reason: 'syn-ack',
        reason_ttl: 'syn-ack',
        scripts: {
          "ssh-hostkey" => {
            :data => [
              { "bits" => "1024", "fingerprint" => "ac00a01a82ffcc5599dc672b34976b75", "key" => "QUFBQUIzTnphQzFrYzNNQUFBQ0JBT2U4bzU5dkZXWkdhQm1HUFZlSkJPYkVmaTFBUjh5RVVZQy9VZmtrdTNzS2hHRjd3TTJtMnVqSWVaREs1dnFlQzBTNUVOMnhZbzZGc2hDUDRGUVJZZVR4RDE3bk5PNFBod1c2NXFBakRSUlUwdUhGZlNBaDV3ayt2dDR5UXp0T0UrK3NUZDFHOU9CTHpBOEhPOTlxRG1DQXhiM3p3K0dRREVnUGp6Z3l6R1ozQUFBQUZRQ0JtRTF2Uk9QOElhUGtVbWhNNXhMRnRhL3hId0FBQUlFQTNFd1JmYWVPUExMN1RLRGdHWDY3TGJrZjlVdGRscENkQzRkb01qR2dzem5ZTXdXSDZhN0xqM3ZpNC9LbWVaWmRpeDZGTWRGcXErMnZyZlQxRFJxeDBSUzBYWWRHeG5rZ1MrMmczMzNXWUNyVWtEQ242UlBVV1IvMVRnR01QSENqN0xXQ2ExWndKd0xXUzJLWDI4OFBhMmdMT1d1aFptMlZZS1NReDZORURPSUFBQUNCQU54SWZwclNkQmRibzRFenJoNi9YNkhTdnJoanRaN01vdVN0V2FFNzE0QnlPNWJTMmNvTTlDeWFDd1l5ckU1cXpZaXlJZmIrMUJHM081blZkRHVOOTVzUS8wYkFkQktsa3FMRnZGcUZqVmJFVEYwcmkzdjk3dzZNcFVhd2ZGNzVvdURyUTR4ZGFVT0xMRVdUc282VkZKY002Smc5YkRsMEZBMHVMWlVTREVITA==", "type" => "ssh-dss"},
              { "bits" => "2048", "fingerprint" => "203d2d44622ab05a9db5b30514c2a6b2", "key" => "QUFBQUIzTnphQzF5YzJFQUFBQURBUUFCQUFBQkFRQzZhZm9vVFo5bVZVR0ZORWhrTW9SUjFCdHp1NjRYWHdFbGhDc0h3L3pWbEl4L0hYeWxOYmI5KzExZG0yVmdKUTIxcHhrV0RzK0w2K0ViWXlEbnZSVVJUck1UZ0hMMHhzZUIwRWtOcWV4czloWVpTaXF0TXg0anRHTnRIdnNNeFpuYnh2VlVrMmRhc1d2dEJrbjhKNUphZ1NieldUUW80aGpLTU9JMVNVbFh0aUt4QXMyRjh3aXEyRWRTdUt3L0tOazhHZklwMVRBKzhjY0dlQXRuc1ZwdFRKNEQvOE1oQVdzUk9rUXpPb3dRdm5CQnoyLzhlY0V2b01TY2FmK2tEZk5Rb3dLM2dFTnRTU09xWXc5SkxPemE2WUpCUEwvYVl1UVEwbko3NFJyNXZMNDRhTklsckdJOWpKYzJ4MGJWN0JlTkE1a1Z1WHNtaHlmV2Jia0I4eUdk", "type" => "ssh-rsa"},
              { "bits" => "256", "fingerprint" => "9602bb5e57541c4e452f564c4a24b257", "key" => "QUFBQUUyVmpaSE5oTFhOb1lUSXRibWx6ZEhBeU5UWUFBQUFJYm1semRIQXlOVFlBQUFCQkJNRDQ2ZzY3eDZ5V05qalFKblhoaXovVHNrSHJxUTB1UGNPc3BGcklZVzM4MnVPR3ptV0RaQ0ZWOEZiRndReUg5MHUrajBRcjFTR05BeEJaTWhPUThwYz0=", "type" => "ecdsa-sha2-nistp256" }
            ],
            :id => "ssh-hostkey",
            :output => "\n  1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)\nssh-dss AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL\n  2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd\n  256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)\necdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc="
          },
          "ssh2-enum-algos" => {
            :data => {
              "compression_algorithms" => ["none", "zlib@openssh.com"],
              "encryption_algorithms" => ["aes128-ctr", "aes192-ctr", "aes256-ctr", "arcfour256", "arcfour128", "aes128-gcm@openssh.com", "aes256-gcm@openssh.com", "chacha20-poly1305@openssh.com", "aes128-cbc", "3des-cbc", "blowfish-cbc", "cast128-cbc", "aes192-cbc", "aes256-cbc", "arcfour", "rijndael-cbc@lysator.liu.se"],
              "kex_algorithms" => ["curve25519-sha256@libssh.org", "ecdh-sha2-nistp256", "ecdh-sha2-nistp384", "ecdh-sha2-nistp521", "diffie-hellman-group-exchange-sha256", "diffie-hellman-group-exchange-sha1", "diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"],
              "mac_algorithms" => ["hmac-md5-etm@openssh.com", "hmac-sha1-etm@openssh.com", "umac-64-etm@openssh.com", "umac-128-etm@openssh.com", "hmac-sha2-256-etm@openssh.com", "hmac-sha2-512-etm@openssh.com", "hmac-ripemd160-etm@openssh.com", "hmac-sha1-96-etm@openssh.com", "hmac-md5-96-etm@openssh.com", "hmac-md5", "hmac-sha1", "umac-64@openssh.com", "umac-128@openssh.com", "hmac-sha2-256", "hmac-sha2-512", "hmac-ripemd160", "hmac-ripemd160@openssh.com", "hmac-sha1-96", "hmac-md5-96"],
              "server_host_key_algorithms" => ["ssh-rsa", "ssh-dss", "ecdsa-sha2-nistp256", "ssh-ed25519"]
            },
            :id => "ssh2-enum-algos",
            :output => "\n  kex_algorithms: (8)\n      curve25519-sha256@libssh.org\n      ecdh-sha2-nistp256\n      ecdh-sha2-nistp384\n      ecdh-sha2-nistp521\n      diffie-hellman-group-exchange-sha256\n      diffie-hellman-group-exchange-sha1\n      diffie-hellman-group14-sha1\n      diffie-hellman-group1-sha1\n  server_host_key_algorithms: (4)\n      ssh-rsa\n      ssh-dss\n      ecdsa-sha2-nistp256\n      ssh-ed25519\n  encryption_algorithms: (16)\n      aes128-ctr\n      aes192-ctr\n      aes256-ctr\n      arcfour256\n      arcfour128\n      aes128-gcm@openssh.com\n      aes256-gcm@openssh.com\n      chacha20-poly1305@openssh.com\n      aes128-cbc\n      3des-cbc\n      blowfish-cbc\n      cast128-cbc\n      aes192-cbc\n      aes256-cbc\n      arcfour\n      rijndael-cbc@lysator.liu.se\n  mac_algorithms: (19)\n      hmac-md5-etm@openssh.com\n      hmac-sha1-etm@openssh.com\n      umac-64-etm@openssh.com\n      umac-128-etm@openssh.com\n      hmac-sha2-256-etm@openssh.com\n      hmac-sha2-512-etm@openssh.com\n      hmac-ripemd160-etm@openssh.com\n      hmac-sha1-96-etm@openssh.com\n      hmac-md5-96-etm@openssh.com\n      hmac-md5\n      hmac-sha1\n      umac-64@openssh.com\n      umac-128@openssh.com\n      hmac-sha2-256\n      hmac-sha2-512\n      hmac-ripemd160\n      hmac-ripemd160@openssh.com\n      hmac-sha1-96\n      hmac-md5-96\n  compression_algorithms: (2)\n      none\n      zlib@openssh.com"
          }
        },
        service: {
          :confidence => 10,
          :device_type => nil,
          :extra_info => "protocol 2.0",
          :fingerprint => "SF-Port22-TCP:V=6.45%I=7%D=4/17%Time=55316FE1%P=x86_64-redhat-linux-gnu%r(NULL,29,\"SSH-2\\.0-OpenSSH_6\\.6\\.1p1\\x20Ubuntu-2ubuntu2\\r\\n\");",
          :fingerprint_method => :probed,
          :hostname => nil,
          :name => "ssh",
          :os_type => nil,
          :product => nil,
          :protocol => nil,
          :ssl => false,
          :version => nil
        }
      }
    end

    it 'converts nmap Port into json representation' do
      expect(subject.port_as_json(port)).to eq(expected)
    end
  end

  describe '.service_as_json' do
    let(:service) { nmap_file.host.ports.first.service }
    let(:expected) do
      {
        name: 'ssh',
        ssl: false,
        protocol: nil,
        product: nil,
        version: nil,
        extra_info: 'protocol 2.0',
        hostname: nil,
        os_type: nil,
        device_type: nil,
        fingerprint_method: :probed,
        fingerprint: "SF-Port22-TCP:V=6.45%I=7%D=4/17%Time=55316FE1%P=x86_64-redhat-linux-gnu%r(NULL,29,\"SSH-2\\.0-OpenSSH_6\\.6\\.1p1\\x20Ubuntu-2ubuntu2\\r\\n\");",
        confidence: 10
      }
    end

    it 'converts nmap Service into json representation' do
      expect(subject.service_as_json(service)).to eq(expected)
    end
  end

  describe '.host_script_as_json' do
  end

  describe '.scripts_as_json' do
    let(:scripts) { nmap_file.host.ports.first }
    let(:expected) do
      {
        id: 'ssh-hostkey',
        output: "\n  1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)\nssh-dss AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL\n  2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd\n  256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)\necdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc=",
        data: [{ "fingerprint" => "ac00a01a82ffcc5599dc672b34976b75", "key" => "QUFBQUIzTnphQzFrYzNNQUFBQ0JBT2U4bzU5dkZXWkdhQm1HUFZlSkJPYkVmaTFBUjh5RVVZQy9VZmtrdTNzS2hHRjd3TTJtMnVqSWVaREs1dnFlQzBTNUVOMnhZbzZGc2hDUDRGUVJZZVR4RDE3bk5PNFBod1c2NXFBakRSUlUwdUhGZlNBaDV3ayt2dDR5UXp0T0UrK3NUZDFHOU9CTHpBOEhPOTlxRG1DQXhiM3p3K0dRREVnUGp6Z3l6R1ozQUFBQUZRQ0JtRTF2Uk9QOElhUGtVbWhNNXhMRnRhL3hId0FBQUlFQTNFd1JmYWVPUExMN1RLRGdHWDY3TGJrZjlVdGRscENkQzRkb01qR2dzem5ZTXdXSDZhN0xqM3ZpNC9LbWVaWmRpeDZGTWRGcXErMnZyZlQxRFJxeDBSUzBYWWRHeG5rZ1MrMmczMzNXWUNyVWtEQ242UlBVV1IvMVRnR01QSENqN0xXQ2ExWndKd0xXUzJLWDI4OFBhMmdMT1d1aFptMlZZS1NReDZORURPSUFBQUNCQU54SWZwclNkQmRibzRFenJoNi9YNkhTdnJoanRaN01vdVN0V2FFNzE0QnlPNWJTMmNvTTlDeWFDd1l5ckU1cXpZaXlJZmIrMUJHM081blZkRHVOOTVzUS8wYkFkQktsa3FMRnZGcUZqVmJFVEYwcmkzdjk3dzZNcFVhd2ZGNzVvdURyUTR4ZGFVT0xMRVdUc282VkZKY002Smc5YkRsMEZBMHVMWlVTREVITA==", "type" => "ssh-dss", "bits" => "1024"}, {"fingerprint" => "203d2d44622ab05a9db5b30514c2a6b2", "key" => "QUFBQUIzTnphQzF5YzJFQUFBQURBUUFCQUFBQkFRQzZhZm9vVFo5bVZVR0ZORWhrTW9SUjFCdHp1NjRYWHdFbGhDc0h3L3pWbEl4L0hYeWxOYmI5KzExZG0yVmdKUTIxcHhrV0RzK0w2K0ViWXlEbnZSVVJUck1UZ0hMMHhzZUIwRWtOcWV4czloWVpTaXF0TXg0anRHTnRIdnNNeFpuYnh2VlVrMmRhc1d2dEJrbjhKNUphZ1NieldUUW80aGpLTU9JMVNVbFh0aUt4QXMyRjh3aXEyRWRTdUt3L0tOazhHZklwMVRBKzhjY0dlQXRuc1ZwdFRKNEQvOE1oQVdzUk9rUXpPb3dRdm5CQnoyLzhlY0V2b01TY2FmK2tEZk5Rb3dLM2dFTnRTU09xWXc5SkxPemE2WUpCUEwvYVl1UVEwbko3NFJyNXZMNDRhTklsckdJOWpKYzJ4MGJWN0JlTkE1a1Z1WHNtaHlmV2Jia0I4eUdk", "type" => "ssh-rsa", "bits" => "2048"}, {"fingerprint" => "9602bb5e57541c4e452f564c4a24b257", "key" => "QUFBQUUyVmpaSE5oTFhOb1lUSXRibWx6ZEhBeU5UWUFBQUFJYm1semRIQXlOVFlBQUFCQkJNRDQ2ZzY3eDZ5V05qalFKblhoaXovVHNrSHJxUTB1UGNPc3BGcklZVzM4MnVPR3ptV0RaQ0ZWOEZiRndReUg5MHUrajBRcjFTR05BeEJaTWhPUThwYz0=", "type" => "ecdsa-sha2-nistp256", "bits" => "256"}]
      }
    end

    it 'must convert Script into json representation' do
      result = subject.scripts_as_json(scripts)

      expect(result.size).to eq(2)
      expect(result['ssh-hostkey']).to eq(expected)
    end
  end

  describe '.script_as_json' do
    let(:script) { nmap_file.host.ports.first.scripts.first[1] }
    let(:expected) do
      {
        id: 'ssh-hostkey',
        output: "\n  1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)\nssh-dss AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL\n  2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)\nssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd\n  256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)\necdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc=",
        data: [{ "fingerprint" => "ac00a01a82ffcc5599dc672b34976b75", "key" => "QUFBQUIzTnphQzFrYzNNQUFBQ0JBT2U4bzU5dkZXWkdhQm1HUFZlSkJPYkVmaTFBUjh5RVVZQy9VZmtrdTNzS2hHRjd3TTJtMnVqSWVaREs1dnFlQzBTNUVOMnhZbzZGc2hDUDRGUVJZZVR4RDE3bk5PNFBod1c2NXFBakRSUlUwdUhGZlNBaDV3ayt2dDR5UXp0T0UrK3NUZDFHOU9CTHpBOEhPOTlxRG1DQXhiM3p3K0dRREVnUGp6Z3l6R1ozQUFBQUZRQ0JtRTF2Uk9QOElhUGtVbWhNNXhMRnRhL3hId0FBQUlFQTNFd1JmYWVPUExMN1RLRGdHWDY3TGJrZjlVdGRscENkQzRkb01qR2dzem5ZTXdXSDZhN0xqM3ZpNC9LbWVaWmRpeDZGTWRGcXErMnZyZlQxRFJxeDBSUzBYWWRHeG5rZ1MrMmczMzNXWUNyVWtEQ242UlBVV1IvMVRnR01QSENqN0xXQ2ExWndKd0xXUzJLWDI4OFBhMmdMT1d1aFptMlZZS1NReDZORURPSUFBQUNCQU54SWZwclNkQmRibzRFenJoNi9YNkhTdnJoanRaN01vdVN0V2FFNzE0QnlPNWJTMmNvTTlDeWFDd1l5ckU1cXpZaXlJZmIrMUJHM081blZkRHVOOTVzUS8wYkFkQktsa3FMRnZGcUZqVmJFVEYwcmkzdjk3dzZNcFVhd2ZGNzVvdURyUTR4ZGFVT0xMRVdUc282VkZKY002Smc5YkRsMEZBMHVMWlVTREVITA==", "type" => "ssh-dss", "bits" => "1024"}, {"fingerprint" => "203d2d44622ab05a9db5b30514c2a6b2", "key" => "QUFBQUIzTnphQzF5YzJFQUFBQURBUUFCQUFBQkFRQzZhZm9vVFo5bVZVR0ZORWhrTW9SUjFCdHp1NjRYWHdFbGhDc0h3L3pWbEl4L0hYeWxOYmI5KzExZG0yVmdKUTIxcHhrV0RzK0w2K0ViWXlEbnZSVVJUck1UZ0hMMHhzZUIwRWtOcWV4czloWVpTaXF0TXg0anRHTnRIdnNNeFpuYnh2VlVrMmRhc1d2dEJrbjhKNUphZ1NieldUUW80aGpLTU9JMVNVbFh0aUt4QXMyRjh3aXEyRWRTdUt3L0tOazhHZklwMVRBKzhjY0dlQXRuc1ZwdFRKNEQvOE1oQVdzUk9rUXpPb3dRdm5CQnoyLzhlY0V2b01TY2FmK2tEZk5Rb3dLM2dFTnRTU09xWXc5SkxPemE2WUpCUEwvYVl1UVEwbko3NFJyNXZMNDRhTklsckdJOWpKYzJ4MGJWN0JlTkE1a1Z1WHNtaHlmV2Jia0I4eUdk", "type" => "ssh-rsa", "bits" => "2048"}, {"fingerprint" => "9602bb5e57541c4e452f564c4a24b257", "key" => "QUFBQUUyVmpaSE5oTFhOb1lUSXRibWx6ZEhBeU5UWUFBQUFJYm1semRIQXlOVFlBQUFCQkJNRDQ2ZzY3eDZ5V05qalFKblhoaXovVHNrSHJxUTB1UGNPc3BGcklZVzM4MnVPR3ptV0RaQ0ZWOEZiRndReUg5MHUrajBRcjFTR05BeEJaTWhPUThwYz0=", "type" => "ecdsa-sha2-nistp256", "bits" => "256"}]
      }
    end

    it 'must convert Script into json representation' do
      expect(subject.script_as_json(script)).to eq(expected)
    end
  end

  describe '.traceroute_as_json' do
    let(:traceroute) { nmap_file.host.traceroute }
    let(:expected) do
      {
        port: 80,
        protocol: :tcp,
        traceroute: [
          { addr: "10.0.0.1", host: nil, rtt: "0.67", ttl: "1" },
          { addr: "68.87.218.65", host: "xe-3-1-2-0-sur04.troutdale.or.bverton.comcast.net", rtt: "21.22", ttl: "3" },
          { addr: "68.87.216.253", host: "et-5-0-0-0-0-ar03.troutdale.or.bverton.comcast.net", rtt: "19.93", ttl: "4" },
          { addr: "68.86.93.25", host: "he-0-4-0-0-11-cr02.seattle.wa.ibone.comcast.net", rtt: "21.56", ttl: "5" },
          { addr: "68.86.85.62", host: "he-0-10-0-1-pe04.seattle.wa.ibone.comcast.net", rtt: "18.52", ttl: "6" },
          { addr: "65.19.191.137", host: "10ge1-20.core1.sea1.he.net", rtt: "29.30", ttl: "7" },
          { addr: "72.52.92.157", host: "10ge13-4.core1.sjc2.he.net", rtt: "33.93", ttl: "8" },
          { addr: "184.105.222.13", host: "10ge3-2.core3.fmt2.he.net", rtt: "34.66", ttl: "9" },
          { addr: "64.71.132.138", host: "router4-fmt.linode.com", rtt: "35.65", ttl: "10" },
          { addr: "45.33.32.156", host: "li982-156.members.linode.com", rtt: "35.92", ttl: "11" }
        ]
      }
    end

    it 'must convert Traceroute into json representation' do
      expect(subject.traceroute_as_json(traceroute)).to eq(expected)
    end
  end

  describe '.hop_as_json' do
    let(:hop) { Nmap::XML::Hop.new('10.0.0.1', 'router4-fmt.linode.com', '1', '0.67') }
    let(:expected) do
      {
        addr: '10.0.0.1',
        host: 'router4-fmt.linode.com',
        ttl: '1',
        rtt: '0.67'
      }
    end

    it 'must convert Hop into json representation' do
      expect(subject.hop_as_json(hop)).to eq(expected)
    end
  end
end
