require 'spec_helper'
require 'ronin/nmap/cli/commands/grep'
require_relative 'man_page_example'

require 'stringio'

describe Ronin::Nmap::CLI::Commands::Grep do
  include_examples "man_page"

  let(:fixtures_dir) { File.join(__dir__,'..','..','fixtures') }
  let(:xml_file)     { File.join(fixtures_dir,'nmap.xml') }
  let(:xml)          { Nmap::XML.open(xml_file) }
  let(:host)         { xml.host }
  let(:hostname)     { xml.host.hostname }
  let(:port)         { host.open_ports.first }
  let(:service)      { port.service }
  let(:script_id)    { 'ssh2-enum-algos' }
  let(:script)       { port.scripts[script_id] }

  let(:red)             { CommandKit::Colors::ANSI::RED }
  let(:bold)            { CommandKit::Colors::ANSI::BOLD }
  let(:reset_color)     { CommandKit::Colors::ANSI::RESET_COLOR }
  let(:reset_intensity) { CommandKit::Colors::ANSI::RESET_INTENSITY }
  let(:reset)           { reset_color + reset_intensity }

  let(:stdout) { StringIO.new }

  subject { described_class.new(stdout: stdout) }
  before { allow(stdout).to receive(:tty?).and_return(true) }

  describe "#run" do
    context "when given a single XML file" do
      let(:pattern) { 'nmap' }

      it "must parse the XML file and print the matching hosts, with the pattern highlighted in bold red" do
        subject.run(pattern,xml_file)

        expect(stdout.string).to eq(
          <<~OUTPUT
            [ 45.33.32.156 / scanme.#{bold}#{red}nmap#{reset_color}#{reset_intensity}.org ]

              [ hostnames ]

                scanme.#{bold}#{red}nmap#{reset_color}#{reset_intensity}.org
                li982-156.members.linode.com

              [ ports ]

                22/tcp	open	ssh protocol 2.0

                  ssh-hostkey:
                    1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)
                    ssh-dss AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL
                      2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)
                    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd
                      256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)
                    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc=

                  ssh2-enum-algos:
                    kex_algorithms: (8)
                          curve25519-sha256@libssh.org
                          ecdh-sha2-nistp256
                          ecdh-sha2-nistp384
                          ecdh-sha2-nistp521
                          diffie-hellman-group-exchange-sha256
                          diffie-hellman-group-exchange-sha1
                          diffie-hellman-group14-sha1
                          diffie-hellman-group1-sha1
                      server_host_key_algorithms: (4)
                          ssh-rsa
                          ssh-dss
                          ecdsa-sha2-nistp256
                          ssh-ed25519
                      encryption_algorithms: (16)
                          aes128-ctr
                          aes192-ctr
                          aes256-ctr
                          arcfour256
                          arcfour128
                          aes128-gcm@openssh.com
                          aes256-gcm@openssh.com
                          chacha20-poly1305@openssh.com
                          aes128-cbc
                          3des-cbc
                          blowfish-cbc
                          cast128-cbc
                          aes192-cbc
                          aes256-cbc
                          arcfour
                          rijndael-cbc@lysator.liu.se
                      mac_algorithms: (19)
                          hmac-md5-etm@openssh.com
                          hmac-sha1-etm@openssh.com
                          umac-64-etm@openssh.com
                          umac-128-etm@openssh.com
                          hmac-sha2-256-etm@openssh.com
                          hmac-sha2-512-etm@openssh.com
                          hmac-ripemd160-etm@openssh.com
                          hmac-sha1-96-etm@openssh.com
                          hmac-md5-96-etm@openssh.com
                          hmac-md5
                          hmac-sha1
                          umac-64@openssh.com
                          umac-128@openssh.com
                          hmac-sha2-256
                          hmac-sha2-512
                          hmac-ripemd160
                          hmac-ripemd160@openssh.com
                          hmac-sha1-96
                          hmac-md5-96
                      compression_algorithms: (2)
                          none
                          zlib@openssh.com

                80/tcp	open	Apache httpd 2.4.7 (Ubuntu)
                9929/tcp	open	nping-echo
                31337/tcp	open	ncat-chat users: nobody
                123/udp	open	NTP v4

          OUTPUT
        )
      end
    end

    context "when given multiple XML files" do
      it "must grep each XML file and print matching hosts with the pattern highlighted in bold red"
    end
  end

  describe "#grep_xml" do
    let(:pattern) { 'scanme' }

    it "must return an Enumerator::Lazy object containing the matching hosts that contain the given pattern" do
      hosts = subject.grep_xml(xml,pattern)

      expect(hosts).to be_kind_of(Enumerator::Lazy)
      expect(hosts.first.hostname.name).to match(pattern)
    end
  end

  describe "#match_host" do
    context "when the Nmap::XML::Host object contains the pattern in one of it's hostnames" do
      let(:pattern) { 'scanme' }

      it do
        expect(subject.match_host(host,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Host object contains the pattern in one of it's open port's services" do
      let(:pattern) { 'httpd' }

      it do
        expect(subject.match_host(host,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Host object contains the pattern in one of it's open ports script IDs" do
      let(:pattern) { 'ssh2-enum-algos' }

      it do
        expect(subject.match_host(host,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Host object contains the pattern in one of it's open ports script outputs" do
      let(:pattern) { 'rsa' }

      it do
        expect(subject.match_host(host,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Host object contains the pattern in one of it's host scripts" do
      let(:pattern) { 'scanme' }

      xit do
        pending "need an nmap XML file which contains host scripts"

        expect(subject.match_host(host,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Host object does not contain the pattern in any of it's hostnames, open port's services, open port's script IDs, open port's script outputs, or it's host scripts" do
      let(:pattern) { 'does-not-match' }

      it do
        expect(subject.match_host(host,pattern)).to be_falsy
      end
    end
  end

  describe "#match_hostname" do
    context "when the Nmap::XML::Hostname object contains the pattern in it's name" do
      let(:pattern) { 'nmap' }

      it do
        expect(subject.match_hostname(hostname,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Hostname object does not contain the pattern in it's name" do
      let(:pattern) { 'does-not-match' }

      it do
        expect(subject.match_hostname(hostname,pattern)).to be_falsy
      end
    end
  end

  describe "#match_port" do
    context "when the Nmap::XML::Port contains the pattern in one of it's script IDs" do
      let(:pattern) { 'ssh2' }

      it do
        expect(subject.match_port(port,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Port contains the pattern in one of it's script outputs" do
      let(:pattern) { 'rsa' }

      it do
        expect(subject.match_port(port,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Port does not contain the pattern in one of it's service, script IDs, script outputs" do
      let(:pattern) { 'does-not-match' }

      it do
        expect(subject.match_port(port,pattern)).to be_falsy
      end
    end

    context "when the Nmap::XML::Port object has a #service" do
      context "and it contains the pattern" do
        let(:port) do
          host.open_ports.find { |port| port.number == 80 }
        end
        let(:pattern) { 'http' }

        it do
          expect(subject.match_port(port,pattern)).to be_truthy
        end
      end
    end
  end

  describe "#match_service" do
    let(:port) do
      host.open_ports.find { |port| port.number == 80 }
    end
    let(:service) { port.service }

    context "when the Nmap::XML::Service contains the pattern in it's product info" do
      let(:pattern) { 'http' }

      it do
        expect(subject.match_service(service,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Service contains the pattern in it's version" do
      let(:pattern) { '2.4' }

      it do
        expect(subject.match_service(service,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Service contains the pattern in it's extra info" do
      let(:pattern) { 'Ubuntu' }

      it do
        expect(subject.match_service(service,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Service does not contain the pattern in any of it's product info, version, or extra info" do
      let(:pattern) { 'does-not-match' }

      it do
        expect(subject.match_service(service,pattern)).to be_falsy
      end
    end
  end

  describe "#match_scripts" do
    let(:has_scripts) { port }

    context "when one of the object's #scripts contains the pattern in it's script ID" do
      let(:pattern) { 'ssh2' }

      it do
        expect(subject.match_scripts(has_scripts,pattern)).to be_truthy
      end
    end

    context "when one of the object's #scripts contains the pattern in it's script outputs" do
      let(:pattern) { 'rsa' }

      it do
        expect(subject.match_scripts(has_scripts,pattern)).to be_truthy
      end
    end

    context "when none of the object's #scripts contains the pattern in it's script ID" do
      let(:pattern) { 'does-not-match' }

      it do
        expect(subject.match_scripts(has_scripts,pattern)).to be_falsy
      end
    end
  end

  describe "#match_script" do
    context "when the Nmap::XML::Script object contains the pattern in it's script ID" do
      let(:pattern) { 'ssh2' }

      it do
        expect(subject.match_script(script,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Script object contains the pattern in it's script outputs" do
      let(:pattern) { 'rsa' }

      it do
        expect(subject.match_script(script,pattern)).to be_truthy
      end
    end

    context "when the Nmap::XML::Script object does not contain the pattern in it's script ID or script output" do
      let(:pattern) { 'does-not-match' }

      it do
        expect(subject.match_script(script,pattern)).to be_falsy
      end
    end
  end

  describe "#highlight_hosts" do
    let(:hosts)   { xml.up_hosts }
    let(:pattern) { 'nmap' }

    it "must print each host, with the pattern highlighted in bold red, with an extra newline after the host" do
      subject.highlight_hosts(hosts,pattern)

      expect(stdout.string).to eq(
        <<~OUTPUT
          [ 45.33.32.156 / scanme.#{bold}#{red}nmap#{reset_color}#{reset_intensity}.org ]

            [ hostnames ]

              scanme.#{bold}#{red}nmap#{reset_color}#{reset_intensity}.org
              li982-156.members.linode.com

            [ ports ]

              22/tcp	open	ssh protocol 2.0

                ssh-hostkey:
                  1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)
                  ssh-dss AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL
                    2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)
                  ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd
                    256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)
                  ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc=

                ssh2-enum-algos:
                  kex_algorithms: (8)
                        curve25519-sha256@libssh.org
                        ecdh-sha2-nistp256
                        ecdh-sha2-nistp384
                        ecdh-sha2-nistp521
                        diffie-hellman-group-exchange-sha256
                        diffie-hellman-group-exchange-sha1
                        diffie-hellman-group14-sha1
                        diffie-hellman-group1-sha1
                    server_host_key_algorithms: (4)
                        ssh-rsa
                        ssh-dss
                        ecdsa-sha2-nistp256
                        ssh-ed25519
                    encryption_algorithms: (16)
                        aes128-ctr
                        aes192-ctr
                        aes256-ctr
                        arcfour256
                        arcfour128
                        aes128-gcm@openssh.com
                        aes256-gcm@openssh.com
                        chacha20-poly1305@openssh.com
                        aes128-cbc
                        3des-cbc
                        blowfish-cbc
                        cast128-cbc
                        aes192-cbc
                        aes256-cbc
                        arcfour
                        rijndael-cbc@lysator.liu.se
                    mac_algorithms: (19)
                        hmac-md5-etm@openssh.com
                        hmac-sha1-etm@openssh.com
                        umac-64-etm@openssh.com
                        umac-128-etm@openssh.com
                        hmac-sha2-256-etm@openssh.com
                        hmac-sha2-512-etm@openssh.com
                        hmac-ripemd160-etm@openssh.com
                        hmac-sha1-96-etm@openssh.com
                        hmac-md5-96-etm@openssh.com
                        hmac-md5
                        hmac-sha1
                        umac-64@openssh.com
                        umac-128@openssh.com
                        hmac-sha2-256
                        hmac-sha2-512
                        hmac-ripemd160
                        hmac-ripemd160@openssh.com
                        hmac-sha1-96
                        hmac-md5-96
                    compression_algorithms: (2)
                        none
                        zlib@openssh.com

              80/tcp	open	Apache httpd 2.4.7 (Ubuntu)
              9929/tcp	open	nping-echo
              31337/tcp	open	ncat-chat users: nobody
              123/udp	open	NTP v4

        OUTPUT
      )
    end
  end

  describe "#highlight_host" do
    context "when the host has more than one address" do
      it "must print a '[ addresses ]' section with the addresses"
    end

    context "when the pattern exists in the first hostname" do
      let(:pattern) { 'nmap' }

      it "must print the address and hostnmae in the top section header and in the '[ hostnames ]' section, with the pattern highlighted in bold red" do
        subject.highlight_host(host,pattern)

        expect(stdout.string).to eq(
          <<~OUTPUT
            [ 45.33.32.156 / scanme.#{bold}#{red}nmap#{reset_color}#{reset_intensity}.org ]

              [ hostnames ]

                scanme.#{bold}#{red}nmap#{reset_color}#{reset_intensity}.org
                li982-156.members.linode.com

              [ ports ]

                22/tcp	open	ssh protocol 2.0

                  ssh-hostkey:
                    1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)
                    ssh-dss AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL
                      2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)
                    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd
                      256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)
                    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc=

                  ssh2-enum-algos:
                    kex_algorithms: (8)
                          curve25519-sha256@libssh.org
                          ecdh-sha2-nistp256
                          ecdh-sha2-nistp384
                          ecdh-sha2-nistp521
                          diffie-hellman-group-exchange-sha256
                          diffie-hellman-group-exchange-sha1
                          diffie-hellman-group14-sha1
                          diffie-hellman-group1-sha1
                      server_host_key_algorithms: (4)
                          ssh-rsa
                          ssh-dss
                          ecdsa-sha2-nistp256
                          ssh-ed25519
                      encryption_algorithms: (16)
                          aes128-ctr
                          aes192-ctr
                          aes256-ctr
                          arcfour256
                          arcfour128
                          aes128-gcm@openssh.com
                          aes256-gcm@openssh.com
                          chacha20-poly1305@openssh.com
                          aes128-cbc
                          3des-cbc
                          blowfish-cbc
                          cast128-cbc
                          aes192-cbc
                          aes256-cbc
                          arcfour
                          rijndael-cbc@lysator.liu.se
                      mac_algorithms: (19)
                          hmac-md5-etm@openssh.com
                          hmac-sha1-etm@openssh.com
                          umac-64-etm@openssh.com
                          umac-128-etm@openssh.com
                          hmac-sha2-256-etm@openssh.com
                          hmac-sha2-512-etm@openssh.com
                          hmac-ripemd160-etm@openssh.com
                          hmac-sha1-96-etm@openssh.com
                          hmac-md5-96-etm@openssh.com
                          hmac-md5
                          hmac-sha1
                          umac-64@openssh.com
                          umac-128@openssh.com
                          hmac-sha2-256
                          hmac-sha2-512
                          hmac-ripemd160
                          hmac-ripemd160@openssh.com
                          hmac-sha1-96
                          hmac-md5-96
                      compression_algorithms: (2)
                          none
                          zlib@openssh.com

                80/tcp	open	Apache httpd 2.4.7 (Ubuntu)
                9929/tcp	open	nping-echo
                31337/tcp	open	ncat-chat users: nobody
                123/udp	open	NTP v4
          OUTPUT
        )
      end
    end

    context "when the pattern exists in one of the other hostnames" do
      let(:pattern) { 'linode' }

      it "must print the '[ hostnames ]' section containing the hostnames, with the pattern highlighted in bold red" do
        subject.highlight_host(host,pattern)

        expect(stdout.string).to eq(
          <<~OUTPUT
            [ 45.33.32.156 / scanme.nmap.org ]

              [ hostnames ]

                scanme.nmap.org
                li982-156.members.#{bold}#{red}linode#{reset_color}#{reset_intensity}.com

              [ ports ]

                22/tcp	open	ssh protocol 2.0

                  ssh-hostkey:
                    1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)
                    ssh-dss AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL
                      2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)
                    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd
                      256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)
                    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc=

                  ssh2-enum-algos:
                    kex_algorithms: (8)
                          curve25519-sha256@libssh.org
                          ecdh-sha2-nistp256
                          ecdh-sha2-nistp384
                          ecdh-sha2-nistp521
                          diffie-hellman-group-exchange-sha256
                          diffie-hellman-group-exchange-sha1
                          diffie-hellman-group14-sha1
                          diffie-hellman-group1-sha1
                      server_host_key_algorithms: (4)
                          ssh-rsa
                          ssh-dss
                          ecdsa-sha2-nistp256
                          ssh-ed25519
                      encryption_algorithms: (16)
                          aes128-ctr
                          aes192-ctr
                          aes256-ctr
                          arcfour256
                          arcfour128
                          aes128-gcm@openssh.com
                          aes256-gcm@openssh.com
                          chacha20-poly1305@openssh.com
                          aes128-cbc
                          3des-cbc
                          blowfish-cbc
                          cast128-cbc
                          aes192-cbc
                          aes256-cbc
                          arcfour
                          rijndael-cbc@lysator.liu.se
                      mac_algorithms: (19)
                          hmac-md5-etm@openssh.com
                          hmac-sha1-etm@openssh.com
                          umac-64-etm@openssh.com
                          umac-128-etm@openssh.com
                          hmac-sha2-256-etm@openssh.com
                          hmac-sha2-512-etm@openssh.com
                          hmac-ripemd160-etm@openssh.com
                          hmac-sha1-96-etm@openssh.com
                          hmac-md5-96-etm@openssh.com
                          hmac-md5
                          hmac-sha1
                          umac-64@openssh.com
                          umac-128@openssh.com
                          hmac-sha2-256
                          hmac-sha2-512
                          hmac-ripemd160
                          hmac-ripemd160@openssh.com
                          hmac-sha1-96
                          hmac-md5-96
                      compression_algorithms: (2)
                          none
                          zlib@openssh.com

                80/tcp	open	Apache httpd 2.4.7 (Ubuntu)
                9929/tcp	open	nping-echo
                31337/tcp	open	ncat-chat users: nobody
                123/udp	open	NTP v4
          OUTPUT
        )
      end
    end

    context "when the Nmap::XML::Host has a host_script" do
      it "must print a '[ host scripts ]' sections with the host scripts"
    end

    context "when the pattern exists in one of the ports or services" do
      let(:pattern) { 'http' }

      it "must print the port number, protocol, state, and service name/version, with the pattern highlighted in bold red" do
        subject.highlight_host(host,pattern)

        expect(stdout.string).to eq(
          <<~OUTPUT
            [ 45.33.32.156 / scanme.nmap.org ]

              [ hostnames ]

                scanme.nmap.org
                li982-156.members.linode.com

              [ ports ]

                22/tcp	open	ssh protocol 2.0

                  ssh-hostkey:
                    1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)
                    ssh-dss AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL
                      2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)
                    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd
                      256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)
                    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc=

                  ssh2-enum-algos:
                    kex_algorithms: (8)
                          curve25519-sha256@libssh.org
                          ecdh-sha2-nistp256
                          ecdh-sha2-nistp384
                          ecdh-sha2-nistp521
                          diffie-hellman-group-exchange-sha256
                          diffie-hellman-group-exchange-sha1
                          diffie-hellman-group14-sha1
                          diffie-hellman-group1-sha1
                      server_host_key_algorithms: (4)
                          ssh-rsa
                          ssh-dss
                          ecdsa-sha2-nistp256
                          ssh-ed25519
                      encryption_algorithms: (16)
                          aes128-ctr
                          aes192-ctr
                          aes256-ctr
                          arcfour256
                          arcfour128
                          aes128-gcm@openssh.com
                          aes256-gcm@openssh.com
                          chacha20-poly1305@openssh.com
                          aes128-cbc
                          3des-cbc
                          blowfish-cbc
                          cast128-cbc
                          aes192-cbc
                          aes256-cbc
                          arcfour
                          rijndael-cbc@lysator.liu.se
                      mac_algorithms: (19)
                          hmac-md5-etm@openssh.com
                          hmac-sha1-etm@openssh.com
                          umac-64-etm@openssh.com
                          umac-128-etm@openssh.com
                          hmac-sha2-256-etm@openssh.com
                          hmac-sha2-512-etm@openssh.com
                          hmac-ripemd160-etm@openssh.com
                          hmac-sha1-96-etm@openssh.com
                          hmac-md5-96-etm@openssh.com
                          hmac-md5
                          hmac-sha1
                          umac-64@openssh.com
                          umac-128@openssh.com
                          hmac-sha2-256
                          hmac-sha2-512
                          hmac-ripemd160
                          hmac-ripemd160@openssh.com
                          hmac-sha1-96
                          hmac-md5-96
                      compression_algorithms: (2)
                          none
                          zlib@openssh.com

                80/tcp	open	Apache #{bold}#{red}http#{reset_color}#{reset_intensity}d 2.4.7 (Ubuntu)
                9929/tcp	open	nping-echo
                31337/tcp	open	ncat-chat users: nobody
                123/udp	open	NTP v4
          OUTPUT
        )
      end
    end

    context "when the pattern exists in one of the script IDs for one of the ports" do
      let(:pattern) { 'ssh2' }

      it "must print the script ID with the pattern highlighted in the script ID" do
        subject.highlight_host(host,pattern)

        expect(stdout.string).to eq(
          <<~OUTPUT
            [ 45.33.32.156 / scanme.nmap.org ]

              [ hostnames ]

                scanme.nmap.org
                li982-156.members.linode.com

              [ ports ]

                22/tcp	open	ssh protocol 2.0

                  ssh-hostkey:
                    1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)
                    ssh-dss AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL
                      2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)
                    ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd
                      256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)
                    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc=

                  #{bold}#{red}ssh2#{reset_color}#{reset_intensity}-enum-algos:
                    kex_algorithms: (8)
                          curve25519-sha256@libssh.org
                          ecdh-sha2-nistp256
                          ecdh-sha2-nistp384
                          ecdh-sha2-nistp521
                          diffie-hellman-group-exchange-sha256
                          diffie-hellman-group-exchange-sha1
                          diffie-hellman-group14-sha1
                          diffie-hellman-group1-sha1
                      server_host_key_algorithms: (4)
                          ssh-rsa
                          ssh-dss
                          ecdsa-sha2-nistp256
                          ssh-ed25519
                      encryption_algorithms: (16)
                          aes128-ctr
                          aes192-ctr
                          aes256-ctr
                          arcfour256
                          arcfour128
                          aes128-gcm@openssh.com
                          aes256-gcm@openssh.com
                          chacha20-poly1305@openssh.com
                          aes128-cbc
                          3des-cbc
                          blowfish-cbc
                          cast128-cbc
                          aes192-cbc
                          aes256-cbc
                          arcfour
                          rijndael-cbc@lysator.liu.se
                      mac_algorithms: (19)
                          hmac-md5-etm@openssh.com
                          hmac-sha1-etm@openssh.com
                          umac-64-etm@openssh.com
                          umac-128-etm@openssh.com
                          hmac-sha2-256-etm@openssh.com
                          hmac-sha2-512-etm@openssh.com
                          hmac-ripemd160-etm@openssh.com
                          hmac-sha1-96-etm@openssh.com
                          hmac-md5-96-etm@openssh.com
                          hmac-md5
                          hmac-sha1
                          umac-64@openssh.com
                          umac-128@openssh.com
                          hmac-sha2-256
                          hmac-sha2-512
                          hmac-ripemd160
                          hmac-ripemd160@openssh.com
                          hmac-sha1-96
                          hmac-md5-96
                      compression_algorithms: (2)
                          none
                          zlib@openssh.com

                80/tcp	open	Apache httpd 2.4.7 (Ubuntu)
                9929/tcp	open	nping-echo
                31337/tcp	open	ncat-chat users: nobody
                123/udp	open	NTP v4
          OUTPUT
        )
      end
    end

    context "when the pattern exists in one of the script output for one of the ports" do
      let(:pattern) { 'rsa' }

      it "must print the script output with the pattern highlighted in the script output" do
        subject.highlight_host(host,pattern)

        expect(stdout.string).to eq(
          <<~OUTPUT
            [ 45.33.32.156 / scanme.nmap.org ]

              [ hostnames ]

                scanme.nmap.org
                li982-156.members.linode.com

              [ ports ]

                22/tcp	open	ssh protocol 2.0

                  ssh-hostkey:
                    1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)
                    ssh-dss AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL
                      2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)
                    ssh-#{bold}#{red}rsa#{reset_color}#{reset_intensity} AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd
                      256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)
                    ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc=

                  ssh2-enum-algos:
                    kex_algorithms: (8)
                          curve25519-sha256@libssh.org
                          ecdh-sha2-nistp256
                          ecdh-sha2-nistp384
                          ecdh-sha2-nistp521
                          diffie-hellman-group-exchange-sha256
                          diffie-hellman-group-exchange-sha1
                          diffie-hellman-group14-sha1
                          diffie-hellman-group1-sha1
                      server_host_key_algorithms: (4)
                          ssh-#{bold}#{red}rsa#{reset_color}#{reset_intensity}
                          ssh-dss
                          ecdsa-sha2-nistp256
                          ssh-ed25519
                      encryption_algorithms: (16)
                          aes128-ctr
                          aes192-ctr
                          aes256-ctr
                          arcfour256
                          arcfour128
                          aes128-gcm@openssh.com
                          aes256-gcm@openssh.com
                          chacha20-poly1305@openssh.com
                          aes128-cbc
                          3des-cbc
                          blowfish-cbc
                          cast128-cbc
                          aes192-cbc
                          aes256-cbc
                          arcfour
                          rijndael-cbc@lysator.liu.se
                      mac_algorithms: (19)
                          hmac-md5-etm@openssh.com
                          hmac-sha1-etm@openssh.com
                          umac-64-etm@openssh.com
                          umac-128-etm@openssh.com
                          hmac-sha2-256-etm@openssh.com
                          hmac-sha2-512-etm@openssh.com
                          hmac-ripemd160-etm@openssh.com
                          hmac-sha1-96-etm@openssh.com
                          hmac-md5-96-etm@openssh.com
                          hmac-md5
                          hmac-sha1
                          umac-64@openssh.com
                          umac-128@openssh.com
                          hmac-sha2-256
                          hmac-sha2-512
                          hmac-ripemd160
                          hmac-ripemd160@openssh.com
                          hmac-sha1-96
                          hmac-md5-96
                      compression_algorithms: (2)
                          none
                          zlib@openssh.com

                80/tcp	open	Apache httpd 2.4.7 (Ubuntu)
                9929/tcp	open	nping-echo
                31337/tcp	open	ncat-chat users: nobody
                123/udp	open	NTP v4
          OUTPUT
        )
      end
    end
  end

  describe "#highlight_port" do
    context "when the Nmap::XML::Port object has a service" do
      let(:port) do
        host.open_ports.find { |port| port.number == 80 }
      end
      let(:pattern) { 'http' }

      it "must print the port number, protocol, state, and service name/version, with the pattern highlighted in bold red" do
        subject.highlight_port(port,pattern)

        expect(stdout.string).to eq(
          "80/tcp\topen\tApache #{bold}#{red}http#{reset_color}#{reset_intensity}d 2.4.7 (Ubuntu)#{$/}"
        )
      end

      context "and when the Nmap::XML::Port object has scripts" do
        let(:port) do
          host.open_ports.find { |port| port.number == 22 }
        end
        let(:pattern) { 'rsa' }

        it "must print the port number, protocol, state, and service name/version, and script IDs and output, with the pattern highlighted in bold red" do
          subject.highlight_port(port,pattern)

          expect(stdout.string).to eq(
            <<~OUTPUT
              22/tcp	open	ssh protocol 2.0

                ssh-hostkey:
                  1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)
                  ssh-dss AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL
                    2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)
                  ssh-#{bold}#{red}rsa#{reset_color}#{reset_intensity} AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd
                    256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)
                  ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc=

                ssh2-enum-algos:
                  kex_algorithms: (8)
                        curve25519-sha256@libssh.org
                        ecdh-sha2-nistp256
                        ecdh-sha2-nistp384
                        ecdh-sha2-nistp521
                        diffie-hellman-group-exchange-sha256
                        diffie-hellman-group-exchange-sha1
                        diffie-hellman-group14-sha1
                        diffie-hellman-group1-sha1
                    server_host_key_algorithms: (4)
                        ssh-#{bold}#{red}rsa#{reset_color}#{reset_intensity}
                        ssh-dss
                        ecdsa-sha2-nistp256
                        ssh-ed25519
                    encryption_algorithms: (16)
                        aes128-ctr
                        aes192-ctr
                        aes256-ctr
                        arcfour256
                        arcfour128
                        aes128-gcm@openssh.com
                        aes256-gcm@openssh.com
                        chacha20-poly1305@openssh.com
                        aes128-cbc
                        3des-cbc
                        blowfish-cbc
                        cast128-cbc
                        aes192-cbc
                        aes256-cbc
                        arcfour
                        rijndael-cbc@lysator.liu.se
                    mac_algorithms: (19)
                        hmac-md5-etm@openssh.com
                        hmac-sha1-etm@openssh.com
                        umac-64-etm@openssh.com
                        umac-128-etm@openssh.com
                        hmac-sha2-256-etm@openssh.com
                        hmac-sha2-512-etm@openssh.com
                        hmac-ripemd160-etm@openssh.com
                        hmac-sha1-96-etm@openssh.com
                        hmac-md5-96-etm@openssh.com
                        hmac-md5
                        hmac-sha1
                        umac-64@openssh.com
                        umac-128@openssh.com
                        hmac-sha2-256
                        hmac-sha2-512
                        hmac-ripemd160
                        hmac-ripemd160@openssh.com
                        hmac-sha1-96
                        hmac-md5-96
                    compression_algorithms: (2)
                        none
                        zlib@openssh.com

            OUTPUT
          )
        end
      end
    end

    context "when the Nmap::XML::Port object does not have a service"

    context "when the Nmap::XML::Port object has scripts"
  end

  describe "#highlight_scripts" do
    let(:has_scripts) { port }
    let(:pattern)     { 'dss' }

    it "must print the script IDs and script outputs of all scripts, highlighting the pattern in bold red" do
      subject.highlight_scripts(has_scripts,pattern)

      expect(stdout.string).to eq(
        <<~OUTPUT
          ssh-hostkey:
            1024 ac:00:a0:1a:82:ff:cc:55:99:dc:67:2b:34:97:6b:75 (DSA)
            ssh-#{bold}#{red}dss#{reset_color}#{reset_intensity} AAAAB3NzaC1kc3MAAACBAOe8o59vFWZGaBmGPVeJBObEfi1AR8yEUYC/Ufkku3sKhGF7wM2m2ujIeZDK5vqeC0S5EN2xYo6FshCP4FQRYeTxD17nNO4PhwW65qAjDRRU0uHFfSAh5wk+vt4yQztOE++sTd1G9OBLzA8HO99qDmCAxb3zw+GQDEgPjzgyzGZ3AAAAFQCBmE1vROP8IaPkUmhM5xLFta/xHwAAAIEA3EwRfaeOPLL7TKDgGX67Lbkf9UtdlpCdC4doMjGgsznYMwWH6a7Lj3vi4/KmeZZdix6FMdFqq+2vrfT1DRqx0RS0XYdGxnkgS+2g333WYCrUkDCn6RPUWR/1TgGMPHCj7LWCa1ZwJwLWS2KX288Pa2gLOWuhZm2VYKSQx6NEDOIAAACBANxIfprSdBdbo4Ezrh6/X6HSvrhjtZ7MouStWaE714ByO5bS2coM9CyaCwYyrE5qzYiyIfb+1BG3O5nVdDuN95sQ/0bAdBKlkqLFvFqFjVbETF0ri3v97w6MpUawfF75ouDrQ4xdaUOLLEWTso6VFJcM6Jg9bDl0FA0uLZUSDEHL
              2048 20:3d:2d:44:62:2a:b0:5a:9d:b5:b3:05:14:c2:a6:b2 (RSA)
            ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC6afooTZ9mVUGFNEhkMoRR1Btzu64XXwElhCsHw/zVlIx/HXylNbb9+11dm2VgJQ21pxkWDs+L6+EbYyDnvRURTrMTgHL0xseB0EkNqexs9hYZSiqtMx4jtGNtHvsMxZnbxvVUk2dasWvtBkn8J5JagSbzWTQo4hjKMOI1SUlXtiKxAs2F8wiq2EdSuKw/KNk8GfIp1TA+8ccGeAtnsVptTJ4D/8MhAWsROkQzOowQvnBBz2/8ecEvoMScaf+kDfNQowK3gENtSSOqYw9JLOza6YJBPL/aYuQQ0nJ74Rr5vL44aNIlrGI9jJc2x0bV7BeNA5kVuXsmhyfWbbkB8yGd
              256 96:02:bb:5e:57:54:1c:4e:45:2f:56:4c:4a:24:b2:57 (ECDSA)
            ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMD46g67x6yWNjjQJnXhiz/TskHrqQ0uPcOspFrIYW382uOGzmWDZCFV8FbFwQyH90u+j0Qr1SGNAxBZMhOQ8pc=

          ssh2-enum-algos:
            kex_algorithms: (8)
                  curve25519-sha256@libssh.org
                  ecdh-sha2-nistp256
                  ecdh-sha2-nistp384
                  ecdh-sha2-nistp521
                  diffie-hellman-group-exchange-sha256
                  diffie-hellman-group-exchange-sha1
                  diffie-hellman-group14-sha1
                  diffie-hellman-group1-sha1
              server_host_key_algorithms: (4)
                  ssh-rsa
                  ssh-#{bold}#{red}dss#{reset_color}#{reset_intensity}
                  ecdsa-sha2-nistp256
                  ssh-ed25519
              encryption_algorithms: (16)
                  aes128-ctr
                  aes192-ctr
                  aes256-ctr
                  arcfour256
                  arcfour128
                  aes128-gcm@openssh.com
                  aes256-gcm@openssh.com
                  chacha20-poly1305@openssh.com
                  aes128-cbc
                  3des-cbc
                  blowfish-cbc
                  cast128-cbc
                  aes192-cbc
                  aes256-cbc
                  arcfour
                  rijndael-cbc@lysator.liu.se
              mac_algorithms: (19)
                  hmac-md5-etm@openssh.com
                  hmac-sha1-etm@openssh.com
                  umac-64-etm@openssh.com
                  umac-128-etm@openssh.com
                  hmac-sha2-256-etm@openssh.com
                  hmac-sha2-512-etm@openssh.com
                  hmac-ripemd160-etm@openssh.com
                  hmac-sha1-96-etm@openssh.com
                  hmac-md5-96-etm@openssh.com
                  hmac-md5
                  hmac-sha1
                  umac-64@openssh.com
                  umac-128@openssh.com
                  hmac-sha2-256
                  hmac-sha2-512
                  hmac-ripemd160
                  hmac-ripemd160@openssh.com
                  hmac-sha1-96
                  hmac-md5-96
              compression_algorithms: (2)
                  none
                  zlib@openssh.com

        OUTPUT
      )
    end
  end

  describe "#highlight_script" do
    context "when the pattern exists in the script ID name" do
      let(:pattern) { 'ssh2' }

      it "must print the script ID with the pattern highlighted in the script ID" do
        subject.highlight_script(script,pattern)

        expect(stdout.string).to eq(
          <<~OUTPUT
            #{bold}#{red}ssh2#{reset_color}#{reset_intensity}-enum-algos:
              kex_algorithms: (8)
                    curve25519-sha256@libssh.org
                    ecdh-sha2-nistp256
                    ecdh-sha2-nistp384
                    ecdh-sha2-nistp521
                    diffie-hellman-group-exchange-sha256
                    diffie-hellman-group-exchange-sha1
                    diffie-hellman-group14-sha1
                    diffie-hellman-group1-sha1
                server_host_key_algorithms: (4)
                    ssh-rsa
                    ssh-dss
                    ecdsa-sha2-nistp256
                    ssh-ed25519
                encryption_algorithms: (16)
                    aes128-ctr
                    aes192-ctr
                    aes256-ctr
                    arcfour256
                    arcfour128
                    aes128-gcm@openssh.com
                    aes256-gcm@openssh.com
                    chacha20-poly1305@openssh.com
                    aes128-cbc
                    3des-cbc
                    blowfish-cbc
                    cast128-cbc
                    aes192-cbc
                    aes256-cbc
                    arcfour
                    rijndael-cbc@lysator.liu.se
                mac_algorithms: (19)
                    hmac-md5-etm@openssh.com
                    hmac-sha1-etm@openssh.com
                    umac-64-etm@openssh.com
                    umac-128-etm@openssh.com
                    hmac-sha2-256-etm@openssh.com
                    hmac-sha2-512-etm@openssh.com
                    hmac-ripemd160-etm@openssh.com
                    hmac-sha1-96-etm@openssh.com
                    hmac-md5-96-etm@openssh.com
                    hmac-md5
                    hmac-sha1
                    umac-64@openssh.com
                    umac-128@openssh.com
                    hmac-sha2-256
                    hmac-sha2-512
                    hmac-ripemd160
                    hmac-ripemd160@openssh.com
                    hmac-sha1-96
                    hmac-md5-96
                compression_algorithms: (2)
                    none
                    zlib@openssh.com
          OUTPUT
        )
      end
    end

    context "when the pattern exists in the script output" do
      let(:pattern) { 'rsa' }

      it "must print the script output with the pattern highlighted in the script output" do
        subject.highlight_script(script,pattern)

        expect(stdout.string).to eq(
          <<~OUTPUT
            ssh2-enum-algos:
              kex_algorithms: (8)
                    curve25519-sha256@libssh.org
                    ecdh-sha2-nistp256
                    ecdh-sha2-nistp384
                    ecdh-sha2-nistp521
                    diffie-hellman-group-exchange-sha256
                    diffie-hellman-group-exchange-sha1
                    diffie-hellman-group14-sha1
                    diffie-hellman-group1-sha1
                server_host_key_algorithms: (4)
                    ssh-#{bold}#{red}rsa#{reset_color}#{reset_intensity}
                    ssh-dss
                    ecdsa-sha2-nistp256
                    ssh-ed25519
                encryption_algorithms: (16)
                    aes128-ctr
                    aes192-ctr
                    aes256-ctr
                    arcfour256
                    arcfour128
                    aes128-gcm@openssh.com
                    aes256-gcm@openssh.com
                    chacha20-poly1305@openssh.com
                    aes128-cbc
                    3des-cbc
                    blowfish-cbc
                    cast128-cbc
                    aes192-cbc
                    aes256-cbc
                    arcfour
                    rijndael-cbc@lysator.liu.se
                mac_algorithms: (19)
                    hmac-md5-etm@openssh.com
                    hmac-sha1-etm@openssh.com
                    umac-64-etm@openssh.com
                    umac-128-etm@openssh.com
                    hmac-sha2-256-etm@openssh.com
                    hmac-sha2-512-etm@openssh.com
                    hmac-ripemd160-etm@openssh.com
                    hmac-sha1-96-etm@openssh.com
                    hmac-md5-96-etm@openssh.com
                    hmac-md5
                    hmac-sha1
                    umac-64@openssh.com
                    umac-128@openssh.com
                    hmac-sha2-256
                    hmac-sha2-512
                    hmac-ripemd160
                    hmac-ripemd160@openssh.com
                    hmac-sha1-96
                    hmac-md5-96
                compression_algorithms: (2)
                    none
                    zlib@openssh.com
          OUTPUT
        )
      end
    end
  end

  describe "#highlight" do
    let(:text)    { "The quick brown fox jumps over the lazy dog" }
    let(:pattern) { "jumps" }

    it "must print the text with the pattern highlighted in red" do
      expect(subject.highlight(text,pattern)).to eq(
        "The quick brown fox #{bold}#{red}#{pattern}#{reset_color}#{reset_intensity} over the lazy dog"
      )
    end
  end
end
