require 'spec_helper'
require 'ronin/nmap/cli/commands/new'

require 'tmpdir'

describe Ronin::Nmap::CLI::Commands::New do
  describe "options" do
    before { subject.option_parser.parse(argv) }

    context "when given the '--parser' option" do
      let(:argv) { %w[--parser] }

      it "must set #script_type to :parser" do
        expect(subject.script_type).to eq(:parser)
      end
    end

    context "when given the '--scanner ' option" do
      let(:argv) { %w[--parser --scanner] }

      it "must set #script_type to :scanner" do
        expect(subject.script_type).to eq(:scanner)
      end
    end

    context "when given the '--printing' option" do
      let(:argv) { %w[--printing] }

      it "must set :printing in #features" do
        expect(subject.features[:printing]).to be(true)
      end
    end

    context "when given the '--import' option" do
      let(:argv) { %w[--import] }

      it "must set :import in #features" do
        expect(subject.features[:import]).to be(true)
      end
    end

    context "when given the '--xml-file FILE' option" do
      let(:file) { 'path/to/nmap.xml' }
      let(:argv) { ['--xml-file', file] }

      it "must set #xml_file to the given FILE argument" do
        expect(subject.xml_file).to eq(file)
      end
    end

    context "when given the '--ports PORT,...' option" do
      let(:ports) { [22, 80, 443] }
      let(:argv)  { ['--ports', "#{ports.join(',')}"] }

      it "must set #ports to an Array of port Integers" do
        expect(subject.ports).to eq(ports)
      end
    end

    context "when given the '--ports PORT1-PORT2,...' option" do
      let(:start_port1) { 1 }
      let(:stop_port1)  { 1024 }
      let(:start_port2) { 8000 }
      let(:stop_port2)  { 9000 }

      let(:argv) do
        ['--ports', "#{start_port1}-#{stop_port1},#{start_port2}-#{stop_port2}"]
      end

      it "must set #ports to an Array of Ranges of Integers" do
        expect(subject.ports).to eq(
          [
            (start_port1..stop_port1),
            (start_port2..stop_port2)
          ]
        )
      end
    end

    context "when given the '--ports PORT1,PORT2,PORT3-PORT4,...' option" do
      let(:port1) { 80 }
      let(:port2) { 443 }
      let(:start_port1) { 1 }
      let(:stop_port1)  { 1024 }
      let(:start_port2) { 8000 }
      let(:stop_port2)  { 9000 }

      let(:argv) do
        ['--ports', "#{port1},#{port2},#{start_port1}-#{stop_port1},#{start_port2}-#{stop_port2}"]
      end

      it "must set #ports to an Array of Integers and Ranges of Integers" do
        expect(subject.ports).to eq(
          [
            port1,
            port2,
            (start_port1..stop_port1),
            (start_port2..stop_port2)
          ]
        )
      end
    end

    context "when given the '--ports -' option" do
      let(:argv) { %w[--ports -] }

      it "must set #ports to '-'" do
        expect(subject.ports).to eq('-')
      end
    end

    context "when given the '--target TARGET' option" do
      let(:target1) { 'example.com' }
      let(:target2) { '192.168.1.1' }
      let(:argv)    { ['--target', target1, '--target', target2] }

      it "must append the target value to #targets" do
        expect(subject.targets).to eq([target1, target2])
      end
    end
  end

  describe "#initialize" do
    it "must default #script_type to :scanner" do
      expect(subject.script_type).to eq(:scanner)
    end

    it "must initialize #targets to an empty Array" do
      expect(subject.targets).to eq([])
    end

    it "must initialize #features to an empty Hash" do
      expect(subject.features).to eq({})
    end
  end

  describe "#run" do
    let(:tempdir) { Dir.mktmpdir('test-ronin-nmap-new') }
    let(:path)    { File.join(tempdir,'test_script.rb') }

    let(:argv) { [] }

    before do
      subject.option_parser.parse(argv)
      subject.run(path)
    end

    it "must generate a new file containing a new `Ronin::Nmap.scan(...)`" do
      expect(File.read(path)).to eq(
        <<~RUBY
          #!/usr/bin/env ruby

          require 'ronin/nmap'

          xml = Ronin::Nmap.scan(
            ARGV[0],
            # ports: [22, 80, 443, 8000..9000],
            # xml_file: "path/to/file.xml"
          )
        RUBY
      )
    end

    it "must make the file executable" do
      expect(File.executable?(path)).to be(true)
    end

    context "when the parent directory does not exist yet" do
      let(:path) { File.join(tempdir,'does_not_exist_yet','test_script.rb') }

      it "must create the parent directory" do
        expect(File.directory?(File.dirname(path))).to be(true)
      end
    end

    context "when given the '--parser' option" do
      let(:argv) { %w[--parser] }

      it "must generate a Ruby script that calls `Ronin::Nmap.parse(...)` instead" do
        expect(File.read(path)).to eq(
          <<~RUBY
            #!/usr/bin/env ruby

            require 'ronin/nmap'

            xml = Ronin::Nmap.parse(ARGV[0])
          RUBY
        )
      end

      context "and when given the '--xml-file FILE' option" do
        let(:file) { 'path/to/nmap.xml' }
        let(:argv) { super() + ['--xml-file', file] }

        it "must include the given file path instead of `ARGV[0]`" do
          expect(File.read(path)).to eq(
            <<~RUBY
              #!/usr/bin/env ruby

              require 'ronin/nmap'

              xml = Ronin::Nmap.parse(#{file.inspect})
            RUBY
          )
        end
      end

      context "when given the '--printing' option" do
        let(:argv) { super() + %w[--printing] }

        it "must append additional code to print the nmap XML scan data" do
          expect(File.read(path)).to eq(
            <<~RUBY
              #!/usr/bin/env ruby

              require 'ronin/nmap'

              xml = Ronin::Nmap.parse(ARGV[0])

              xml.each_host do |host|
                puts "[ \#{host.ip} ]"

                host.each_port do |port|
                  puts "  \#{port.number}/\#{port.protocol}\\t\#{port.state}\\t\#{port.service}"

                  port.scripts.each do |id,script|
                    puts "    [ \#{id} ]"

                    script.output.each_line { |line| puts "      \#{line}" }
                  end
                end
              end
            RUBY
          )
        end
      end

      context "and when given the '--scanner' option" do
        let(:argv) { super() + %w[--scanner] }

        it "must generate a new file containing a new `Ronin::Nmap.scan(...)` instead" do
          expect(File.read(path)).to eq(
            <<~RUBY
              #!/usr/bin/env ruby

              require 'ronin/nmap'

              xml = Ronin::Nmap.scan(
                ARGV[0],
                # ports: [22, 80, 443, 8000..9000],
                # xml_file: "path/to/file.xml"
              )
            RUBY
          )
        end
      end
    end

    context "when given the '--printing' option" do
      let(:argv) { %w[--printing] }

      it "must append additional code to print the nmap XML scan data" do
        expect(File.read(path)).to eq(
          <<~RUBY
            #!/usr/bin/env ruby

            require 'ronin/nmap'

            xml = Ronin::Nmap.scan(
              ARGV[0],
              # ports: [22, 80, 443, 8000..9000],
              # xml_file: "path/to/file.xml"
            )

            xml.each_host do |host|
              puts "[ \#{host.ip} ]"

              host.each_port do |port|
                puts "  \#{port.number}/\#{port.protocol}\\t\#{port.state}\\t\#{port.service}"

                port.scripts.each do |id,script|
                  puts "    [ \#{id} ]"

                  script.output.each_line { |line| puts "      \#{line}" }
                end
              end
            end
          RUBY
        )
      end
    end

    context "when given the '--import' option" do
      let(:argv) { %w[--import] }

      it "must append additional code to print the nmap XML scan data" do
        expect(File.read(path)).to eq(
          <<~RUBY
            #!/usr/bin/env ruby

            require 'ronin/nmap'

            xml = Ronin::Nmap.scan(
              ARGV[0],
              # ports: [22, 80, 443, 8000..9000],
              # xml_file: "path/to/file.xml"
            )

            Ronin::DB.connect
            Ronin::Nmap::Importer.import(xml)
          RUBY
        )
      end
    end

    context "when given the '--xml-file FILE' option" do
      let(:file) { 'path/to/nmap.xml' }
      let(:argv) { ['--xml-file', file] }

      it "must add an `xml_file:` keyword argument to `Ronin::Nmap.scan(...)` with the given file" do
        expect(File.read(path)).to eq(
          <<~RUBY
            #!/usr/bin/env ruby

            require 'ronin/nmap'

            xml = Ronin::Nmap.scan(
              ARGV[0],
              # ports: [22, 80, 443, 8000..9000],
              xml_file: #{file.inspect}
            )
          RUBY
        )
      end
    end

    context "when given the '--ports PORT,...' option" do
      let(:ports) { [22, 80, 443] }
      let(:argv)  { ['--ports', "#{ports.join(',')}"] }

      it "must add an `ports:` keyword argument to `Ronin::Nmap.scan(...)` with an Array of the given port numbers" do
        expect(File.read(path)).to eq(
          <<~RUBY
            #!/usr/bin/env ruby

            require 'ronin/nmap'

            xml = Ronin::Nmap.scan(
              ARGV[0],
              ports: #{ports.inspect},
              # xml_file: "path/to/file.xml"
            )
          RUBY
        )
      end
    end

    context "when given the '--ports PORT1-PORT2,...' option" do
      let(:start_port1) { 1 }
      let(:stop_port1)  { 1024 }
      let(:start_port2) { 8000 }
      let(:stop_port2)  { 9000 }
      let(:ports) do
        [
          (start_port1..stop_port1),
          (start_port2..stop_port2)
        ]
      end

      let(:argv) do
        ['--ports', "#{start_port1}-#{stop_port1},#{start_port2}-#{stop_port2}"]
      end

      it "must add an `ports:` keyword argument to `Ronin::Nmap.scan(...)` with an Array of the given port ranges" do
        expect(File.read(path)).to eq(
          <<~RUBY
            #!/usr/bin/env ruby

            require 'ronin/nmap'

            xml = Ronin::Nmap.scan(
              ARGV[0],
              ports: #{ports.inspect},
              # xml_file: "path/to/file.xml"
            )
          RUBY
        )
      end
    end

    context "when given the '--ports PORT1,PORT2,PORT3-PORT4,...' option" do
      let(:port1) { 80 }
      let(:port2) { 443 }
      let(:start_port1) { 1 }
      let(:stop_port1)  { 1024 }
      let(:start_port2) { 8000 }
      let(:stop_port2)  { 9000 }
      let(:ports) do
        [
          port1,
          port2,
          (start_port1..stop_port1),
          (start_port2..stop_port2)
        ]
      end

      let(:argv) do
        ['--ports', "#{port1},#{port2},#{start_port1}-#{stop_port1},#{start_port2}-#{stop_port2}"]
      end

      it "must add an `ports:` keyword argument to `Ronin::Nmap.scan(...)` with an Array of the given port numbers and ranges" do
        expect(File.read(path)).to eq(
          <<~RUBY
            #!/usr/bin/env ruby

            require 'ronin/nmap'

            xml = Ronin::Nmap.scan(
              ARGV[0],
              ports: #{ports.inspect},
              # xml_file: "path/to/file.xml"
            )
          RUBY
        )
      end
    end

    context "when given the '--ports -' option" do
      let(:argv) { %w[--ports -] }

      it "must add an `ports:` keyword argument to `Ronin::Nmap.scan(...)` with '-'" do
        expect(File.read(path)).to eq(
          <<~RUBY
            #!/usr/bin/env ruby

            require 'ronin/nmap'

            xml = Ronin::Nmap.scan(
              ARGV[0],
              ports: "-",
              # xml_file: "path/to/file.xml"
            )
          RUBY
        )
      end
    end
  end

  describe "#parse_port_range" do
    context "when given 'PORT,...'" do
      let(:ports)  { [22, 80, 443] }
      let(:string) { ports.join(',') }

      it "must parse the string into an Array of port Integers" do
        expect(subject.parse_port_range(string)).to eq(ports)
      end
    end

    context "when given 'PORT1-PORT2,...'" do
      let(:start_port1) { 1 }
      let(:stop_port1)  { 1024 }
      let(:start_port2) { 8000 }
      let(:stop_port2)  { 9000 }

      let(:string) do
        "#{start_port1}-#{stop_port1},#{start_port2}-#{stop_port2}"
      end

      it "must parse the string into an Array of Ranges of Integers" do
        expect(subject.parse_port_range(string)).to eq(
          [
            (start_port1..stop_port1),
            (start_port2..stop_port2)
          ]
        )
      end
    end

    context "when given 'PORT1,PORT2,PORT3-PORT4,...'" do
      let(:port1) { 80 }
      let(:port2) { 443 }
      let(:start_port1) { 1 }
      let(:stop_port1)  { 1024 }
      let(:start_port2) { 8000 }
      let(:stop_port2)  { 9000 }

      let(:string) do
        "#{port1},#{port2},#{start_port1}-#{stop_port1},#{start_port2}-#{stop_port2}"
      end

      it "must parse the string into an Array of Integers and Ranges of Integers" do
        expect(subject.parse_port_range(string)).to eq(
          [
            port1,
            port2,
            (start_port1..stop_port1),
            (start_port2..stop_port2)
          ]
        )
      end
    end

    context "when given '-'" do
      it "must return '-'" do
        expect(subject.parse_port_range('-')).to eq('-')
      end
    end
  end
end
