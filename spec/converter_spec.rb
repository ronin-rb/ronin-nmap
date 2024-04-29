require 'spec_helper'
require 'ronin/nmap/converter'
require 'tempfile'

RSpec.describe Ronin::Nmap::Converter do
  let(:fixtures_path) { File.expand_path(File.join(__dir__, 'fixtures')) }
  let(:nmap_xml_path) { File.join(fixtures_path, 'nmap.xml') }
  let(:json_path)     { File.join(fixtures_path, 'nmap.json') }
  let(:csv_path)      { File.join(fixtures_path, 'nmap.csv') }
  let(:nmap_file)     { Nmap::XML.open(nmap_xml_path) }
  let(:expected_json) { File.read(json_path) }
  let(:expected_csv)  { File.read(csv_path) }

  around(:each) do |example|
    original_timezone = ENV['TZ']
    ENV['TZ']         = 'America/New_York'

    example.run

    ENV['TZ'] = original_timezone
  end

  describe '.convert_file' do
    let(:tempfile) { ['dest', '.json'] }

    it 'must convert xml and wirte it into a file' do
      Tempfile.create(tempfile) do |output|
        subject.convert_file(nmap_xml_path, output)
        output.rewind

        expect(output.read).to eq(expected_json)
      end
    end

    context 'when format is given' do
      it 'must ignore file extension and convert xml to the given format' do
        Tempfile.create(tempfile) do |output|
          subject.convert_file(nmap_xml_path, output, format: :csv)
          output.rewind

          expect(output.read).to eq(expected_csv)
        end
      end
    end
  end

  describe '.convert' do
    let(:tempfile) { ['dest', '.json'] }

    context 'when there is no output' do
      it 'must return a string' do
        expect(subject.convert(nmap_file, format: :json)).to eq(expected_json)
      end
    end

    context 'when there is a output' do
      it 'must write result into it' do
        Tempfile.create(tempfile) do |output|
          subject.convert(nmap_file, output, format: :json)

          output.rewind
          expect(output.read).to eq(expected_json)
        end
      end
    end
  end

  describe '.infer_format_for' do
    context 'for json file' do
      let(:path) { 'path/with/valid_extension.json' }

      it 'must return correct format' do
        expect(subject.infer_format_for(path)).to eq(:json)
      end
    end

    context 'for csv file' do
      let(:path) { 'path/with/valid_extension.csv' }

      it 'must return correct format' do
        expect(subject.infer_format_for(path)).to eq(:csv)
      end
    end

    context 'for file with unknown extension' do
      let(:path) { '/path/with/invalid_extension.txt' }

      it 'must raise an ArgumentError' do
        expect {
          subject.infer_format_for(path)
        }.to raise_error(ArgumentError, "cannot infer output format from path: #{path.inspect}")
      end
    end
  end
end
