### 0.1.1 / 2025-02-14

* Added the `csv` gem as a dependency for Bundler and Ruby 3.4.0.
* Use `require_relative` to improve load times.

### 0.1.0 / 2024-07-22

* Initial release:
  * Supports automating `nmap` using [ruby-nmap].
  * Supports parsing and filtering nmap XML.
  * Supports converting nmap XML into JSON or CSV.
  * Supports importing nmap XML data into the [ronin-db] database.

[ruby-nmap]: https://github.com/postmodern/ruby-nmap#readme
[ronin-db]: https://github.com/ronin-rb/ronin-db#readme
