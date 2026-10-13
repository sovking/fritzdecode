class Fritzdecode < Formula
  desc "Tools for reading, verifying, decrypting, and manipulating AVM FritzBox config exports"
  homepage "https://github.com/sovking/fritzdecode"
  url "https://github.com/sovking/fritzdecode/archive/refs/tags/v0.4.1.tar.gz"
  sha256 "SKIP"
  license "AGPL-3.0-or-later"
  head "https://github.com/sovking/fritzdecode.git", branch: "main"

  depends_on "rust" => :build

  def install
    system "cargo", "install", *std_cargo_args
    generate_completions_from_executable(bin/"fritzdecode", "completions")
  end

  test do
    assert_match "fritzdecode", shell_output("#{bin}/fritzdecode --help")
  end
end
