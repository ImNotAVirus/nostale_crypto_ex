defmodule NostaleCrypto.NativeTest do
  use ExUnit.Case, async: true

  test "login_next/1 return nil if the delimiter is not found" do
    enc = <<0x9C, 0xBB, 0x9F, 0x02, 0x05, 0x03>>

    assert NostaleCrypto.Native.login_next(enc) == {nil, enc}
  end

  test "login_next/1 split by delimiter" do
    enc = <<0x9C, 0xBB, 0x9F, 0x02, 0x05, 0x03, 0xD8, 0x01, 0x02, 0x03>>

    assert NostaleCrypto.Native.login_next(enc) ==
             {<<0x9C, 0xBB, 0x9F, 0x02, 0x05, 0x03>>, <<0x01, 0x02, 0x03>>}
  end

  test "login_encrypt/1 encrypt a packet" do
    dec = "failc 5\n"
    enc = <<0x75, 0x70, 0x78, 0x7B, 0x72, 0x2F, 0x44, 0x19>>

    assert NostaleCrypto.Native.login_encrypt(dec) == enc
  end

  test "login_decrypt/1 decrypt a packet" do
    enc =
      <<0x9C, 0xBB, 0x9F, 0x02, 0x05, 0x03, 0x05, 0xF2, 0x05, 0x03, 0x01, 0x03, 0xFF, 0x09, 0xF2,
        0xB1, 0xB6, 0xBD, 0xB9, 0xBC, 0xF2, 0x8F, 0x03, 0x91, 0x96, 0x06, 0x06, 0x8F, 0x90, 0x91,
        0x96, 0x03, 0x04, 0x00, 0x91, 0x05, 0x96, 0x91, 0x02, 0x91, 0x06, 0x05, 0x00, 0x94, 0x09,
        0x95, 0x0A, 0x05, 0x06, 0x94, 0x96, 0x8F, 0x01, 0x95, 0x02, 0x95, 0x03, 0x91, 0x05, 0x00,
        0x91, 0xFF, 0x0A, 0x02, 0x01, 0x05, 0x94, 0x00, 0xFF, 0x94, 0xFF, 0x95, 0x91, 0x90, 0x01,
        0x96, 0x0A, 0x02, 0x90, 0x09, 0xFF, 0x01, 0x96, 0x96, 0x06, 0x03, 0x00, 0x04, 0xFF, 0x06,
        0x96, 0x94, 0x91, 0x8F, 0x03, 0x01, 0x8F, 0x96, 0xFF, 0x06, 0x95, 0x90, 0x8F, 0xFF, 0x05,
        0x96, 0x01, 0x04, 0x91, 0x90, 0x03, 0x94, 0x90, 0x0A, 0x91, 0x09, 0x02, 0x8F, 0x0A, 0x01,
        0x94, 0x09, 0x03, 0x05, 0x01, 0x01, 0xFF, 0x96, 0x04, 0x8F, 0x03, 0x05, 0xFF, 0x0A, 0x96,
        0x8F, 0x04, 0x09, 0x96, 0x96, 0x0A, 0x96, 0x95, 0x09, 0x02, 0x03, 0x03, 0x95, 0x8F, 0xF2,
        0x04, 0xAF, 0xFF, 0x0A, 0xB4, 0xB6, 0x06, 0x05, 0xFD, 0xB5, 0xB4, 0x09, 0x01, 0xFD, 0x06,
        0x02, 0x05, 0x06, 0xFD, 0x0A, 0x00, 0xB0, 0x0A, 0xFD, 0x09, 0xAF, 0x09, 0x04, 0xB0, 0x06,
        0xB0, 0x02, 0xB0, 0x00, 0x02, 0x09, 0xF2, 0x02, 0x02, 0x03, 0x00, 0x03, 0xFF, 0x03, 0x01,
        0xF2, 0x02, 0xD7, 0x02, 0xFC, 0x09, 0xFC, 0xFF, 0xFC, 0xFF, 0x01, 0xFF, 0x06, 0xF2, 0x02,
        0xF2, 0x09, 0x0A, 0x00, 0x05, 0x95, 0x05, 0x94, 0x8F, 0x02, 0x05, 0x01, 0x94, 0x09, 0x91,
        0x01, 0x03, 0x91, 0x95, 0x94, 0x95, 0x02, 0x06, 0x03, 0x91, 0x06, 0x0A, 0x94, 0x06, 0x8F,
        0x04, 0x94, 0x09, 0xD8>>

    dec =
      "NoS0575 571739 admin C7AD44CBAD762A5DA0A452F9E854FDC1E0E7A52A38015F23F3EAB1D80B931DD472634DFAC71CD34EBC35D16AB7FB8A90C81F975113D6C7538DC69DD8DE9077EC 6c38fd45-ef91-4054-82b8-9c96b4b0b209 00727371 0\x0B0.9.3.3134 0 9825E5FC051F9A17AEFE047A48F4C6F9\n"

    assert NostaleCrypto.Native.login_decrypt(enc) == dec
  end

  test "world_next/2 return nil if the delimiter is not found" do
    enc = <<0x91, 0xD3, 0x4E, 0x2A, 0x1E, 0x2B>>

    assert NostaleCrypto.Native.world_next(enc, 12) == {nil, enc}
  end

  test "world_next/2 return split by delimiter" do
    enc =
      <<198, 228, 203, 145, 70, 205, 214, 220, 208, 217, 208, 196, 7, 212, 73, 112, 208, 203, 222,
        209, 215, 208, 210, 218, 193, 112, 67, 220, 208, 210, 63, 199, 228, 203, 161, 16, 72, 215,
        214, 221, 200, 214, 200, 214, 248, 193, 160, 65, 218, 193, 224, 66, 241, 205, 199, 228,
        203, 161, 16, 72, 215, 214, 221, 200, 214, 200, 214, 248, 193, 160, 65, 218, 193, 224, 66,
        241, 205>>

    assert NostaleCrypto.Native.world_next(enc, 34353) ==
             {<<198, 228, 203, 145, 70, 205, 214, 220, 208, 217, 208, 196, 7, 212, 73>>,
              <<208, 203, 222, 209, 215, 208, 210, 218, 193, 112, 67, 220, 208, 210, 63, 199, 228,
                203, 161, 16, 72, 215, 214, 221, 200, 214, 200, 214, 248, 193, 160, 65, 218, 193,
                224, 66, 241, 205, 199, 228, 203, 161, 16, 72, 215, 214, 221, 200, 214, 200, 214,
                248, 193, 160, 65, 218, 193, 224, 66, 241, 205>>}
  end

  test "world_encrypt/1 encrypt ad packet" do
    dec = "foo"
    enc = <<3, 153, 144, 144, 255>>

    assert NostaleCrypto.Native.world_encrypt(dec) == enc
  end

  test "world_session_decrypt/2 decrypt a channel session packet" do
    enc =
      <<198, 228, 203, 145, 70, 205, 214, 220, 208, 217, 208, 196, 7, 212, 73, 255, 208, 203, 222,
        209, 215, 208, 210, 218, 193, 112, 67, 220, 208, 210, 63, 199, 228, 203, 161, 16, 72, 215,
        214, 221, 200, 214, 200, 214, 248, 193, 160, 65, 218, 193, 224, 66, 241, 205>>

    dec =
      "7391784-.37:83898 868 71;481.6; 8 788;8-848 8.877-2 .0898 8.. 7491785-  .584838:75837583:57-5 .-877-9 ..:-7:"

    assert NostaleCrypto.Native.world_session_decrypt(enc) == dec
  end

  test "world_session_decrypt/2 decrypt a pulse session packet" do
    enc = <<159, 172, 100, 160, 99, 235, 103, 120, 99, 14>>
    dec = "5 59115 1098142510;;"

    assert NostaleCrypto.Native.world_session_decrypt(enc) == dec
  end

  test "world_session_decrypt/2 decrypt a handshake session packet" do
    enc = <<150, 165, 170, 224, 79, 14>>
    dec = "4352579 0 ;;"

    assert NostaleCrypto.Native.world_session_decrypt(enc) == dec
  end

  test "world_channel_decrypt/2 decrypt a c_blist channel packet" do
    enc =
      <<66, 76, 22, 111, 193, 92, 96, 91, 77, 82, 76, 69, 36, 207, 127, 127, 127, 127, 127, 127,
        127, 127, 149, 211, 7, 209, 130, 220, 2, 219, 66, 219, 27, 211, 91, 143, 151, 18, 216,
        140, 175, 84, 103, 215, 134, 255, 84, 107, 215, 133, 127, 82, 134, 215, 180, 111, 81, 99,
        215, 28, 159, 91, 19, 57>>

    dec =
      <<134, 140, 218, 177, 7, 156, 160, 157, 147, 150, 140, 139, 228, 17, 65, 65, 65, 65, 65, 65,
        65, 65, 91, 21, 201, 23, 70, 28, 198, 29, 134, 29, 221, 21, 157, 81, 89, 214, 24, 76, 113,
        148, 169, 25, 74, 193, 148, 173, 25, 75, 65, 150, 74, 25, 116, 177, 151, 165, 25, 220, 97,
        157, 213, 255>>

    unpacked =
      "48967 c_blist  0 0 0 0 0 0 0 0 17 185 302 882 942 999 1591 1592 4083 5065 5068 5069 5070 5206 5307 5361 5982 5991"

    assert NostaleCrypto.Native.world_channel_decrypt(enc, 10685) == dec
    assert NostaleCrypto.Native.world_channel_unpack(dec) == unpacked
  end

  test "world_channel_decrypt/2 decrypt a stat channel packet" do
    enc =
      <<247, 201, 231, 18, 116, 253, 15, 247, 242, 129, 120, 12, 10, 253, 5, 6, 12, 15, 246, 199,
        230, 209, 130, 183, 212, 183, 209, 177, 209, 177, 138, 138, 177, 183, 183, 183, 212, 183,
        183, 183, 245, 214, 236, 127, 12, 15, 12, 15, 134, 125, 183, 212, 189, 177, 209, 138, 127,
        53, 245, 198, 215, 112>>

    dec =
      <<134, 88, 118, 161, 3, 140, 158, 134, 129, 16, 7, 155, 153, 140, 148, 149, 155, 158, 133,
        86, 117, 96, 17, 70, 99, 70, 96, 64, 96, 64, 25, 25, 64, 70, 70, 70, 99, 70, 70, 70, 132,
        101, 123, 14, 155, 158, 155, 158, 21, 12, 70, 99, 76, 64, 96, 25, 14, 196, 132, 85, 102,
        255>>

    unpacked =
      <<49, 52, 51, 50, 54, 32, 115, 97, 121, 32, 100, 102, 115, 107, 106, 100, 97, 49, 50, 51,
        49, 50, 185, 156, 185, 159, 191, 159, 191, 230, 230, 191, 185, 185, 185, 156, 185, 185,
        185, 50, 49, 51, 55, 100, 97, 100, 97, 234, 243, 185, 156, 179, 191, 159, 230, 241, 59,
        49, 49, 50, 50>>

    assert NostaleCrypto.Native.world_channel_decrypt(enc, 34353) == dec
    assert NostaleCrypto.Native.world_channel_unpack(dec) == unpacked
  end
end
