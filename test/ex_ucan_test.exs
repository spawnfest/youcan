defmodule ExUcanTest do
  alias ExUcan.Keymaterial.Ed25519.Keypair
  use ExUnit.Case
  doctest ExUcan

  test "create_default_keypair" do
    assert %Keypair{jwt_alg: "EdDSA"} = keypair = Keypair.create()
    assert is_binary(keypair.public_key)
    assert is_binary(keypair.secret_key)
  end
end
